/*
 * RedirFS: Redirecting File System
 * Written by Frantisek Hrbata <frantisek.hrbata@redirfs.org>
 *
 * Copyright (C) 2008 Frantisek Hrbata
 * All rights reserved.
 *
 * This file is part of RedirFS.
 *
 * RedirFS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * RedirFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with RedirFS. If not, see <http://www.gnu.org/licenses/>.
 */

#include "avflt.h"

static DECLARE_COMPLETION(avflt_request_available);
static spinlock_t avflt_request_lock = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(avflt_request_list);
static int avflt_request_accept = 0;
static struct kmem_cache *avflt_event_cache = NULL;

static struct avflt_event *avflt_event_alloc(struct file *file, int type)
{
	struct avflt_event *event;

	event = kmem_cache_zalloc(avflt_event_cache, GFP_KERNEL);
	if (!event)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&event->req_list);
	INIT_LIST_HEAD(&event->proc_list);
	event->mnt = mntget(file->f_path.mnt);
	event->dentry = dget(file->f_path.dentry);
	init_waitqueue_head(&event->wait);
	atomic_set(&event->done, 0);
	atomic_set(&event->count, 1);
	event->type = type;
	event->id = -1;
	event->result = 0;
	event->file = NULL;
	event->fd = -1;

	return event;
}

struct avflt_event *avflt_event_get(struct avflt_event *event)
{
	if (!event || IS_ERR(event))
		return NULL;

	BUG_ON(!atomic_read(&event->count));
	atomic_inc(&event->count);

	return event;
}

void avflt_event_put(struct avflt_event *event)
{
	if (!event || IS_ERR(event))
		return;

	BUG_ON(!atomic_read(&event->count));

	if (!atomic_dec_and_test(&event->count))
		return;

	dput(event->dentry);
	mntput(event->mnt);
	kmem_cache_free(avflt_event_cache, event);
}

static int avflt_add_request(struct avflt_event *event, int tail)
{
	spin_lock(&avflt_request_lock);

	if (avflt_request_accept <= 0) {
		spin_unlock(&avflt_request_lock);
		return 1;
	}

	if (tail)
		list_add_tail(&event->req_list, &avflt_request_list);
	else
		list_add(&event->req_list, &avflt_request_list);

	avflt_event_get(event);

	complete(&avflt_request_available);

	spin_unlock(&avflt_request_lock);

	return 0;
}

void avflt_readd_request(struct avflt_event *event)
{
	if (avflt_add_request(event, 0))
		avflt_event_done(event);
}

static void avflt_rem_request(struct avflt_event *event)
{
	spin_lock(&avflt_request_lock);
	if (list_empty(&event->req_list)) {
		spin_unlock(&avflt_request_lock);
		return;
	}
	list_del_init(&event->req_list);
	spin_unlock(&avflt_request_lock);
	avflt_event_put(event);
}

struct avflt_event *avflt_get_request(void)
{
	struct avflt_event *event = NULL;
	int rv;

again:
	rv = wait_for_completion_interruptible(&avflt_request_available);
	if (rv) {
		event = ERR_PTR(rv);
		return event;
	}

	spin_lock(&avflt_request_lock);

	if (list_empty(&avflt_request_list)) {
		spin_unlock(&avflt_request_lock);
		goto again;
	}

	event = list_entry(avflt_request_list.next, struct avflt_event,
			req_list);
	list_del_init(&event->req_list);

	spin_unlock(&avflt_request_lock);

	return event;
}

static int avflt_wait_for_reply(struct avflt_event *event)
{
	long jiffies;
	int timeout;

	timeout = atomic_read(&avflt_reply_timeout);
	if (timeout)
		jiffies = msecs_to_jiffies(timeout);
	else
		jiffies = MAX_SCHEDULE_TIMEOUT;

	jiffies = wait_event_freezable_timeout(event->wait,
			atomic_read(&event->done), jiffies);

	if (jiffies < 0)
		return (int)jiffies;

	if (!jiffies) {
		printk(KERN_WARNING "avflt: wait for reply timeout\n");
		return -ETIMEDOUT;
	}

	return 0;
}

static int avflt_update_cache(struct avflt_event *event)
{
	struct avflt_data *data;

	if (!event->result)
		return 0;

	data = avflt_attach_data(event->dentry->d_inode);
	if (IS_ERR(data))
		return PTR_ERR(data);

	atomic_set(&data->state, event->result);

	avflt_put_data(data);
	return 0;
}

int avflt_process_request(struct file *file, int type)
{
	struct avflt_event *event;
	int rv = 0;

	event = avflt_event_alloc(file, type);
	if (IS_ERR(event))
		return PTR_ERR(event);

	if (avflt_add_request(event, 1))
		goto exit;

	rv = avflt_wait_for_reply(event);
	if (rv)
		goto exit;

	rv = avflt_update_cache(event);
	if (rv)
		goto exit;

	rv = event->result;
exit:
	avflt_rem_request(event);
	avflt_event_put(event);
	return rv;
}

void avflt_event_done(struct avflt_event *event)
{
	atomic_set(&event->done, 1);
	wake_up(&event->wait);
}

int avflt_get_file(struct avflt_event *event)
{
	struct file *file;
	int fd;

	fd = get_unused_fd();
	if (fd < 0)
		return fd;

	file = dentry_open(event->dentry, event->mnt, O_RDONLY);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		return PTR_ERR(file);
	}

	event->file = file;
	event->fd = fd;

	return 0;
}

void avflt_put_file(struct avflt_event *event)
{
	if (event->fd > 0) 
		put_unused_fd(event->fd);

	if (event->file) 
		fput(event->file);

	event->fd = -1;
	event->file = NULL;
}

void avflt_install_fd(struct avflt_event *event)
{
	fd_install(event->fd, event->file);
}

ssize_t avflt_copy_cmd(char __user *buf, size_t size, struct avflt_event *event)
{
	char cmd[256];
	int len;

	len = snprintf(cmd, 256, "id:%d,event:%d,fd:%d",
			event->id, event->type, event->fd);
	if (len < 0)
		return len;

	len++;

	if (len > size)
		return -EINVAL;

	if (copy_to_user(buf, cmd, len)) 
		return -EFAULT;

	return len;
}

int avflt_add_reply(struct avflt_event *event)
{
	struct avflt_proc *proc;

	proc = avflt_proc_find(current->tgid);
	if (!proc)
		return -ENOENT;

	avflt_proc_add_event(proc, event);
	avflt_proc_put(proc);

	return 0;
}

void avflt_start_accept(void)
{
	spin_lock(&avflt_request_lock);
	if (avflt_proc_empty())
		avflt_request_accept = 0;
	else
		avflt_request_accept = 1;
	spin_unlock(&avflt_request_lock);
}

void avflt_stop_accept(void)
{
	spin_lock(&avflt_request_lock);
	avflt_request_accept = -1;
	spin_unlock(&avflt_request_lock);
}

int avflt_is_stopped(void)
{
	int stopped;

	spin_lock(&avflt_request_lock);
	stopped = avflt_request_accept <= 0;
	spin_unlock(&avflt_request_lock);

	return stopped;
}

void avflt_proc_start_accept(void)
{
	spin_lock(&avflt_request_lock);

	if (avflt_proc_empty())
		goto exit;

	if (avflt_request_accept < 0)
		goto exit;

	avflt_request_accept = 1;
exit:
	spin_unlock(&avflt_request_lock);
}

void avflt_proc_stop_accept(void)
{
	spin_lock(&avflt_request_lock);
	if (!avflt_proc_empty())
		goto exit;

	if (avflt_request_accept <= 0)
		goto exit;

	avflt_request_accept = 0;
exit:
	spin_unlock(&avflt_request_lock);
}

void avflt_rem_requests(void)
{
	LIST_HEAD(list);
	struct avflt_event *event;
	struct avflt_event *tmp;

	spin_lock(&avflt_request_lock);

	if (avflt_request_accept > 0) {
		spin_unlock(&avflt_request_lock);
		return;

	}

	list_for_each_entry_safe(event, tmp, &avflt_request_list, req_list) {
		list_move_tail(&event->req_list, &list);
		avflt_event_done(event);
	}

	spin_unlock(&avflt_request_lock);

	list_for_each_entry_safe(event, tmp, &list, req_list) {
		list_del_init(&event->req_list);
		avflt_event_put(event);
	}
}

struct avflt_event *avflt_get_reply(const char __user *buf, size_t size)
{
	struct avflt_proc *proc;
	struct avflt_event *event;
	char cmd[256];
	int id;
	int result;

	if (size > 256)
		return ERR_PTR(-EINVAL);

	if (copy_from_user(cmd, buf, size))
		return ERR_PTR(-EFAULT);

	if (sscanf(buf, "id:%d,res:%d", &id, &result) != 2)
		return ERR_PTR(-EINVAL);

	proc = avflt_proc_find(current->tgid);
	if (!proc)
		return ERR_PTR(-ENOENT);

	event = avflt_proc_get_event(proc, id);
	if (!event) {
		avflt_proc_put(proc);
		return ERR_PTR(-ENOENT);
	}

	event->result = result;
	return event;
}

void avflt_invalidate_cache(void)
{
}

int avflt_check_init(void)
{
	avflt_event_cache = kmem_cache_create("avflt_event_cache",
			sizeof(struct avflt_event),
			0, SLAB_RECLAIM_ACCOUNT, NULL);

	if (!avflt_event_cache)
		return -ENOMEM;

	return 0;
}

void avflt_check_exit(void)
{
	kmem_cache_destroy(avflt_event_cache);
}

