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

atomic_t avflt_reply_timeout = ATOMIC_INIT(0);
atomic_t avflt_cache_enabled = ATOMIC_INIT(1);

static ssize_t avflt_timeout_show(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d",
			atomic_read(&avflt_reply_timeout));
}

static ssize_t avflt_timeout_store(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, const char *buf,
		size_t count)
{
	int timeout;

	if (sscanf(buf, "%d", &timeout) != 1)
		return -EINVAL;

	if (timeout < 0)
		return -EINVAL;

	atomic_set(&avflt_reply_timeout, timeout);

	return count;
}

static ssize_t avflt_cache_show(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, char *buf)
{
	char state;

	if (atomic_read(&avflt_cache_enabled))
		state = 'a';
	else
		state = 'd';

	return snprintf(buf, PAGE_SIZE, "%d", state);
}

static ssize_t avflt_cache_store(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, const char *buf,
		size_t count)
{
	char cache;

	if (sscanf(buf, "%c", &cache) != 1)
		return -EINVAL;

	switch (cache) {
		case 'a':
			avflt_invalidate_cache();
			atomic_set(&avflt_cache_enabled, 1);
			break;

		case 'd':
			atomic_set(&avflt_cache_enabled, 0);
			break;

		case 'i':
			avflt_invalidate_cache();
			break;

		default:
			return -EINVAL;
	}

	return count;
}

static ssize_t avflt_cache_paths_show(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, char *buf)
{
	struct avflt_root_data *data;
	redirfs_path *paths;
	redirfs_root root;
	ssize_t size = 0;
	char state;
	int i = 0;

	paths = redirfs_get_paths(avflt);
	if (IS_ERR(paths))
		return PTR_ERR(paths);

	while (paths[i]) {
		root = redirfs_get_root_path(paths[i]);
		if (!root)
			goto next;

		data = avflt_get_root_data_root(root);
		redirfs_put_root(root);
		if (!data)
			goto next;

		if (atomic_read(&data->cache_enabled))
			state = 'a';
		else
			state = 'd';

		avflt_put_root_data(data);

		size += snprintf(buf + size, PAGE_SIZE - size, "%c:%d",
				redirfs_get_id_path(paths[i]), state) + 1;

		if (size >= PAGE_SIZE)
			break;
next:
		i++;
	}

	redirfs_put_paths(paths);
	return size;
}

static ssize_t avflt_cache_paths_store(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, const char *buf,
		size_t count)
{
	struct avflt_root_data *data;
	redirfs_path path;
	redirfs_root root;
	char cache;
	int id;

	if (sscanf(buf, "%c:%d", &cache, &id) != 2)
		return -EINVAL;

	path = redirfs_get_path_id(id);
	if (!path)
		return -ENOENT;

	root = redirfs_get_root_path(path);
	redirfs_put_path(path);
	if (!root)
		return -ENOENT;

	data = avflt_get_root_data_root(root);
	redirfs_put_root(root);
	if (!data)
		return -ENOENT;

	switch (cache) {
		case 'a':
			atomic_inc(&data->cache_ver);
			atomic_set(&data->cache_enabled, 1);
			break;
		case 'd':
			atomic_set(&data->cache_enabled, 0);
			break;
		case 'i':
			atomic_inc(&data->cache_ver);
			break;

		default:
			avflt_put_root_data(data);
			return -EINVAL;

	}

	avflt_put_root_data(data);

	return count;
}

static struct redirfs_filter_attribute avflt_timeout_attr = 
	REDIRFS_FILTER_ATTRIBUTE(timeout, 0644, avflt_timeout_show,
			avflt_timeout_store);

static struct redirfs_filter_attribute avflt_cache_attr = 
	REDIRFS_FILTER_ATTRIBUTE(cache, 0644, avflt_cache_show,
			avflt_cache_store);

static struct redirfs_filter_attribute avflt_pathcache_attr = 
	REDIRFS_FILTER_ATTRIBUTE(cache_paths, 0644, avflt_cache_paths_show,
			avflt_cache_paths_store);

int avflt_sys_init(void)
{
	int rv;

	rv = redirfs_create_attribute(avflt, &avflt_timeout_attr);
	if (rv)
		return rv;

	rv = redirfs_create_attribute(avflt, &avflt_cache_attr);
	if (rv) {
		redirfs_remove_attribute(avflt, &avflt_timeout_attr);
		return rv;
	}

	rv = redirfs_create_attribute(avflt, &avflt_pathcache_attr);
	if (rv) {
		redirfs_remove_attribute(avflt, &avflt_timeout_attr);
		redirfs_remove_attribute(avflt, &avflt_cache_attr);
		return rv;
	}

	return 0;
}

void avflt_sys_exit(void)
{
	redirfs_remove_attribute(avflt, &avflt_timeout_attr);
	redirfs_remove_attribute(avflt, &avflt_cache_attr);
	redirfs_remove_attribute(avflt, &avflt_pathcache_attr);
}

