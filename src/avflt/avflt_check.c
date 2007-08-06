#include "avflt.h"

int avflt_request_nr = 0;
int avflt_reply_nr = 0;

int avflt_request_max = 0;
int avflt_reply_max = 0;

atomic_t avflt_request_free = ATOMIC_INIT(0);
atomic_t avflt_reply_free = ATOMIC_INIT(0);

int avflt_request_accept = 0;
int avflt_reply_accept = 0;

static DECLARE_WAIT_QUEUE_HEAD(avflt_request_waitq);
static DECLARE_WAIT_QUEUE_HEAD(avflt_reply_waitq);

static DECLARE_WAIT_QUEUE_HEAD(avflt_request_available_waitq);
static atomic_t avflt_request_available = ATOMIC_INIT(0);

static struct kmem_cache *avflt_check_cache = NULL;

static LIST_HEAD(avflt_request_list);
spinlock_t avflt_request_lock = SPIN_LOCK_UNLOCKED;

static int avflt_reply_hashtable_size = 4096;
static struct list_head *avflt_reply_hashtable;
spinlock_t avflt_reply_lock = SPIN_LOCK_UNLOCKED;
static unsigned int avflt_reply_ids = 0;

static pid_t *avflt_pids = NULL;
static int avflt_pids_size = 10;
static int avflt_pids_nr = 0;
static spinlock_t avflt_pids_lock = SPIN_LOCK_UNLOCKED;

struct avflt_check *avflt_check_alloc(void)
{
	struct avflt_check *check;

	check = kmem_cache_alloc(avflt_check_cache, GFP_KERNEL);
	if (!check)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&check->list);
	init_waitqueue_head(&check->wait);
	atomic_set(&check->cnt, 1);
	atomic_set(&check->done, 0);
	atomic_set(&check->deny, 0);
	check->id = -1;
	check->event = -1;
	check->fn_size = PATH_MAX;
	check->fn_len = 0;
	memset(&check->fn, 0, check->fn_size);

	return check;
}

struct avflt_check *avflt_check_get(struct avflt_check *check)
{
	if (!check || IS_ERR(check))
		return NULL;

	BUG_ON(!atomic_read(&check->cnt));
	atomic_inc(&check->cnt);

	return check;
}

void avflt_check_put(struct avflt_check *check)
{
	if (!check || IS_ERR(check))
		return;

	BUG_ON(!atomic_read(&check->cnt));

	if (!atomic_dec_and_test(&check->cnt))
		return;

	kmem_cache_free(avflt_check_cache, check);
}

int avflt_request_queue(struct avflt_check *check)
{
	spin_lock(&avflt_request_lock);

	if (!avflt_request_accept) {
		spin_unlock(&avflt_request_lock);
		return 1;
	}

	list_add_tail(&check->list, &avflt_request_list);
	avflt_check_get(check);

	spin_unlock(&avflt_request_lock);

	atomic_set(&avflt_request_available, 1);
	wake_up(&avflt_request_available_waitq);

	return 0;
}

struct avflt_check *avflt_request_dequeue(void)
{
	struct avflt_check *check;

	spin_lock(&avflt_request_lock);
	if (list_empty(&avflt_request_list)) {
		spin_unlock(&avflt_request_lock);
		return NULL;
	}

	check = list_entry(avflt_request_list.next, struct avflt_check, list);
	list_del(&check->list);

	if (list_empty(&avflt_request_list))
		atomic_set(&avflt_request_available, 0);


	spin_unlock(&avflt_request_lock);

	return check;
}

void avflt_request_put(void)
{
	spin_lock(&avflt_request_lock);
	avflt_request_nr--;
	atomic_set(&avflt_request_free, 1);
	wake_up(&avflt_request_waitq);
	spin_unlock(&avflt_request_lock);
}


int avflt_request_available_wait(void)
{
	return wait_event_interruptible(avflt_request_available_waitq,
			atomic_read(&avflt_request_available));
}

int avflt_request_wait(void)
{
	int rv = 0;

again:
	spin_lock(&avflt_request_lock);

	if (!avflt_request_accept) {
		rv = 1;
		goto done;
	}

	if (!avflt_request_max)
		goto done;

	if (avflt_request_nr < avflt_request_max) {
		avflt_request_nr++;
		if (avflt_request_nr == avflt_request_max)
			atomic_set(&avflt_request_free, 0);
		goto done;
	}

	spin_unlock(&avflt_request_lock);

	rv = wait_event_interruptible(avflt_request_waitq,
			atomic_read(&avflt_request_free));

	if (rv)
		return rv;

	goto again;

done:
	spin_unlock(&avflt_request_lock);
	return rv;
}

int avflt_reply_queue(struct avflt_check *check)
{
	struct list_head *list;
	struct avflt_check *loop;
	int rv;

again:
	spin_lock(&avflt_reply_lock);
	if (!avflt_reply_accept) {
		spin_unlock(&avflt_reply_lock);
		return 1;
	}

	if (avflt_reply_nr >= avflt_reply_max) {
		spin_unlock(&avflt_reply_lock);
		rv = wait_event_interruptible(avflt_reply_waitq,
			atomic_read(&avflt_reply_free));
		if (rv)
			return rv;

		goto again;
	}

	check->id = avflt_reply_ids;
	list = avflt_reply_hashtable +
		(check->id % avflt_reply_hashtable_size);

	list_for_each_entry(loop, list, list) {
		if (loop->id == check->id) {
			spin_unlock(&avflt_reply_lock);
			rv = wait_event_interruptible(avflt_reply_waitq,
				atomic_read(&avflt_reply_free));
			if (rv)
				return rv;

			goto again;
		}
	}

	list_add_tail(&check->list, list);
	avflt_reply_nr++;
	avflt_reply_ids++;

	spin_unlock(&avflt_reply_lock);

	return 0;
}

struct avflt_check *avflt_reply_dequeue(int id)
{
	struct list_head *list;
	struct avflt_check *loop;
	struct avflt_check *found = NULL;

	spin_lock(&avflt_reply_lock);

	list = avflt_reply_hashtable + (id % avflt_reply_hashtable_size);

	list_for_each_entry(loop, list, list) {
		if (loop->id == id) {
			found = loop;
			break;
		}
	}

	if (found) {
		list_del(&found->list);
		avflt_reply_nr--;
		atomic_set(&avflt_reply_free, 1);
		wake_up(&avflt_reply_waitq);
	}

	spin_unlock(&avflt_reply_lock);

	return found;
}

int avflt_reply_wait(struct avflt_check *check)
{
	return wait_event_interruptible(check->wait, atomic_read(&check->done));
}

void avflt_check_start(void)
{

	spin_lock(&avflt_reply_lock);
	avflt_reply_accept = 1;
	spin_unlock(&avflt_reply_lock);

	spin_lock(&avflt_request_lock);
	avflt_request_accept= 1;
	spin_unlock(&avflt_request_lock);
}

void avflt_check_stop(void)
{
	struct avflt_check *tmp;
	struct avflt_check *loop;
	int i;

	spin_lock(&avflt_request_lock);

	avflt_request_accept = 0;

	list_for_each_entry_safe(loop, tmp, &avflt_request_list, list) {
		list_del(&loop->list);
		atomic_set(&loop->deny, 0);
		avflt_check_done(loop);
		avflt_request_nr--;
	};

	spin_unlock(&avflt_request_lock);

	spin_lock(&avflt_reply_lock);

	avflt_reply_accept = 0;

	for (i = 0; i < avflt_reply_hashtable_size; i++) {
		list_for_each_entry_safe(loop, tmp,
				&avflt_reply_hashtable[i], list) {
			list_del(&loop->list);
			atomic_set(&loop->deny, 0);
			avflt_check_done(loop);
			avflt_reply_nr--;
		}
	}

	spin_unlock(&avflt_reply_lock);
}

void avflt_check_done(struct avflt_check *check)
{
	atomic_set(&check->done, 1);
	wake_up(&check->wait);
}

int avflt_pid_add(pid_t pid)
{
	pid_t *pids_new;

	spin_lock(&avflt_pids_lock);

	if (avflt_pids_nr == avflt_pids_size) {
		pids_new = kmalloc(sizeof(pid_t) * avflt_pids_size * 2,
				GFP_ATOMIC);

		if (!pids_new) {
			spin_unlock(&avflt_pids_lock);
			return -ENOMEM;
		}

		memcpy(pids_new, avflt_pids, avflt_pids_size);
		kfree(avflt_pids);
		avflt_pids = pids_new;
		avflt_pids_size *= 2;
	}

	avflt_pids[avflt_pids_nr++] = pid;

	if (avflt_pids_nr == 1)
		avflt_check_start();

	spin_unlock(&avflt_pids_lock);

	return 0;
}

void avflt_pid_rem(pid_t pid)
{
	int i;
	int found = -1;

	spin_lock(&avflt_pids_lock);

	for (i = 0; i < avflt_pids_nr; i++) {
		if (avflt_pids[i] == pid) {
			found = i;
			break;
		}
	}

	if (found != -1)
		return;

	memmove(avflt_pids + i, avflt_pids + i + 1, avflt_pids_nr - (i + 1));
	avflt_pids_nr--;

	if (!avflt_pids_nr)
		avflt_check_stop();

	spin_unlock(&avflt_pids_lock);
}

pid_t avflt_pid_find(pid_t pid)
{
	int i;

	spin_lock(&avflt_pids_lock);

	for (i = 0; i < avflt_pids_nr; i++) {
		if (avflt_pids[i] == pid) {
			spin_unlock(&avflt_pids_lock);
			return pid;
		}
	}

	spin_unlock(&avflt_pids_lock);

	return 0;
}

int avflt_check_init(void)
{
	int i;

	avflt_check_cache = kmem_cache_create("avflt_check_cache", 
			sizeof(struct avflt_check), 0, 
			SLAB_RECLAIM_ACCOUNT, NULL, NULL);

	if (!avflt_check_cache)
		return -ENOMEM;

	avflt_reply_hashtable = kmalloc(sizeof(struct list_head) *
			avflt_reply_hashtable_size, GFP_KERNEL);

	if (!avflt_reply_hashtable) {
		kmem_cache_destroy(avflt_check_cache);
		return -ENOMEM;
	}

	avflt_pids = kmalloc(sizeof(pid_t) * avflt_pids_size, GFP_KERNEL);
	if (!avflt_pids) {
		kfree(avflt_reply_hashtable);
		kmem_cache_destroy(avflt_check_cache);
		return -ENOMEM;
	}

	for (i = 0; i < avflt_reply_hashtable_size; i++)
		INIT_LIST_HEAD(&avflt_reply_hashtable[i]);

	return 0;
}

void avflt_check_exit(void)
{
	kfree(avflt_reply_hashtable);
	kmem_cache_destroy(avflt_check_cache);
}

