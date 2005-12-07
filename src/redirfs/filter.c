#include <linux/module.h>
#include "filter.h"
#include "root.h"
#include "debug.h"

static spinlock_t redirfs_flt_list_lock = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(redirfs_flt_list);

static struct redirfs_flt_t *redirfs_alloc_flt(const char *name, int priority,
		unsigned long flags)
{
	struct redirfs_flt_t *flt;
	char *flt_name;
	size_t flt_name_len;
	

	redirfs_debug("started");

	if (!name)
		return ERR_PTR(-EINVAL);

	flt_name_len = strlen(name);
	
	flt = kmalloc(sizeof(struct redirfs_flt_t), GFP_KERNEL);
	flt_name = kmalloc(flt_name_len + 1, GFP_KERNEL);

	if (!flt || !flt_name) {
		kfree(flt_name);
		kfree(flt);
		return ERR_PTR(-ENOMEM);
	}
	
	atomic_set(&flt->active, 0);
	atomic_set(&flt->ref_cnt, 1);
	strncpy(flt_name, name, flt_name_len + 1);
	flt->name = flt_name;
	flt->priority = priority;
	flt->flags = flags;
	spin_lock_init(&flt->lock); 

	redirfs_init_ops(&flt->pre_ops, &flt->vfs_pre_ops);
	redirfs_init_ops(&flt->post_ops, &flt->vfs_post_ops);

	redirfs_debug("ended");

	return flt;
}

struct redirfs_flt_t *redirfs_fltget(struct redirfs_flt_t *flt)
{
	redirfs_debug("started");
	atomic_inc(&flt->ref_cnt);
	redirfs_debug("ended");
	return flt;
}

void redirfs_fltput(struct redirfs_flt_t *flt)
{
	redirfs_debug("started");

	if (atomic_dec_and_test(&flt->ref_cnt)) {
		kfree(flt->name);
		kfree(flt);
	}

	redirfs_debug("ended");
}

static struct redirfs_flt_t *redirfs_find_flt_turn(int priority)
{
	struct redirfs_flt_t *flt = NULL;
	struct redirfs_flt_t *found = NULL;
	

	redirfs_debug("started");

	list_for_each_entry(flt, &redirfs_flt_list, flt_list) {
		if (flt->priority == priority) {
			found = flt;
		}
			break;
	}

	redirfs_debug("ended");

	return found;
}

redirfs_filter redirfs_register_filter(const char *name, int priority, unsigned long flags)
{
	struct redirfs_flt_t *flt;

	
	redirfs_debug("started");

	spin_lock(&redirfs_flt_list_lock);

	flt = redirfs_find_flt_turn(priority);
	if (flt) {
		spin_unlock(&redirfs_flt_list_lock);
		return ERR_PTR(-EEXIST);
	}

	flt = redirfs_alloc_flt(name, priority, flags);
	if (IS_ERR(flt)) {
		spin_unlock(&redirfs_flt_list_lock);
		return flt;
	}

	list_add(&flt->flt_list, &redirfs_flt_list);

	spin_unlock(&redirfs_flt_list_lock);
	
	redirfs_debug("ended");

	return redirfs_cover_flt(flt);
}

int redirfs_unregister_filter(redirfs_filter filter)
{
	struct redirfs_flt_t *flt;


	redirfs_debug("started");

	if (!filter)
		return -EINVAL;

	flt = redirfs_uncover_flt(filter);

	redirfs_walk_roots(NULL, redirfs_remove_flt, (void *)flt);
	redirfs_remove_roots();

	spin_lock(&redirfs_flt_list_lock);
	list_del(&flt->flt_list);
	spin_unlock(&redirfs_flt_list_lock);

	redirfs_fltput(flt);

	redirfs_debug("ended");

	return 0;
}

void redirfs_activate_filter(redirfs_filter filter)
{
	struct redirfs_flt_t *flt = redirfs_uncover_flt(filter);


	redirfs_debug("started");
	atomic_set(&flt->active, 1);
	redirfs_debug("ended");
}

void redirfs_deactivate_filter(redirfs_filter filter)
{
	struct redirfs_flt_t *flt = redirfs_uncover_flt(filter);


	redirfs_debug("started");
	atomic_set(&flt->active, 0);
	redirfs_debug("ended");
}

void redirfs_flt_arr_init(struct redirfs_flt_arr_t *flt_arr)
{
	flt_arr->arr = NULL;
	flt_arr->cnt = 0;
	flt_arr->size = 0;
	spin_lock_init(&flt_arr->lock);
}

int redirfs_flt_arr_create(struct redirfs_flt_arr_t *flt_arr, int size)
{
	flt_arr->arr = kmalloc(sizeof(struct redirfs_flt_t *) * size,
			GFP_KERNEL);

	if (!flt_arr->arr)
		return -ENOMEM;

	flt_arr->cnt =  0;
	flt_arr->size = size;
	spin_lock_init(&flt_arr->lock);

	return 0;
}

void redirfs_flt_arr_destroy(struct redirfs_flt_arr_t *flt_arr)
{
	int i = 0;


	spin_lock(&flt_arr->lock);
	if (flt_arr->arr) {
		for (i = 0; i < flt_arr->cnt; i++)
			redirfs_fltput(flt_arr->arr[i]);

		kfree(flt_arr->arr);
	}
	flt_arr->arr = NULL;
	flt_arr->cnt = 0;
	flt_arr->size = 0;
	spin_unlock(&flt_arr->lock);
}

static int __redirfs_flt_arr_get(struct redirfs_flt_arr_t *flt_arr,
		struct redirfs_flt_t *flt) 
{
	int i = 0;
	int rv = -1;

	for(i = 0; i < flt_arr->cnt; i++) {
		if (flt_arr->arr[i] == flt) {
			rv = i;
			break;
		}
	}

	return rv;
}

int redirfs_flt_arr_get(struct redirfs_flt_arr_t *flt_arr,
		struct redirfs_flt_t *flt)
{
	int rv = -1;


	spin_lock(&flt_arr->lock);
	rv = __redirfs_flt_arr_get(flt_arr, flt);
	spin_unlock(&flt_arr->lock);

	return rv;
}

static int __redirfs_flt_arr_find(struct redirfs_flt_arr_t *flt_arr, 
		struct redirfs_flt_t *flt)
{
	int i = 0;


	if (!flt_arr->cnt)
		return i;

	for(i = 0; i < flt_arr->cnt; i++) {
		if (flt->priority < flt_arr->arr[i]->priority)
			return i;
	}

	return i;
}

int redirfs_flt_arr_add_flt(struct redirfs_flt_arr_t *flt_arr,
		struct redirfs_flt_t *flt)
{
	int size = 0;
	struct redirfs_flt_t **arr = NULL;
	int pos = 0;


	spin_lock(&flt_arr->lock);

	if (__redirfs_flt_arr_get(flt_arr, flt) >= 0) {
		spin_unlock(&flt_arr->lock);
		return 0;
	}

	if (flt_arr->cnt == flt_arr->size) {
		size = sizeof(struct redirfs_flt_t *) * 
			(2 * flt_arr->size);

		arr = kmalloc(size, GFP_KERNEL);
		if (!arr) {
			spin_unlock(&flt_arr->lock);
			return -ENOMEM;
		}

		size = sizeof(struct redirfs_flt_t *) * flt_arr->cnt;
		memcpy(arr, flt_arr->arr, size);
		kfree(flt_arr->arr);
		flt_arr->arr = arr;
		flt_arr->size *= 2;

	}

	pos = __redirfs_flt_arr_find(flt_arr, flt);

	size = sizeof(struct redirfs_flt_t *) * (flt_arr->cnt - pos);

	if (size)
		memmove(&flt_arr->arr[pos+1], &flt_arr->arr[pos],
				size);

	flt_arr->arr[pos] = redirfs_fltget(flt);
	flt_arr->cnt++;

	spin_unlock(&flt_arr->lock);

	return 0;
}

void redirfs_flt_arr_remove_flt(struct redirfs_flt_arr_t *flt_arr,
		struct redirfs_flt_t *flt)
{
	int size = 0;
	int pos = 0;


	spin_lock(&flt_arr->lock);

	if (__redirfs_flt_arr_get(flt_arr, flt) == -1) {
		spin_unlock(&flt_arr->lock);
		return;
	}

	pos = __redirfs_flt_arr_get(flt_arr, flt);
	if (pos == -1) {
		spin_unlock(&flt_arr->lock);
		return;
	}

	size = sizeof(struct redirfs_flt_t *) * (flt_arr->cnt - (pos + 1));

	if (size)
		memmove(&flt_arr->arr[pos], &flt_arr->arr[pos+1],
				size);

	flt_arr->cnt--;

	redirfs_fltput(flt);
	
	spin_unlock(&flt_arr->lock);
}

int redirfs_flt_arr_copy(struct redirfs_flt_arr_t *src,
		struct redirfs_flt_arr_t *dst)
{
	struct redirfs_flt_t **arr;
	int i = 0;

	
	spin_lock(&src->lock);
	spin_lock(&dst->lock);

	arr = kmalloc(sizeof(struct redirfs_flt_t *) * src->size, GFP_KERNEL);
	if (!arr) {
		spin_unlock(&dst->lock);
		spin_unlock(&src->lock);
		return -ENOMEM;
	}

	if (dst->arr) {
		for (i = 0; i < dst->cnt; i++)
			redirfs_fltput(dst->arr[i]);
		kfree(dst->arr);
	}

	memcpy(arr, src->arr, sizeof(struct redirfs_flt_t *) * src->cnt);

	for (i = 0; i < src->cnt; i++)
		redirfs_fltget(arr[i]);

	dst->arr = arr;
	dst->cnt = src->cnt;
	dst->size = src->size;

	spin_unlock(&dst->lock);
	spin_unlock(&src->lock);

	return 0;
}

int redirfs_flt_arr_cnt(struct redirfs_flt_arr_t *flt_arr)
{
	int cnt;


	spin_lock(&flt_arr->lock);
	cnt = flt_arr->cnt;
	spin_unlock(&flt_arr->lock);

	return cnt;
}

int redirfs_flt_arr_cmp(struct redirfs_flt_arr_t *flt_arr1,
		struct redirfs_flt_arr_t *flt_arr2)
{
	int rv = -1;

	
	spin_lock(&flt_arr1->lock);
	spin_lock(&flt_arr2->lock);
	if (flt_arr1->cnt == flt_arr2->cnt) {
		if (!memcmp(flt_arr1->arr, flt_arr2->arr,
		    sizeof(struct redirfs_flt_t *) * flt_arr1->cnt))
			rv = 0;
	} 
	spin_unlock(&flt_arr2->lock);
	spin_unlock(&flt_arr1->lock);

	return rv;
}

int redirfs_filters_info(char *buf, int size)
{	
	struct redirfs_flt_t *flt;
	int len = 0;
	char active;


	if ((len + 36) > size)
		goto out;
	len += sprintf(buf + len, "%-10s\t%-10s\t%-10s\n", "name", "priority", "active");

	spin_lock(&redirfs_flt_list_lock);

	list_for_each_entry(flt, &redirfs_flt_list, flt_list) {
		if ((len + strlen(flt->name) + 36) > size)
			goto out;
		active = atomic_read(&flt->active) ? 'y' : 'n';
		len += sprintf(buf + len, "%-10s\t%-10d\t%-10c\n", flt->name, flt->priority, active);
	}
out:
	spin_unlock(&redirfs_flt_list_lock);
	return len;
}

EXPORT_SYMBOL(redirfs_register_filter);
EXPORT_SYMBOL(redirfs_unregister_filter);
EXPORT_SYMBOL(redirfs_activate_filter);
EXPORT_SYMBOL(redirfs_deactivate_filter);
