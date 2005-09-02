#include <linux/module.h>
#include "filter.h"
#include "root.h"

extern spinlock_t redirfs_root_list_lock;
static spinlock_t redirfs_flt_list_lock = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(redirfs_flt_list);

static struct redirfs_flt_t *redirfs_alloc_flt(const char *name, int turn, unsigned long flags)
{
	struct redirfs_flt_t *flt;
	char *flt_name;
	size_t flt_name_len;
	

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
	strncpy(flt_name, name, flt_name_len);
	flt->name = flt_name;
	flt->turn = turn;
	flt->flags = flags;
	flt->lock = SPIN_LOCK_UNLOCKED;

	redirfs_init_ops(&flt->pre_ops, &flt->vfs_pre_ops);
	redirfs_init_ops(&flt->post_ops, &flt->vfs_post_ops);

	INIT_LIST_HEAD(&flt->flt_list);

	return flt;
}

static void redirfs_free_flt(struct redirfs_flt_t *flt)
{
	kfree(flt->name);
	kfree(flt);
}

static struct redirfs_flt_t *redirfs_find_flt_turn(int turn)
{
	struct redirfs_flt_t *flt = NULL;
	struct redirfs_flt_t *found = NULL;
	

	list_for_each_entry(flt, &redirfs_flt_list, flt_list) {
		if (flt->turn == turn) {
			found = flt;
		}
			break;
	}

	return found;
}

redirfs_filter redirfs_register_filter(const char *name, int turn, unsigned long flags)
{
	struct redirfs_flt_t *flt;

	
	spin_lock(&redirfs_flt_list_lock);

	flt = redirfs_find_flt_turn(turn);
	if (flt) {
		spin_unlock(&redirfs_flt_list_lock);
		return ERR_PTR(-EEXIST);
	}

	flt = redirfs_alloc_flt(name, turn, flags);
	if (IS_ERR(flt)) {
		spin_unlock(&redirfs_flt_list_lock);
		return flt;
	}

	list_add(&flt->flt_list, &redirfs_flt_list);

	spin_unlock(&redirfs_flt_list_lock);
	
	return redirfs_cover_flt(flt);
}

int redirfs_unregister_filter(redirfs_filter filter)
{
	struct redirfs_flt_t *flt;


	if (!filter)
		return -EINVAL;

	flt = redirfs_uncover_flt(filter);

	spin_lock(&redirfs_root_list_lock);
	spin_lock(&flt->lock);

	/*
	list_for_each_entry(ptr, &flt->inc_roots, ptr_list) {
		root = ptr->ptr_val;
		redirfs_walk_roots(root, redirfs_detach_flt, (void *)flt);
	}
	*/

	redirfs_walk_roots(NULL, redirfs_detach_flt, (void *)flt);

	redirfs_remove_roots(flt);

	spin_unlock(&flt->lock);
	spin_unlock(&redirfs_root_list_lock);

	spin_lock(&redirfs_flt_list_lock);
	list_del(&flt->flt_list);
	spin_unlock(&redirfs_flt_list_lock);

	redirfs_free_flt(flt);

	return 0;
}

void redirfs_activate_filter(redirfs_filter filter)
{
	struct redirfs_flt_t *flt = redirfs_uncover_flt(filter);
	atomic_set(&flt->active, 1);
}

void redirfs_deactivate_filter(redirfs_filter filter)
{
	struct redirfs_flt_t *flt = redirfs_uncover_flt(filter);
	atomic_set(&flt->active, 0);
}

struct redirfs_ptr_t *redirfs_alloc_ptr(void *ptr_val)
{
	struct redirfs_ptr_t *ptr = kmalloc(sizeof(struct redirfs_ptr_t), GFP_KERNEL);

	if (!ptr)
		return ERR_PTR(-ENOMEM);

	ptr->ptr_val = ptr_val;
	INIT_LIST_HEAD(&ptr->ptr_list);

	return ptr;
}

void redirfs_free_ptr(struct redirfs_ptr_t *ptr)
{
	kfree(ptr);
}

EXPORT_SYMBOL(redirfs_register_filter);
EXPORT_SYMBOL(redirfs_unregister_filter);
EXPORT_SYMBOL(redirfs_activate_filter);
EXPORT_SYMBOL(redirfs_deactivate_filter);
