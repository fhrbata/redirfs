#ifndef _REDIRFS_FILTER_H
#define _REDIRFS_FILTER_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/dcache.h>
#include "redirfs.h"
#include "operations.h"

#define redirfs_cover_flt(flt) ((redirfs_filter)flt)
#define redirfs_uncover_flt(filter) ((struct redirfs_flt_t*)filter)

struct redirfs_ptr_t {
	struct list_head ptr_list;
	void *ptr_val;
};

struct redirfs_flt_t {
	struct list_head flt_list;
	spinlock_t lock;
	char *name;
	int turn;
	unsigned int flags;
	atomic_t active;
	struct redirfs_vfs_operations_t vfs_pre_ops;
	struct redirfs_vfs_operations_t vfs_post_ops;
	struct redirfs_operations_t pre_ops;
	struct redirfs_operations_t post_ops;
};

struct redirfs_cb_data_t {
	struct dentry *dentry;
	struct redirfs_flt_t *flt;
	int i_val;
	int type;
	int op;
};

struct redirfs_ptr_t *redirfs_alloc_ptr(void *ptr_val);
void redirfs_free_ptr(struct redirfs_ptr_t *ptr);

#endif
