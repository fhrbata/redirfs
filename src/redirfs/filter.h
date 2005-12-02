#ifndef _REDIRFS_FILTER_H
#define _REDIRFS_FILTER_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/dcache.h>
#include "redirfs.h"
#include "operations.h"

#define redirfs_cover_flt(flt) ((redirfs_filter)flt)
#define redirfs_uncover_flt(filter) ((struct redirfs_flt_t*)filter)


struct redirfs_flt_t {
	struct list_head flt_list;
	spinlock_t lock;
	char *name;
	int priority;
	unsigned int flags;
	atomic_t active;
	atomic_t ref_cnt;
	struct redirfs_vfs_operations_t vfs_pre_ops;
	struct redirfs_vfs_operations_t vfs_post_ops;
	struct redirfs_operations_t pre_ops;
	struct redirfs_operations_t post_ops;
};


struct redirfs_flt_arr_t {
	spinlock_t lock;
	struct redirfs_flt_t **arr;
	int cnt;
	int size;
};

void redirfs_flt_arr_init(struct redirfs_flt_arr_t *flt_arr);
int redirfs_flt_arr_create(struct redirfs_flt_arr_t *flt_arr, int size);
void redirfs_flt_arr_destroy(struct redirfs_flt_arr_t *flt_arr);
int redirfs_flt_arr_add_flt(struct redirfs_flt_arr_t *flt_arr,
		struct redirfs_flt_t *flt);
void redirfs_flt_arr_remove_flt(struct redirfs_flt_arr_t *flt_arr,
		struct redirfs_flt_t *flt);
int redirfs_flt_arr_get(struct redirfs_flt_arr_t *flt_arr,
		struct redirfs_flt_t *flt);
int redirfs_flt_arr_copy(struct redirfs_flt_arr_t *src,
		struct redirfs_flt_arr_t *dst);
int redirfs_flt_arr_cnt(struct redirfs_flt_arr_t *flt_arr);
int redirfs_flt_arr_cmp(struct redirfs_flt_arr_t *flt_arr1,
		struct redirfs_flt_arr_t *flt_arr2);
struct redirfs_flt_t *redirfs_fltget(struct redirfs_flt_t *flt);
void redirfs_fltput(struct redirfs_flt_t *flt);
int redirfs_filters_info(char *buf, int size);

#endif
