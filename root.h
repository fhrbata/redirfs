#ifndef _REDIRFS_ROOT_H
#define _REDIRFS_ROOT_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/dcache.h>
#include "operations.h"
#include "filter.h"

struct redirfs_root_t {
	struct list_head attached_flts;
	struct list_head subroots;
	struct list_head sibroots;
	struct list_head remove;
	struct list_head inodes;
	struct redirfs_root_t *parent;
	struct dentry *dentry;
	spinlock_t lock;
	char *path;
	atomic_t flt_cnt;
	struct redirfs_operations_t *fw_ops;
	struct redirfs_operations_t new_ops;
	struct redirfs_operations_t orig_ops;
	struct redirfs_vfs_operations_t vfs_ops;
	struct redirfs_operations_counters_t new_ops_cnts;
};

struct list_head *redirfs_find_flt(struct redirfs_root_t *root, struct redirfs_flt_t *flt_find);
int redirfs_walk_roots(struct redirfs_root_t *root, int (*walk_root)(struct redirfs_root_t *root, void *data), void *data);
void redirfs_set_reg_ops(struct redirfs_root_t *root, struct inode *inode);
void redirfs_set_root_ops(struct redirfs_root_t *root, int type);
void redirfs_replace_files_ops(const char *path, struct dentry *root_dentry, struct
		file_operations *fops, int what);
void redirfs_set_dir_ops(struct redirfs_root_t *root, struct inode *inode);
int redirfs_detach_flt(struct redirfs_root_t *root, void *data);
void redirfs_remove_roots(struct redirfs_flt_t *flt);

#endif
