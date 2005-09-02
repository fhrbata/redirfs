#ifndef _REDIRFS_OPERATIONS_H
#define _REDIRFS_OPERATIONS_H

#include <linux/fs.h>
#include <linux/dcache.h>
#include "redirfs.h"

struct redirfs_vfs_operations_t {
	struct inode_operations reg_iops;
	struct inode_operations dir_iops;
	struct file_operations reg_fops;
	struct file_operations dir_fops;
	struct dentry_operations dops;
};

struct redirfs_operations_t {
	struct inode_operations *reg_iops;
	struct inode_operations *dir_iops;
	struct file_operations *reg_fops;
	struct file_operations *dir_fops;
	struct dentry_operations *dops;
	void **reg_iops_arr[REDIRFS_IOP_END];
	void **dir_iops_arr[REDIRFS_IOP_END];
	void **reg_fops_arr[REDIRFS_FOP_END];
	void **dir_fops_arr[REDIRFS_FOP_END];
	void **dops_arr[REDIRFS_DOP_END];
	void ***reg_iops_arrp;
	void ***dir_iops_arrp;
	void ***reg_fops_arrp;
	void ***dir_fops_arrp;
	void ***dops_arrp;
	int ops_arr_sizes[REDIRFS_END];
};

struct redirfs_operations_counters_t {
	unsigned int reg_iops_cnt[REDIRFS_IOP_END];
	unsigned int dir_iops_cnt[REDIRFS_IOP_END];
	unsigned int reg_fops_cnt[REDIRFS_FOP_END];
	unsigned int dir_fops_cnt[REDIRFS_FOP_END];
	unsigned int dops_cnt[REDIRFS_FOP_END];
};

struct redirfs_context_t {
	struct redirfs_inode_t *inode;
	struct redirfs_root_t *root;
	struct redirfs_flt_t *flt;
};

void redirfs_init_ops(struct redirfs_operations_t *ops, struct redirfs_vfs_operations_t *vfs_ops); 
void redirfs_init_cnts(struct redirfs_operations_counters_t *cnts);
void redirfs_init_orig_ops(struct redirfs_operations_t *ops);
void redirfs_init_iops_arr(void ***arr, struct inode_operations *iops);
void redirfs_init_fops_arr(void ***arr, struct file_operations *fops);
void redirfs_init_dops_arr(void ***arr, struct dentry_operations *dops);
void ***redirfs_gettype(int type, struct redirfs_operations_t *ops);
unsigned int *redirfs_getcnt(int type, struct redirfs_operations_counters_t *cnts);

#endif
