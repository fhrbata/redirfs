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

#include <linux/mount.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include "redirfs.h"

#define RFS_ADD_OP(ops_new, op) \
	(ops_new.op = rfs_##op)

#define RFS_REM_OP(ops_new, ops_old, op) \
	(ops_new.op = ops_old ? ops_old->op : NULL)

#define RFS_SET_OP(arr, id, ops_new, ops_old, op) \
	(arr[id] ? \
	 	RFS_ADD_OP(ops_new, op) : \
	 	RFS_REM_OP(ops_new, ops_old, op) \
	)

#define RFS_SET_FOP(rf, id, op) \
	(rf->rdentry->rinfo->rops ? \
		RFS_SET_OP(rf->rdentry->rinfo->rops->arr, id, rf->op_new, \
			rf->op_old, op) : \
	 	RFS_REM_OP(rf->op_new, rf->op_old, op) \
	)

#define RFS_SET_DOP(rd, id, op) \
	(rd->rinfo->rops ? \
		RFS_SET_OP(rd->rinfo->rops->arr, id, rd->op_new,\
			rd->op_old, op) : \
	 	RFS_REM_OP(rd->op_new, rd->op_old, op) \
	)

#define RFS_SET_IOP_MGT(ri, op) \
	(ri->rinfo->rops ? \
	 	RFS_ADD_OP(ri->op_new, op) : \
	 	RFS_REM_OP(ri->op_new, ri->op_old, op) \
	)

#define RFS_SET_IOP(ri, id, op) \
	(ri->rinfo->rops ? \
	 	RFS_SET_OP(ri->rinfo->rops->arr, id, ri->op_new, \
			ri->op_old, op) : \
	 	RFS_REM_OP(ri->op_new, ri->op_old, op) \
	)

#define RFS_SET_AOP(ri, id, op) \
	(ri->rinfo->rops ? \
	 	RFS_SET_OP(ri->rinfo->rops->arr, id, ri->aop_new, \
			ri->aop_old, op) : \
	 	RFS_REM_OP(ri->aop_new, ri->aop_old, op) \
	)

#define RFS_NONE_OPS	1
#define RFS_REG_OPS	2
#define RFS_CHR_OPS	4
#define RFS_BLK_OPS	8
#define RFS_FIFO_OPS	16
#define RFS_LNK_OPS	32
#define RFS_SOCK_OPS	64

struct rfs_file;

struct rfs_op_info {
	enum redirfs_rv (*pre_cb)(redirfs_context, struct redirfs_args *);
	enum redirfs_rv (*post_cb)(redirfs_context, struct redirfs_args *);
};

struct rfs_flt {
	struct list_head list;
	struct rfs_op_info cbs[REDIRFS_OP_END];
	struct module *owner;
	struct kobject kobj;
	char *name;
	int priority;
	int paths_nr;
	spinlock_t lock;
	atomic_t active;
	int (*ctl_cb)(struct redirfs_ctl *ctl);
	int ctl_id;
};

void rfs_flt_put(struct rfs_flt *rflt);
struct rfs_flt *rfs_flt_get(struct rfs_flt *rflt);
void rfs_flt_release(struct kobject *kobj);

struct rfs_path {
	struct list_head list;
	struct list_head rfst_list;
	struct list_head rroot_list;
	struct rfs_root *rroot;
	struct rfs_chain *rinch;
	struct rfs_chain *rexch;
	struct vfsmount *mnt;
	struct dentry *dentry;
	atomic_t count;
	int id;
};

extern struct mutex rfs_path_mutex;

struct rfs_path *rfs_path_get(struct rfs_path *rpath);
void rfs_path_put(struct rfs_path *rpath);
struct rfs_path *rfs_path_find_id(int id);
int rfs_path_get_info(struct rfs_flt *rflt, char *buf, int size);
int rfs_fsrename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry);

struct rfs_root {
	struct list_head list;
	struct list_head walk_list;
	struct list_head rpaths;
	struct rfs_chain *rinch;
	struct rfs_chain *rexch;
	struct rfs_info *rinfo;
	struct dentry *dentry;
	atomic_t count;
};

extern struct list_head rfs_root_list;
extern struct list_head rfs_root_walk_list;

struct rfs_root *rfs_root_get(struct rfs_root *rroot);
void rfs_root_put(struct rfs_root *rroot);
void rfs_root_add_rpath(struct rfs_root *rroot, struct rfs_path *rpath);
void rfs_root_rem_rpath(struct rfs_root *rroot, struct rfs_path *rpath);
struct rfs_root *rfs_root_add(struct dentry *dentry);
int rfs_root_add_include(struct rfs_root *rroot, struct rfs_flt *rflt);
int rfs_root_add_exclude(struct rfs_root *rroot, struct rfs_flt *rflt);
int rfs_root_rem_include(struct rfs_root *rroot, struct rfs_flt *rflt);
int rfs_root_rem_exclude(struct rfs_root *rroot, struct rfs_flt *rflt);
int rfs_root_add_flt(struct rfs_root *rroot, void *data);
int rfs_root_rem_flt(struct rfs_root *rroot, void *data);
int rfs_root_walk(int (*cb)(struct rfs_root*, void *), void *data);
void rfs_root_add_walk(struct dentry *dentry);

struct rfs_ops {
	char *arr;
	atomic_t count;
	int flags;
};

struct rfs_ops *rfs_ops_alloc(void);
struct rfs_ops *rfs_ops_get(struct rfs_ops *rops);
void rfs_ops_put(struct rfs_ops *rops);
void rfs_ops_set_types(struct rfs_ops *rops);

struct rfs_chain {
	struct rfs_flt **rflts;
	int rflts_nr;
	atomic_t count;
};

struct rfs_chain *rfs_chain_get(struct rfs_chain *rchain);
void rfs_chain_put(struct rfs_chain *rchain);
int rfs_chain_find(struct rfs_chain *rchain, struct rfs_flt *rflt);
struct rfs_chain *rfs_chain_add(struct rfs_chain *rchain, struct rfs_flt *rflt);
struct rfs_chain *rfs_chain_rem(struct rfs_chain *rchain, struct rfs_flt *rflt);
void rfs_chain_ops(struct rfs_chain *rchain, struct rfs_ops *ops);
int rfs_chain_cmp(struct rfs_chain *rch1, struct rfs_chain *rch2);
struct rfs_chain *rfs_chain_join(struct rfs_chain *rch1,
		struct rfs_chain *rch2);
struct rfs_chain *rfs_chain_diff(struct rfs_chain *rch1,
		struct rfs_chain *rch2);

struct rfs_info {
	struct rfs_chain *rchain;
	struct rfs_ops *rops;
	struct rfs_root *rroot;
	atomic_t count;
};

extern struct rfs_info *rfs_info_none;

struct rfs_info *rfs_info_alloc(struct rfs_root *rroot,
		struct rfs_chain *rchain);
struct rfs_info *rfs_info_get(struct rfs_info *rinfo);
void rfs_info_put(struct rfs_info *rinfo);
int rfs_info_add_include(struct rfs_root *rroot, struct rfs_flt *rflt);
int rfs_info_add_exclude(struct rfs_root *rroot, struct rfs_flt *rflt);
int rfs_info_rem_include(struct rfs_root *rroot, struct rfs_flt *rflt);
int rfs_info_rem_exclude(struct rfs_root *rroot, struct rfs_flt *rflt);
int rfs_info_add(struct dentry *dentry, struct rfs_info *rinfo,
		struct rfs_flt *rflt);
int rfs_info_rem(struct dentry *dentry, struct rfs_info *rinfo,
		struct rfs_flt *rflt);
int rfs_info_set(struct dentry *dentry, struct rfs_info *rinfo);

struct rfs_dentry {
	struct list_head rinode_list;
	struct list_head rfiles;
	struct list_head data;
	struct dentry *dentry;
	struct dentry_operations *op_old;
	struct dentry_operations op_new;
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	spinlock_t lock;
	atomic_t count;
};

#define rfs_dentry_find(dentry) \
	(dentry && dentry->d_op && dentry->d_op->d_iput == rfs_d_iput ? \
	 rfs_dentry_get(container_of(dentry->d_op, struct rfs_dentry, op_new)) : \
	 NULL)

void rfs_d_iput(struct dentry *dentry, struct inode *inode);
struct rfs_dentry *rfs_dentry_get(struct rfs_dentry *rdentry);
void rfs_dentry_put(struct rfs_dentry *rdentry);
struct rfs_dentry *rfs_dentry_add(struct dentry *dentry,
		struct rfs_info *rinfo);
void rfs_dentry_del(struct rfs_dentry *rdentry);
int rfs_dentry_add_rinode(struct rfs_dentry *rdentry, struct rfs_info *rinfo);
void rfs_dentry_rem_rinode(struct rfs_dentry *rdentry);
struct rfs_info *rfs_dentry_get_rinfo(struct rfs_dentry *rdentry);
void rfs_dentry_set_rinfo(struct rfs_dentry *rdentry, struct rfs_info *rinfo);
void rfs_dentry_add_rfile(struct rfs_dentry *rdentry, struct rfs_file *rfile);
void rfs_dentry_rem_rfile(struct rfs_file *rfile);
void rfs_dentry_rem_rfiles(struct rfs_dentry *rdentry);
void rfs_dentry_set_ops(struct rfs_dentry *dentry);
int rfs_dentry_cache_create(void);
void rfs_dentry_cache_destory(void);
void rfs_dentry_rem_data(struct dentry *dentry, struct rfs_flt *rflt);

struct rfs_inode {
	struct list_head rdentries;
	struct list_head data;
	struct inode *inode;
	const struct inode_operations *op_old;
	const struct address_space_operations *aop_old;
	const struct file_operations *fop_old;
	struct inode_operations op_new;
	struct address_space_operations aop_new;
	struct rfs_info *rinfo;
	spinlock_t lock;
	atomic_t count;
	atomic_t nlink;
	int rdentries_nr;
};

#define rfs_inode_find(inode) \
	(inode && inode->i_op && inode->i_op->lookup == rfs_lookup ? \
	 rfs_inode_get(container_of(inode->i_op, struct rfs_inode, op_new)) : \
	 NULL)

struct dentry *rfs_lookup(struct inode *dir,struct dentry *dentry,
		struct nameidata *nd);
struct rfs_inode *rfs_inode_get(struct rfs_inode *rinode);
void rfs_inode_put(struct rfs_inode *rinode);
struct rfs_inode *rfs_inode_add(struct inode *inode, struct rfs_info *rinfo);
void rfs_inode_del(struct rfs_inode *rinode);
void rfs_inode_add_rdentry(struct rfs_inode *rinode,
		struct rfs_dentry *rdentry);
void rfs_inode_rem_rdentry(struct rfs_inode *rinode,
		struct rfs_dentry *rdentry);
struct rfs_info *rfs_inode_get_rinfo(struct rfs_inode *rinode);
int rfs_inode_set_rinfo(struct rfs_inode *rinode);
void rfs_inode_set_ops(struct rfs_inode *rinode);
int rfs_inode_cache_create(void);
void rfs_inode_cache_destroy(void);

struct rfs_file {
	struct list_head rdentry_list;
	struct list_head data;
	struct file *file;
	struct rfs_dentry *rdentry;
	const struct file_operations *op_old;
	struct file_operations op_new;
	spinlock_t lock;
	atomic_t count;
};

#define rfs_file_find(file) \
	(file && file->f_op && file->f_op->open == rfs_open ? \
	 rfs_file_get(container_of(file->f_op, struct rfs_file, op_new)) : \
	 NULL)
	 
extern struct file_operations rfs_file_ops;

int rfs_open(struct inode *inode, struct file *file);
struct rfs_file *rfs_file_get(struct rfs_file *rfile);
void rfs_file_put(struct rfs_file *rfile);
void rfs_file_set_ops(struct rfs_file *rfile);
int rfs_file_cache_create(void);
void rfs_file_cache_destory(void);

struct rfs_dcache_data {
	struct rfs_info *rinfo;
	struct rfs_flt *rflt;
	struct dentry *droot;
};

struct rfs_dcache_data *rfs_dcache_data_alloc(struct dentry *dentry,
		struct rfs_info *rinfo, struct rfs_flt *rflt);
void rfs_dcache_data_free(struct rfs_dcache_data *rdata);

struct rfs_dcache_entry {
	struct list_head list;
	struct dentry *dentry;
};

int rfs_dcache_walk(struct dentry *root, int (*cb)(struct dentry *, void *),
		void *data);
int rfs_dcache_add_dir(struct dentry *dentry, void *data);
int rfs_dcache_add(struct dentry *dentry, void *data);
int rfs_dcache_rem(struct dentry *dentry, void *data);
int rfs_dcache_set(struct dentry *dentry, void *data);
int rfs_dcache_rdentry_add(struct dentry *dentry, struct rfs_info *rinfo);
int rfs_dcache_rinode_del(struct rfs_dentry *rdentry, struct inode *inode);
int rfs_dcache_get_subs(struct dentry *dir, struct list_head *sibs);
void rfs_dcache_entry_free_list(struct list_head *head);

struct rfs_context {
	struct list_head data;
	int idx;
	int idx_start;
};

void rfs_context_init(struct rfs_context *rcont, int start);
void rfs_context_deinit(struct rfs_context *rcont);

int rfs_precall_flts(struct rfs_chain *rchain, struct rfs_context *rcont,
		struct redirfs_args *rargs);
void rfs_postcall_flts(struct rfs_chain *rchain, struct rfs_context *rcont,
		struct redirfs_args *rargs);

#define rfs_kobj_to_rflt(__kobj) container_of(__kobj, struct rfs_flt, kobj)
int rfs_flt_sysfs_init(struct rfs_flt *rflt);
void rfs_flt_sysfs_exit(struct rfs_flt *rflt);
extern struct kobj_type rfs_flt_ktype;

int rfs_sysfs_create(void);
void rfs_sysfs_destroy(void);

