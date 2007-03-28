#if !defined(_RFS_REDIR_H)
#define _RFS_REDIR_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/hash.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include "redirfs.h"

struct rdentry;
struct rinode;
struct path;

struct filter {
	struct list_head f_list;
	const char *f_name;
	int f_priority;
	enum rfs_retv (*f_pre_cbs[RFS_OP_END])(rfs_context, struct rfs_args *);
	enum rfs_retv (*f_post_cbs[RFS_OP_END])(rfs_context, struct rfs_args *);
	atomic_t f_count;
	atomic_t f_active;
	atomic_t f_del;
	wait_queue_head_t f_wait;
};

int flt_add_local(struct path *path, struct filter *flt);
int flt_rem_local(struct path *path, struct filter *flt);
int flt_add_cb(struct path *path, void *data);
int flt_rem_cb(struct path *path, void *data);
struct filter *flt_get(struct filter *flt);
void flt_put(struct filter *flt);
struct filter *flt_alloc(struct rfs_filter_info *flt_info);
int flt_set_ops_cb(struct path *path, void *data);


struct ops {
	spinlock_t o_lock;
	unsigned long long o_count;
	int *o_ops;
};

struct ops *ops_alloc(void);
struct ops *ops_get(struct ops *ops);
void ops_put(struct ops *ops);


struct chain {
	spinlock_t c_lock;
	unsigned long long c_count;
	struct filter **c_flts;
	int c_flts_nr;
};

struct chain *chain_alloc(int size);
struct chain *chain_get(struct chain *chain);
void chain_put(struct chain *chain);
int chain_find_flt(struct chain *chain, struct filter *flt);
struct chain *chain_add_flt(struct chain *chain, struct filter *flt);
struct chain *chain_rem_flt(struct chain *chain, struct filter *flt);
void chain_get_ops(struct chain *chain, int *ops);
struct chain *chain_copy(struct chain *src);
int chain_cmp(struct chain *chain1, struct chain *chain2);


struct path {
	char *p_path;
	int p_len;
	int p_flags;
	struct dentry *p_dentry;
	unsigned long long p_count;
	spinlock_t p_lock;
	struct path *p_parent;
	struct list_head p_subpath;
	struct list_head p_sibpath;
	struct list_head p_rem;
	struct chain *p_inchain;
	struct chain *p_exchain;
	struct chain *p_inchain_local;
	struct chain *p_exchain_local;
	struct ops *p_ops;
};

int path_del(struct path *path);
struct path *path_alloc(const char *path_name);
struct path *path_get(struct path *path);
void path_put(struct path *path);
void path_add_rdentry(struct path *path, struct rdentry *rdentry);
void path_del_rdentry(struct path *path, struct rdentry *rdentry);
int rfs_path_walk(struct path *path, int walkcb(struct path*, void*), void *datacb);
void path_rem(struct path *path);

struct rfile {
	struct list_head rf_rdentry_list;
	struct rdentry *rf_rdentry;
	struct rcu_head rf_rcu;
	struct path *rf_path;
	struct chain *rf_chain;
	struct file *rf_file;
	struct file_operations *rf_op_old;
	struct file_operations rf_op_new;
	atomic_t rf_count;
	spinlock_t rf_lock;
};

int rfile_cache_create(void);
void rfile_cache_destroy(void);
struct rfile *rfile_add(struct file *file);
void rfile_del(struct file *file);
struct rfile *rfile_get(struct rfile* rfile);
void rfile_put(struct rfile *rfile);
struct rfile* rfile_find(struct file *file);
void rfile_set_ops(struct rfile *rfile, struct ops *ops);
int rfs_open(struct inode *inode, struct file *file);


struct rdentry {
	struct list_head rd_rinode_list;
	struct list_head rd_rfiles;
	struct rcu_head rd_rcu;
	struct dentry *rd_dentry;
	struct dentry_operations *rd_op_old;
	struct dentry_operations rd_op_new;
	struct path *rd_path;
	struct chain *rd_chain;
	struct rinode *rd_rinode;
	spinlock_t rd_lock;
	atomic_t rd_count;
	int rd_root;
};

int rdentry_cache_create(void);
void rdentry_cache_destroy(void);
struct rdentry *rdentry_alloc(struct dentry* dentry);
struct rdentry *rdentry_get(struct rdentry *rdentry);
void rdentry_put(struct rdentry *rdentry);
struct rdentry *rdentry_find(struct dentry *dentry);
struct rdentry *rdentry_add(struct dentry *dentry);
void rdentry_del(struct dentry *dentry);
void rdentry_set_ops(struct rdentry *rdentry, struct ops *ops);
void rfs_d_release(struct dentry *dentry);


struct rinode {
	struct list_head ri_rdentries;
	struct rcu_head ri_rcu;
	struct inode *ri_inode;
	struct inode_operations *ri_op_old;
	struct file_operations *ri_fop_old;
	struct address_space_operations *ri_aop_old;
	struct address_space_operations ri_aop_new;
	struct inode_operations ri_op_new;
	struct path *ri_path;
	struct chain *ri_chain;
	struct path *ri_path_set;
	struct chain *ri_chain_set;
	struct ops *ri_ops_set;
	spinlock_t ri_lock;
	atomic_t ri_count;
	atomic_t ri_nlink;
};

int rinode_cache_create(void);
void rinode_cache_destroy(void);
struct rinode *rinode_alloc(struct inode *inode);
struct rinode *rinode_get(struct rinode *rinode);
void rinode_put(struct rinode *rinode);
struct rinode *rinode_find(struct inode *inode);
void rinode_del(struct inode *inode);
void rinode_set_ops(struct rinode *rinode, struct ops *ops);
struct dentry *rfs_lookup(struct inode *inode, struct dentry *dentry, struct nameidata *nd);

struct context {
};

int rfs_replace_ops(struct path *path_old, struct path *path_new);
int rfs_replace_ops_cb(struct dentry *dentry, void *data);
int rfs_restore_ops_cb(struct dentry *dentry, void *data);
int rfs_set_path_cb(struct dentry *dentry, void *data);
int rfs_set_ops(struct dentry *dentry, struct path *path);
int rfs_set_ops_cb(struct dentry *dentry, void *data);
int rfs_walk_dcache(struct dentry *root, int (*)(struct dentry *, void *), void *, int (*)(struct dentry *, void *), void *);
int rfs_precall_flts(struct chain *chain, struct context *context, struct rfs_args *args);
int rfs_postcall_flts(struct chain *chain, struct context *context, struct rfs_args *args);

#endif /* _RFS_REDIR_H */

