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
#include <asm/uaccess.h>
#include <linux/device.h>
#include "redirfs.h"
#include "debug.h"

struct rdentry;
struct rinode;
struct rpath;

struct filter {
	struct list_head f_list;
	const char *f_name;
	int f_priority;
	enum rfs_retv (*f_pre_cbs[RFS_OP_END])(rfs_context, struct rfs_args *);
	enum rfs_retv (*f_post_cbs[RFS_OP_END])(rfs_context, struct rfs_args *);
	int (*mod_cb)(union rfs_mod *);
	unsigned long long f_count;
	atomic_t f_active;
	atomic_t f_del;
	wait_queue_head_t f_wait;
	spinlock_t f_lock;
};

int flt_add_local(struct rpath *path, struct filter *flt);
int flt_rem_local(struct rpath *path, struct filter *flt);
int flt_add_cb(struct rpath *path, void *data);
int flt_rem_cb(struct rpath *path, void *data);
struct filter *flt_get(struct filter *flt);
void flt_put(struct filter *flt);
struct filter *flt_alloc(struct rfs_filter_info *flt_info);
int flt_set_ops_cb(struct rpath *path, void *data);
int flt_proc_info(char *buf, int size);
int flt_get_by_name(rfs_filter *filter, char *name);
int flt_get_all_infos(struct rfs_filter_info **filters_info, int *count);
int flt_execute_mod_cb(struct filter *flt, union rfs_mod *mod);

struct ops {
	spinlock_t o_lock;
	unsigned long long o_count;
	char *o_ops;
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
void chain_get_ops(struct chain *chain, char *ops);
struct chain *chain_copy(struct chain *src);
int chain_cmp(struct chain *chain1, struct chain *chain2);


struct rpath {
	char *p_path;
	int p_len;
	int p_flags;
	struct dentry *p_dentry;
	unsigned long long p_count;
	spinlock_t p_lock;
	struct rpath *p_parent;
	struct list_head p_subpath;
	struct list_head p_sibpath;
	struct list_head p_rem;
	struct chain *p_inchain;
	struct chain *p_exchain;
	struct chain *p_inchain_local;
	struct chain *p_exchain_local;
	struct ops *p_ops;
	struct ops *p_ops_local;
};
#if defined(RFS_DEBUG)
void path_dump(void);
#endif

int path_del(struct rpath *path);
struct rpath *path_alloc(const char *path_name);
struct rpath *path_get(struct rpath *path);
void path_put(struct rpath *path);
void path_add_rdentry(struct rpath *path, struct rdentry *rdentry);
void path_del_rdentry(struct rpath *path, struct rdentry *rdentry);
int rfs_path_walk(struct rpath *path, int walkcb(struct rpath*, void*), void *datacb);
void path_rem(struct rpath *path);
int path_proc_info(char *buf, int size);
int path_get_infos(rfs_filter filter, struct rfs_path_info **paths_info, int *count);

struct rfile {
	struct list_head rf_rdentry_list;
	struct rdentry *rf_rdentry;
	struct rcu_head rf_rcu;
	struct rpath *rf_path;
	struct chain *rf_chain;
	struct file *rf_file;
	struct file_operations *rf_op_old;
	struct file_operations rf_op_new;
	atomic_t rf_count;
	spinlock_t rf_lock;
	struct list_head rf_data;
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
	struct rpath *rd_path;
	struct chain *rd_chain;
	struct rinode *rd_rinode;
	spinlock_t rd_lock;
	atomic_t rd_count;
	int rd_root;
	struct ops *rd_ops;
	struct list_head rd_data;
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
void rfs_d_iput(struct dentry *dentry, struct inode *inode);


struct rinode {
	struct list_head ri_rdentries;
	struct rcu_head ri_rcu;
	struct inode *ri_inode;
	struct inode_operations *ri_op_old;
	struct file_operations *ri_fop_old;
	struct address_space_operations *ri_aop_old;
	struct address_space_operations ri_aop_new;
	struct inode_operations ri_op_new;
	struct rpath *ri_path;
	struct chain *ri_chain;
	struct rpath *ri_path_set;
	struct chain *ri_chain_set;
	struct ops *ri_ops_set;
	spinlock_t ri_lock;
	atomic_t ri_count;
	atomic_t ri_nlink;
	struct list_head ri_data;
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

struct data {
	struct list_head list;
	struct filter *filter;
	void (*cb)(void *data);
	void *data;
};

struct data *data_find(struct list_head *head, struct filter *flt);

int rfs_replace_ops(struct rpath *path_old, struct rpath *path_new);
int rfs_replace_ops_cb(struct dentry *dentry, void *data);
int rfs_restore_ops_cb(struct dentry *dentry, void *data);
int rfs_set_path_cb(struct dentry *dentry, void *data);
int rfs_set_ops(struct dentry *dentry, struct rpath *path);
int rfs_set_ops_cb(struct dentry *dentry, void *data);
int rfs_walk_dcache(struct dentry *root, int (*)(struct dentry *, void *), void *, int (*)(struct dentry *, void *), void *);
int rfs_precall_flts(struct chain *chain, struct context *context, struct rfs_args *args, int *cnt);
int rfs_postcall_flts(struct chain *chain, struct context *context, struct rfs_args *args, int *cnt);

int rfs_proc_init(void);
void rfs_proc_destroy(void);

int redirctl_init(void);
void redirctl_destroy(void);

#endif /* _RFS_REDIR_H */

