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

struct rdentry;
struct rinode;

struct path {
	struct list_head p_rdentry;
	struct list_head p_rinode;
	atomic_t p_count;
	spinlock_t p_lock;
};

int path_del(struct path *path);
struct path *path_alloc(void);
struct path *path_get(struct path *path);
void path_put(struct path *path);
void path_add_rdentry(struct path *path, struct rdentry *rdentry);
void path_del_rdentry(struct path *path, struct rdentry *rdentry);

struct rfile {
	struct list_head rf_rdentry_list;
	struct rdentry *rf_rdentry;
	struct rcu_head rf_rcu;
	struct path *rf_path;
	struct file *rf_file;
	struct file_operations *rf_op_old;
	struct file_operations rf_op_new;
	atomic_t rf_count;
};

int rfile_cache_create(void);
void rfile_cache_destroy(void);
struct rfile *rfile_add(struct file *file);
void rfile_del(struct file *file);
struct rfile *rfile_get(struct rfile* rfile);
void rfile_put(struct rfile *rfile);
struct rfile* rfile_find(struct file *file);
void rfile_set_ops(struct rfile *rfile, struct path *path);
int rfs_open(struct inode *inode, struct file *file);


struct rdentry {
	struct list_head rd_list;
	struct list_head rd_rinode_list;
	struct list_head rd_rfiles;
	struct rcu_head rd_rcu;
	struct dentry *rd_dentry;
	struct dentry_operations *rd_op_old;
	struct dentry_operations rd_op_new;
	struct path *rd_path;
	struct rinode *rd_rinode;
	atomic_t rd_count;
};

int rdentry_cache_create(void);
void rdentry_cache_destroy(void);
struct rdentry *rdentry_add(struct dentry *dentry, struct path *path);
struct rdentry *rdentry_del(struct dentry *dentry);
struct rdentry *rdentry_get(struct rdentry *rdentry);
void rdentry_put(struct rdentry *rdentry);
struct rdentry *rdentry_find(struct dentry *dentry);
void rdentry_set_ops(struct rdentry *rdentry, struct path *path);
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
	atomic_t ri_count;
	atomic_t ri_nlink;
};

int rinode_cache_create(void);
void rinode_cache_destroy(void);
struct rinode *rinode_alloc(struct inode *inode, struct path *path);
void rinode_del(struct inode *inode);
struct rinode *rinode_get(struct rinode *rinode);
void rinode_put(struct rinode *rinode);
struct rinode *rinode_find(struct inode *inode);
void rinode_set_ops(struct rinode *rinode, struct path *path);
struct dentry *rfs_lookup(struct inode *inode,
			  struct dentry *dentry,
			  struct nameidata *nd);


#endif /* _RFS_REDIR_H */
