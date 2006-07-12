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
void path_add_rinode(struct path *path, struct rinode *rinode);
void path_del_rinode(struct path *path, struct rinode *rinode);


struct rdentry {
	struct list_head rd_list;
	struct rcu_head rd_rcu;
	struct dentry *rd_dentry;
	struct dentry_operations *rd_op_old;
	struct dentry_operations rd_op_new;
	struct path *rd_path;
	atomic_t rd_count;
};

int rdentry_cache_create(void);
void rdentry_cache_destroy(void);
struct rdentry *rdentry_add(struct dentry *dentry, struct path *path);
void rdentry_del(struct dentry *dentry);
struct rdentry *rdentry_get(struct rdentry *rdentry);
void rdentry_put(struct rdentry *rdentry);
struct rdentry *rdentry_find(struct dentry *dentry);


struct rinode {
	struct list_head ri_list;
	struct rcu_head ri_rcu;
	struct inode *ri_inode;
	struct inode_operations *ri_op_old;
	struct file_operations *ri_fop_old;
	struct address_space_operations *ri_aop_old;
	struct inode_operations ri_op_new;
	struct file_operations ri_fop_new;
	struct address_space_operations ri_aop_new;
	struct path *ri_path;
	atomic_t ri_count;
	atomic_t ri_nlink;
};

int rinode_cache_create(void);
void rinode_cache_destroy(void);
struct rinode *rinode_add(struct inode *inode,
			  struct rdentry *rdentry,
			  struct path *path);
void rinode_del(struct inode *inode);
struct rinode *rinode_get(struct rinode *rinode);
void rinode_put(struct rinode *rinode);
struct rinode *rinode_find(struct inode *inode);

#endif /* _RFS_REDIR_H */
