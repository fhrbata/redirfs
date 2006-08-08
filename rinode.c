#include "redir.h"

static kmem_cache_t *rinode_cache = NULL;

struct rinode *rinode_alloc(struct inode *inode, struct path *path)
{
	struct rinode *rinode = NULL;


	rinode = kmem_cache_alloc(rinode_cache, SLAB_KERNEL);
	if (!rinode)
		return ERR_PTR(-ENOMEM);

	INIT_RCU_HEAD(&rinode->ri_rcu);
	INIT_LIST_HEAD(&rinode->ri_rdentries);
	rinode->ri_inode = inode;
	rinode->ri_op_old = inode->i_op;
	rinode->ri_fop_old = (struct file_operations *)inode->i_fop;
	rinode->ri_aop_old = inode->i_mapping->a_ops;
	rinode->ri_path = path_get(path);
	atomic_set(&rinode->ri_count, 1);
	atomic_set(&rinode->ri_nlink, 1);

	if (inode->i_op)
		memcpy(&rinode->ri_op_new, inode->i_op,
				sizeof(struct inode_operations));
	else
		memset(&rinode->ri_op_new, 0,
				sizeof(struct inode_operations));

	if (inode->i_mapping->a_ops)
		memcpy(&rinode->ri_aop_new, inode->i_mapping->a_ops,
				sizeof(struct address_space_operations));
	else
		memset(&rinode->ri_aop_new, 0,
				sizeof(struct address_space_operations));

	return rinode;
}

inline struct rinode *rinode_get(struct rinode *rinode)
{
	BUG_ON(!atomic_read(&rinode->ri_count));
	atomic_inc(&rinode->ri_count);
	return rinode;
}

inline void rinode_put(struct rinode *rinode)
{
	if (!rinode || IS_ERR(rinode))
		return;

	BUG_ON(!atomic_read(&rinode->ri_count));
	if (!atomic_dec_and_test(&rinode->ri_count))
		return;
	
	path_put(rinode->ri_path);
	BUG_ON(!list_empty(&rinode->ri_rdentries));
	kmem_cache_free(rinode_cache, rinode);
}

inline struct rinode *rinode_find(struct inode *inode)
{
	struct rinode *rinode = NULL;
	struct inode_operations *i_op;


	rcu_read_lock();
	i_op = rcu_dereference(inode->i_op);
	if (i_op) {
		if (i_op->lookup == rfs_lookup) {
			rinode = container_of(i_op, struct rinode, ri_op_new);
			rinode = rinode_get(rinode);
		}
	}
	rcu_read_unlock();

	return rinode;
}

static inline void rinode_del_rcu(struct rcu_head *head)
{
	struct rinode *rinode = NULL;

	
	rinode = container_of(head, struct rinode, ri_rcu);
	rinode_put(rinode);
}

void rinode_del(struct inode *inode)
{
	struct rinode *rinode = NULL;


	spin_lock(&inode->i_lock);

	rinode = rinode_find(inode);
	if (!rinode) {
		spin_unlock(&inode->i_lock);
		return;
	}

	if (!atomic_dec_and_test(&rinode->ri_nlink)) {
		spin_unlock(&inode->i_lock);
		rinode_put(rinode);
		return;
	}

	inode->i_fop = rinode->ri_fop_old;
	inode->i_mapping->a_ops = rinode->ri_aop_old;
	rcu_assign_pointer(inode->i_op, rinode->ri_op_old);

	rinode_put(rinode);

	spin_unlock(&inode->i_lock);

	call_rcu(&rinode->ri_rcu, rinode_del_rcu);
}

inline struct path *rinode_get_path(struct rinode *rinode)
{
	struct path *path;


	if (!rinode)
		return NULL;

	spin_lock(&rinode->ri_inode->i_lock);
	path = path_get(rinode->ri_path);
	spin_unlock(&rinode->ri_inode->i_lock);

	return path;
}

int rfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	struct rinode *parent = rinode_find(dir);
	struct path *path = rinode_get_path(parent);
	struct rdentry *rdentry;
	int rv = -EPERM;


	if (!parent) {
		if (dir->i_op && dir->i_op->mkdir)
			rv = dir->i_op->mkdir(dir, dentry, mode);
		return rv;
	}

	if (parent->ri_op_old && parent->ri_op_old->mkdir)
		rv = parent->ri_op_old->mkdir(dir, dentry, mode);

	rdentry = rdentry_add(dentry, path);
	BUG_ON(IS_ERR(rdentry));

	rdentry_put(rdentry);
	rinode_put(parent);
	path_put(path);

	return rv;
}

int rfs_create(struct inode *dir,
	       struct dentry *dentry,
	       int mode,
	       struct nameidata *nd)
{
	struct rinode *parent = rinode_find(dir);
	struct path *path = rinode_get_path(parent);
	struct rdentry *rdentry;
	int rv = -EACCES;


	if (!parent) {
		if (dir->i_op && dir->i_op->create)
			rv = dir->i_op->create(dir, dentry, mode, nd);
		return rv;
	}

	if (parent->ri_op_old && parent->ri_op_old->create)
		rv = parent->ri_op_old->create(dir, dentry, mode, nd);

	rdentry = rdentry_add(dentry, path);
	BUG_ON(IS_ERR(rdentry));

	rdentry_put(rdentry);
	rinode_put(parent);
	path_put(path);

	return rv;
}

struct dentry *rfs_lookup(struct inode *inode,
			  struct dentry *dentry,
			  struct nameidata *nd)
{
	struct rinode *parent = rinode_find(inode);
	struct path *path = rinode_get_path(parent);
	struct rdentry *rdentry;
	struct dentry *rv = NULL;


	if (!parent) {
		if (inode->i_op && inode->i_op->lookup)
			rv = inode->i_op->lookup(inode, dentry, nd);
		return rv;
	}

	if (parent->ri_op_old && parent->ri_op_old->lookup)
		rv = parent->ri_op_old->lookup(inode, dentry, nd);

	rdentry = rdentry_add(dentry, path);
	BUG_ON(IS_ERR(rdentry));

	rdentry_put(rdentry);
	rinode_put(parent);
	path_put(path);

	return rv;
}

int rfs_permission(struct inode *inode, int mask, struct nameidata *nd)
{
	struct rinode *rinode = rinode_find(inode);
	struct path *path = rinode_get_path(rinode);
	int submask = mask & ~MAY_APPEND;
	int rv;

	
	if (!rinode) {
		if (inode->i_op && inode->i_op->permission)
			rv = inode->i_op->permission(inode, mask, nd);
		else
			rv = generic_permission(inode, submask, NULL);
		return rv;
	}

	if (rinode->ri_op_old && rinode->ri_op_old->permission)
		rv = rinode->ri_op_old->permission(inode, mask, nd);
	else
		rv = generic_permission(inode, submask, NULL);

	rinode_put(rinode);
	path_put(path);

	return rv;
}

void rinode_set_ops(struct rinode *rinode, struct path *path)
{
	spin_lock(&path->p_lock);

	rinode->ri_op_new.lookup = rfs_lookup;
	rinode->ri_op_new.mkdir = rfs_mkdir;
	rinode->ri_op_new.create = rfs_create;

	spin_unlock(&path->p_lock);
}

int rinode_cache_create(void)
{
	rinode_cache = kmem_cache_create("rinode_cache",
					  sizeof(struct rinode),
					  0, SLAB_RECLAIM_ACCOUNT,
					  NULL, NULL);
	if (!rinode_cache)
		return -1;

	return 0;
}

void rinode_cache_destroy(void)
{
	kmem_cache_destroy(rinode_cache);
}

