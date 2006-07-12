#include "redir.h"

static kmem_cache_t *rinode_cache = NULL;

int rfs_permission(struct inode *inode, int mask, struct nameidata *nd);
int rfs_mkdir(struct inode *dir, struct dentry *dentry, int mode);
struct dentry *rfs_lookup(struct inode *inode,
			  struct dentry *dentry,
			  struct nameidata *nd);
int rfs_create(struct inode *dir,
	       struct dentry *dentry,
	       int mode,
	       struct nameidata *nd);

static struct rinode *rinode_alloc(struct inode *inode, struct path *path)
{
	struct rinode *rinode = NULL;


	rinode = kmem_cache_alloc(rinode_cache, SLAB_KERNEL);
	if (!rinode)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&rinode->ri_list);
	INIT_RCU_HEAD(&rinode->ri_rcu);
	rinode->ri_inode = inode;
	rinode->ri_op_old = inode->i_op;
	rinode->ri_fop_old = inode->i_fop;
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

	/*
	if (inode->i_fop)
		memcpy(&rinode->ri_fop_new, inode->i_fop,
				sizeof(struct file_operations));
	else
		memset(&rinode->ri_fop_new, 0,
				sizeof(struct file_operations));

	if (inode->i_mapping->a_ops)
		memcpy(&rinode->ri_aop_new, inode->i_mapping->a_ops,
				sizeof(struct address_space_operations));
	else
		memset(&rinode->ri_aop_new, 0,
				sizeof(struct address_space_operations));
	*/

	rinode->ri_op_new.lookup = rfs_lookup;
	rinode->ri_op_new.permission = rfs_permission;
	rinode->ri_op_new.mkdir = rfs_mkdir;
	rinode->ri_op_new.create= rfs_create;

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
	if (!rinode)
		return;

	BUG_ON(!atomic_read(&rinode->ri_count));
	if (!atomic_dec_and_test(&rinode->ri_count))
		return;
	
	path_put(rinode->ri_path);
	kmem_cache_free(rinode_cache, rinode);
}

inline struct rinode *rinode_find(struct inode *inode)
{
	struct rinode *rinode = NULL;
	struct inode_operations *i_op;

	if (!inode)
		return NULL;

	rcu_read_lock();
	i_op = rcu_dereference(inode->i_op);
	if (i_op) {
		if(i_op->lookup == rfs_lookup) {
			rinode = container_of(i_op, struct rinode, ri_op_new);
			rinode = rinode_get(rinode);
		}
	}
	rcu_read_unlock();

	return rinode;

}

struct rinode *rinode_add(struct inode *inode,
			  struct rdentry *rdentry,
			  struct path *path)
{
	struct rinode *rinode;
	struct rinode *rinode_new;


	if (!inode)
		return NULL;

	rinode_new = rinode_alloc(inode, path);
	if (IS_ERR(rinode_new))
		return rinode_new;

	spin_lock(&inode->i_lock);
	rinode = rinode_find(inode);
	if (rinode) {
		if (rdentry)
			atomic_inc(&rinode->ri_nlink);
		rinode_put(rinode_new);
		rinode_put(rinode);
		spin_unlock(&inode->i_lock);
		return NULL;
	}

	/*
	inode->i_fop = &rinode_new->ri_fop_new;
	inode->i_mapping->a_ops = &rinode_new->ri_aop_new;
	*/
	rcu_assign_pointer(inode->i_op, &rinode_new->ri_op_new);

	spin_unlock(&inode->i_lock);

	return rinode_get(rinode_new);
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


	if (!inode)
		return;

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

	/*
	inode->i_fop = rinode->ri_fop_old;
	inode->i_mapping->a_ops = rinode->ri_aop_old;
	*/
	rcu_assign_pointer(inode->i_op, rinode->ri_op_old);

	spin_unlock(&inode->i_lock);
	rinode_put(rinode);
	call_rcu(&rinode->ri_rcu, rinode_del_rcu);
}

int rfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	struct rinode *parent = rinode_find(dir);
	struct rinode *rinode;
	struct rdentry *rdentry;
	int rv = -EPERM;


	if (!parent) {
		if (dir->i_op && dir->i_op->mkdir)
			rv = dir->i_op->mkdir(dir, dentry, mode);
		return rv;
	}

	if (parent->ri_op_old && parent->ri_op_old->mkdir)
		rv = parent->ri_op_old->mkdir(dir, dentry, mode);

	spin_lock(&dir->i_lock);
	rdentry = rdentry_add(dentry, parent->ri_path);
	BUG_ON(IS_ERR(rdentry));

	rinode = rinode_add(dentry->d_inode, rdentry, parent->ri_path);
	BUG_ON(IS_ERR(rinode));

	path_add_rinode(parent->ri_path, rinode);
	path_add_rdentry(parent->ri_path, rdentry);

	spin_unlock(&dir->i_lock);

	rinode_put(rinode);
	rdentry_put(rdentry);
	rinode_put(parent);

	return rv;
}

int rfs_create(struct inode *dir,
	       struct dentry *dentry,
	       int mode,
	       struct nameidata *nd)
{
	struct rinode *parent = rinode_find(dir);
	struct rinode *rinode;
	struct rdentry *rdentry;
	int rv = -EACCES;


	if (!parent) {
		if (dir->i_op && dir->i_op->create)
			rv = dir->i_op->create(dir, dentry, mode, nd);
		return rv;
	}

	if (parent->ri_op_old && parent->ri_op_old->create)
		rv = parent->ri_op_old->create(dir, dentry, mode, nd);

	spin_lock(&dir->i_lock);
	rdentry = rdentry_add(dentry, parent->ri_path);
	BUG_ON(IS_ERR(rdentry));

	rinode = rinode_add(dentry->d_inode, rdentry, parent->ri_path);
	BUG_ON(IS_ERR(rinode));

	path_add_rinode(parent->ri_path, rinode);
	path_add_rdentry(parent->ri_path, rdentry);

	spin_unlock(&dir->i_lock);

	rinode_put(rinode);
	rdentry_put(rdentry);
	rinode_put(parent);

	return rv;
}

struct dentry *rfs_lookup(struct inode *inode,
			  struct dentry *dentry,
			  struct nameidata *nd)
{
	struct rinode *parent = rinode_find(inode);
	struct rinode *rinode;
	struct rdentry *rdentry;
	struct dentry *rv = NULL;


	if (!parent) {
		if (inode->i_op && inode->i_op->lookup)
			rv = inode->i_op->lookup(inode, dentry, nd);
		return rv;
	}

	if (parent->ri_op_old && parent->ri_op_old->lookup)
		rv = parent->ri_op_old->lookup(inode, dentry, nd);

	spin_lock(&inode->i_lock);
	rdentry = rdentry_add(dentry, parent->ri_path);
	BUG_ON(IS_ERR(rdentry));

	rinode = rinode_add(dentry->d_inode, rdentry, parent->ri_path);
	BUG_ON(IS_ERR(rinode));

	path_add_rinode(parent->ri_path, rinode);
	path_add_rdentry(parent->ri_path, rdentry);

	spin_unlock(&inode->i_lock);

	rinode_put(rinode);
	rdentry_put(rdentry);
	rinode_put(parent);

	return rv;
}

int rfs_permission(struct inode *inode, int mask, struct nameidata *nd)
{
	struct rinode *rinode = rinode_find(inode);
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

	if (nd && nd->dentry)
		printk(KERN_ERR "rfs_permission dname: %s\n", nd->dentry->d_name.name);

	return rv;
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

