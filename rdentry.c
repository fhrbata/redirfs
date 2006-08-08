#include "redir.h"

static kmem_cache_t *rdentry_cache = NULL;
spinlock_t rdentry_list_lock = SPIN_LOCK_UNLOCKED;
LIST_HEAD(rdentry_list);

extern struct file_operations rfs_file_ops;

static struct rdentry *rdentry_alloc(struct dentry* dentry, struct path *path)
{
	struct rdentry *rdentry = NULL;


	rdentry = kmem_cache_alloc(rdentry_cache, SLAB_KERNEL);
	if (!rdentry)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&rdentry->rd_list);
	INIT_LIST_HEAD(&rdentry->rd_rfiles);
	INIT_LIST_HEAD(&rdentry->rd_rinode_list);
	INIT_RCU_HEAD(&rdentry->rd_rcu);
	rdentry->rd_op_old = dentry->d_op;
	rdentry->rd_dentry = dentry;
	rdentry->rd_path = path_get(path);
	rdentry->rd_rinode = NULL;
	atomic_set(&rdentry->rd_count, 1);

	if (dentry->d_op)
		memcpy(&rdentry->rd_op_new, dentry->d_op, 
				sizeof(struct dentry_operations));
	else
		memset(&rdentry->rd_op_new, 0, 
				sizeof(struct dentry_operations));

	return rdentry;
}

inline struct rdentry *rdentry_get(struct rdentry *rdentry)
{
	BUG_ON(!atomic_read(&rdentry->rd_count));
	atomic_inc(&rdentry->rd_count);
	return rdentry;
}

inline void rdentry_put(struct rdentry *rdentry)
{
	if (!rdentry || IS_ERR(rdentry))
		return;

	BUG_ON(!atomic_read(&rdentry->rd_count));
	if (!atomic_dec_and_test(&rdentry->rd_count))
		return;

	BUG_ON(!list_empty(&rdentry->rd_rfiles));

	path_put(rdentry->rd_path);
	rinode_put(rdentry->rd_rinode);

	kmem_cache_free(rdentry_cache, rdentry);
}


inline struct rdentry *rdentry_find(struct dentry *dentry)
{
	struct rdentry *rdentry = NULL;
	struct dentry_operations *d_op;


	rcu_read_lock();
	d_op = rcu_dereference(dentry->d_op);
	if (d_op) {
		if (d_op->d_release == rfs_d_release) {
			rdentry = container_of(d_op, struct rdentry, rd_op_new);
			rdentry = rdentry_get(rdentry);
		}
	}
	rcu_read_unlock();

	return rdentry;
}

struct rdentry *rdentry_add(struct dentry *dentry, struct path *path)
{
	struct rdentry *rdentry = NULL;
	struct rdentry *rdentry_new = NULL;
	struct rinode *rinode = NULL;
	struct rinode *rinode_new = NULL;
	struct inode *inode = dentry->d_inode;


	rdentry_new = rdentry_alloc(dentry, path);
	if (IS_ERR(rdentry_new))
			return rdentry_new;

	if (inode) {
		rinode_new = rinode_alloc(inode, path);
		if (IS_ERR(rinode_new)) {
			rdentry_put(rdentry_new);
			return ERR_PTR(PTR_ERR(rinode_new));
		}
	}

	spin_lock(&dentry->d_lock);

	rdentry = rdentry_find(dentry);

	if (rdentry) {
		rdentry_put(rdentry_new);
		rdentry_new = NULL;

	} else {
		rcu_assign_pointer(dentry->d_op, &rdentry_new->rd_op_new);
		rdentry = rdentry_get(rdentry_new);
		spin_lock(&rdentry_list_lock);
		list_add_tail(&rdentry->rd_list, &rdentry_list);
		spin_unlock(&rdentry_list_lock);
	}

	if (!inode || rdentry->rd_rinode) {
		if (rdentry_new)
			rdentry_set_ops(rdentry, path);

		spin_unlock(&dentry->d_lock);
		rinode_put(rinode_new);
		return rdentry;
	}

	spin_lock(&inode->i_lock);

	rinode = rinode_find(inode);

	if (rinode) {
		rinode_put(rinode_new);
		atomic_inc(&rinode->ri_nlink);
		rinode_new = NULL;

	} else {
		inode->i_fop = &rfs_file_ops;
		inode->i_mapping->a_ops = &rinode_new->ri_aop_new;
		rcu_assign_pointer(inode->i_op, &rinode_new->ri_op_new);
		rinode = rinode_get(rinode_new);
	}

	rdentry->rd_rinode = rinode;
	list_add_tail(&rdentry->rd_rinode_list, &rinode->ri_rdentries);
	rdentry_get(rdentry);

	if (rinode_new)
		rinode_set_ops(rinode, path);

	if (rdentry_new)
		rdentry_set_ops(rdentry, path);

	spin_unlock(&inode->i_lock);
	spin_unlock(&dentry->d_lock);

	return rdentry;
}

static inline void rdentry_del_rcu(struct rcu_head *head)
{
	struct rdentry *rdentry = NULL;


	rdentry = container_of(head, struct rdentry, rd_rcu);
	rdentry_put(rdentry);
}

struct rdentry *rdentry_del(struct dentry *dentry)
{
	struct rdentry *rdentry = NULL;
	struct rinode *rinode = NULL;


	spin_lock(&dentry->d_lock);

	rdentry = rdentry_find(dentry);
	if (!rdentry) {
		spin_unlock(&dentry->d_lock);
		return NULL;
	}

	rcu_assign_pointer(dentry->d_op, rdentry->rd_op_old);

	rinode = rdentry->rd_rinode;

	if (rinode) {
		rinode_del(rinode->ri_inode);
		spin_lock(&rinode->ri_inode->i_lock);
		list_del_init(&rdentry->rd_rinode_list);
		rdentry_put(rdentry);
		spin_unlock(&rinode->ri_inode->i_lock);
	}

	spin_unlock(&dentry->d_lock);

	call_rcu(&rdentry->rd_rcu, rdentry_del_rcu);

	return rdentry;
}

inline struct path *rdentry_get_path(struct rdentry *rdentry)
{
	struct path *path;


	if (!rdentry)
		return NULL;

	spin_lock(&rdentry->rd_dentry->d_lock);
	path = path_get(rdentry->rd_path);
	spin_unlock(&rdentry->rd_dentry->d_lock);

	return path;
}

int rfs_d_revalidate(struct dentry *dentry, struct nameidata *nd)
{
	struct rdentry *rdentry = rdentry_find(dentry);
	struct path *path = rdentry_get_path(rdentry);
	int rv = 1;


	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_revalidate)
			rv = dentry->d_op->d_revalidate(dentry, nd);
		return rv;
	}

	if (rdentry->rd_op_old && rdentry->rd_op_old->d_revalidate)
		rv = rdentry->rd_op_old->d_revalidate(dentry, nd);

	rdentry_put(rdentry);
	path_put(path);

	return rv;
}

int rfs_d_hash(struct dentry *dentry, struct qstr *name)
{
	struct rdentry *rdentry = rdentry_find(dentry);
	struct path *path = rdentry_get_path(rdentry);
	int rv = 0;


	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_hash)
			rv = dentry->d_op->d_hash(dentry, name);
		return rv;
	}

	if (rdentry->rd_op_old && rdentry->rd_op_old->d_hash)
		rv = rdentry->rd_op_old->d_hash(dentry, name);

	rdentry_put(rdentry);
	path_put(path);

	return rv;
}

static inline int rfs_d_compare_default(struct qstr *name1, struct qstr *name2)
{
	if (name1->len != name2->len)
		return 1;
	if (memcmp(name1->name, name2->name, name1->len))
		return 1;

	return 0;
}

int rfs_d_compare(struct dentry *dentry, struct qstr *name1, struct qstr *name2)
{
	struct rdentry *rdentry = rdentry_find(dentry);
	struct path *path = rdentry_get_path(rdentry);
	int rv;


	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_compare)
			rv = dentry->d_op->d_compare(dentry, name1, name2);
		else
			rv = rfs_d_compare_default(name1, name2);

		return rv;
	}

	if (rdentry->rd_op_old && rdentry->rd_op_old->d_compare)
		rv = rdentry->rd_op_old->d_compare(dentry, name1, name2);
	else
		rv = rfs_d_compare_default(name1, name2);

	rdentry_put(rdentry);
	path_put(path);

	return rv;
}

int rfs_d_delete(struct dentry *dentry)
{
	struct rdentry *rdentry = rdentry_find(dentry);
	struct path *path;
	int rv = 0;

	if(rdentry)
		path = rdentry->rd_path;

	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_delete)
			rv = dentry->d_op->d_delete(dentry);
		return rv;
	}

	if (rdentry->rd_op_old && rdentry->rd_op_old->d_delete)
		rv = rdentry->rd_op_old->d_delete(dentry);

	rdentry_put(rdentry);
	path_put(path);

	return rv;
}

void rfs_d_release(struct dentry *dentry)
{
	struct rdentry *rdentry = rdentry_find(dentry);
	struct path *path = rdentry_get_path(rdentry);
	struct rdentry *rdentry_rem;


	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_release)
			dentry->d_op->d_release(dentry);
		return;
	}

	if (rdentry->rd_op_old && rdentry->rd_op_old->d_release)
		rdentry->rd_op_old->d_release(dentry);


	rdentry_rem = rdentry_del(dentry);
	if (rdentry_rem) {
		spin_lock(&rdentry_list_lock);
		list_del_init(&rdentry_rem->rd_list);
		spin_unlock(&rdentry_list_lock);
		rdentry_put(rdentry_rem);
	}
	rdentry_put(rdentry);
	path_put(path);
}

void rfs_d_iput(struct dentry *dentry, struct inode *inode)
{
	struct rdentry *rdentry = rdentry_find(dentry);
	struct rinode *rinode = rinode_find(inode);
	struct path *path = rdentry_get_path(rdentry);


	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_iput)
			dentry->d_op->d_iput(dentry, inode);
		else
			iput(inode);
		return;
	}

	if (rdentry->rd_op_old && rdentry->rd_op_old->d_iput)
		rdentry->rd_op_old->d_iput(dentry, inode);
	else
		iput(inode);

	rinode_del(inode);

	rinode_put(rinode);
	rdentry_put(rdentry);
	path_put(path);
}

void rdentry_set_ops(struct rdentry *rdentry, struct path *path)
{

	spin_lock(&path->p_lock);
	rdentry->rd_op_new.d_release = rfs_d_release;
	rdentry->rd_op_new.d_iput = rfs_d_iput;

	/*
	if (path->p_ops_cnt[RFS_DIR_IOP_LOOKUP])
		new.d_revalidate = rfs_d_revalidate;

	if (path->p_ops_cnt[RFS_DOP_REVALIDATE])
		new.d_revalidate = rfs_d_revalidate;
	else 
		new.d_revalidate = old->d_revalidate;

	if (path->p_ops_cnt[RFS_DOP_HASH])
		new.d_hash = rfs_d_hash;
	else 
		new.d_hash= old->d_hash;

	if (path->p_ops_cnt[RFS_DOP_COMPARE])
		new.d_compare = rfs_d_compare;
	else 
		new.d_compare= old->d_compare;

	if (path->p_ops_cnt[RFS_DOP_DELETE])
		new.d_delete = rfs_d_delete;
	else 
		new.d_delete= old->d_delete;
	*/

	spin_unlock(&path->p_lock);
}

int rdentry_cache_create(void)
{
	rdentry_cache = kmem_cache_create("rdentry_cache",
			sizeof(struct rdentry),
			0, SLAB_RECLAIM_ACCOUNT,
			NULL, NULL);
	if (!rdentry_cache)
		return -1;

	return 0;
}

void rdentry_cache_destroy(void)
{
	kmem_cache_destroy(rdentry_cache);
}

