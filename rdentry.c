#include "redir.h"

static kmem_cache_t *rdentry_cache = NULL;

void rfs_d_release(struct dentry *dentry);
void rfs_d_iput(struct dentry *dentry, struct inode *inode);

static struct rdentry *rdentry_alloc(struct dentry* dentry, struct path *path)
{
	struct rdentry *rdentry = NULL;


	rdentry = kmem_cache_alloc(rdentry_cache, SLAB_KERNEL);
	if (!rdentry)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&rdentry->rd_list);
	INIT_RCU_HEAD(&rdentry->rd_rcu);
	rdentry->rd_op_old = dentry->d_op;
	rdentry->rd_dentry = dentry;
	rdentry->rd_path = path_get(path);
	atomic_set(&rdentry->rd_count, 1);

	if (dentry->d_op)
		memcpy(&rdentry->rd_op_new, dentry->d_op, 
				sizeof(struct dentry_operations));
	else
		memset(&rdentry->rd_op_new, 0, 
				sizeof(struct dentry_operations));

	rdentry->rd_op_new.d_release = rfs_d_release;
	rdentry->rd_op_new.d_iput = rfs_d_iput;

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
	if (!rdentry)
		return;

	BUG_ON(!atomic_read(&rdentry->rd_count));
	if (!atomic_dec_and_test(&rdentry->rd_count))
		return;

	path_put(rdentry->rd_path);
	kmem_cache_free(rdentry_cache, rdentry);
}


inline struct rdentry *rdentry_find(struct dentry *dentry)
{
	struct rdentry *rdentry = NULL;
	struct dentry_operations *d_op;


	if (!dentry)
		return NULL;

	rcu_read_lock();
	d_op = rcu_dereference(dentry->d_op);
	if (d_op) {
		if(d_op->d_release == rfs_d_release) {
			rdentry = container_of(d_op, struct rdentry, rd_op_new);
			rdentry = rdentry_get(rdentry);
		}
	}
	rcu_read_unlock();

	return rdentry;
}

struct rdentry *rdentry_add(struct dentry *dentry, struct path *path)
{
	struct rdentry *rdentry;
	struct rdentry *rdentry_new;


	if (!dentry)
		return NULL;

	rdentry_new = rdentry_alloc(dentry, path);
	if (IS_ERR(rdentry_new))
		return rdentry_new;

	spin_lock(&dentry->d_lock);
	rdentry = rdentry_find(dentry);
	if (rdentry) {
		rdentry_put(rdentry_new);
		rdentry_put(rdentry);
		spin_unlock(&dentry->d_lock);
		return NULL;
	}

	rcu_assign_pointer(dentry->d_op, &rdentry_new->rd_op_new);
	spin_unlock(&dentry->d_lock);

	return rdentry_get(rdentry_new);
}

static inline void rdentry_del_rcu(struct rcu_head *head)
{
	struct rdentry *rdentry = NULL;

	
	rdentry = container_of(head, struct rdentry, rd_rcu);
	rdentry_put(rdentry);
}

void rdentry_del(struct dentry *dentry)
{
	struct rdentry *rdentry = NULL;


	spin_lock(&dentry->d_lock);
	rdentry = rdentry_find(dentry);
	if (!rdentry) {
		spin_unlock(&dentry->d_lock);
		return;
	}

	rcu_assign_pointer(dentry->d_op, rdentry->rd_op_old);
	spin_unlock(&dentry->d_lock);
	rdentry_put(rdentry);
	call_rcu(&rdentry->rd_rcu, rdentry_del_rcu);
}

int rfs_d_revalidate(struct dentry *dentry, struct nameidata *nd)
{
	struct rdentry *rdentry = rdentry_find(dentry);
	int rv = 1;


	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_revalidate)
			rv = dentry->d_op->d_revalidate(dentry, nd);
		return rv;
	}
	
	if (rdentry->rd_op_old && rdentry->rd_op_old->d_revalidate)
		rv = rdentry->rd_op_old->d_revalidate(dentry, nd);

	rdentry_put(rdentry);

	return rv;
}

int rfs_d_hash(struct dentry *dentry, struct qstr *name)
{
	struct rdentry *rdentry = rdentry_find(dentry);
	int rv = 0;


	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_hash)
			rv = dentry->d_op->d_hash(dentry, name);
		return rv;
	}

	if (rdentry->rd_op_old && rdentry->rd_op_old->d_hash)
		rv = rdentry->rd_op_old->d_hash(dentry, name);

	rdentry_put(rdentry);

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

	return rv;
}

int rfs_d_delete(struct dentry *dentry)
{
	struct rdentry *rdentry = rdentry_find(dentry);
	int rv = 0;


	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_delete)
			rv = dentry->d_op->d_delete(dentry);
		return rv;
	}

	if (rdentry->rd_op_old && rdentry->rd_op_old->d_delete)
		rv = rdentry->rd_op_old->d_delete(dentry);

	rdentry_put(rdentry);

	return rv;
}

void rfs_d_release(struct dentry *dentry)
{
	struct rdentry *rdentry = rdentry_find(dentry);

	
	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_release)
			dentry->d_op->d_release(dentry);
		return;
	}

	if (rdentry->rd_op_old && rdentry->rd_op_old->d_release)
		rdentry->rd_op_old->d_release(dentry);


	path_del_rdentry(rdentry->rd_path, rdentry);
	rdentry_del(dentry);
	rdentry_put(rdentry);
}

void rfs_d_iput(struct dentry *dentry, struct inode *inode)
{
	struct rdentry *rdentry = rdentry_find(dentry);
	struct rinode *rinode = rinode_find(inode);


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
	path_del_rinode(rdentry->rd_path, rinode);
	rinode_put(rinode);
	rdentry_put(rdentry);
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

