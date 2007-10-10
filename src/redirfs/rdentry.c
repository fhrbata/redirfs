#include "redir.h"

static struct kmem_cache *rdentry_cache = NULL;
unsigned long long rdentry_cnt = 0;
spinlock_t rdentry_cnt_lock = SPIN_LOCK_UNLOCKED;
extern struct file_operations rfs_file_ops;
extern atomic_t rdentries_freed;
extern wait_queue_head_t rdentries_wait;

struct rdentry *rdentry_alloc(struct dentry* dentry)
{
	struct rdentry *rdentry = NULL;
	unsigned long flags;


	rdentry = kmem_cache_alloc(rdentry_cache, GFP_KERNEL);
	if (!rdentry)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&rdentry->rd_rfiles);
	INIT_LIST_HEAD(&rdentry->rd_data);
	INIT_LIST_HEAD(&rdentry->rd_rinode_list);
	INIT_RCU_HEAD(&rdentry->rd_rcu);
	rdentry->rd_op_old = dentry->d_op;
	rdentry->rd_dentry = dentry;
	rdentry->rd_path = NULL;
	rdentry->rd_rinode = NULL;
	rdentry->rd_chain = NULL;
	rdentry->rd_ops = NULL;
	rdentry->rd_root = 0;
	atomic_set(&rdentry->rd_count, 1);
	spin_lock_init(&rdentry->rd_lock);

	if (dentry->d_op)
		memcpy(&rdentry->rd_op_new, dentry->d_op, 
				sizeof(struct dentry_operations));
	else
		memset(&rdentry->rd_op_new, 0, 
				sizeof(struct dentry_operations));

	rdentry->rd_op_new.d_iput = rfs_d_iput;

	spin_lock_irqsave(&rdentry_cnt_lock, flags);
	rdentry_cnt++;
	spin_unlock_irqrestore(&rdentry_cnt_lock, flags);

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
	unsigned long flags;
	struct rfs_priv_data *data;
	struct rfs_priv_data *tmp;

	if (!rdentry || IS_ERR(rdentry))
		return;

	BUG_ON(!atomic_read(&rdentry->rd_count));
	if (!atomic_dec_and_test(&rdentry->rd_count))
		return;

	BUG_ON(!list_empty(&rdentry->rd_rfiles));

	path_put(rdentry->rd_path);
	chain_put(rdentry->rd_chain);
	rinode_put(rdentry->rd_rinode);
	ops_put(rdentry->rd_ops);

	list_for_each_entry_safe(data, tmp, &rdentry->rd_data, list) {
		spin_lock_irqsave(&rdentry->rd_lock, flags);
		list_del(&data->list);
		spin_unlock_irqrestore(&rdentry->rd_lock, flags);
		rfs_put_data(data);
	}

	kmem_cache_free(rdentry_cache, rdentry);

	spin_lock_irqsave(&rdentry_cnt_lock, flags);
	if (!--rdentry_cnt)
		atomic_set(&rdentries_freed, 1);
	spin_unlock_irqrestore(&rdentry_cnt_lock, flags);

	if (atomic_read(&rdentries_freed))
		wake_up_interruptible(&rdentries_wait);
}


inline struct rdentry *rdentry_find(struct dentry *dentry)
{
	struct rdentry *rdentry = NULL;
	struct dentry_operations *d_op;


	rcu_read_lock();
	d_op = rcu_dereference(dentry->d_op);
	if (d_op) {
		if (d_op->d_iput == rfs_d_iput) {
			rdentry = container_of(d_op, struct rdentry, rd_op_new);
			rdentry = rdentry_get(rdentry);
		}
	}
	rcu_read_unlock();

	return rdentry;
}

struct rdentry *rdentry_add(struct dentry *dentry)
{
	struct rdentry *rdentry = NULL;
	struct rdentry *rdentry_new = NULL;
	struct rinode *rinode = NULL;
	struct rinode *rinode_new = NULL;
	struct inode *inode = dentry->d_inode;


	rdentry_new = rdentry_alloc(dentry);
	if (IS_ERR(rdentry_new))
			return rdentry_new;

	if (inode) {
		rinode_new = rinode_alloc(inode);
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
	}

	if (!inode || rdentry->rd_rinode) {
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
		if (!S_ISSOCK(inode->i_mode))
			inode->i_fop = &rfs_file_ops;

		if (S_ISREG(inode->i_mode))
			inode->i_mapping->a_ops = &rinode_new->ri_aop_new;

		rcu_assign_pointer(inode->i_op, &rinode_new->ri_op_new);
		rinode = rinode_get(rinode_new);
	}

	rdentry->rd_rinode = rinode;
	list_add_tail(&rdentry->rd_rinode_list, &rinode->ri_rdentries);
	rdentry_get(rdentry);

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

void rdentry_del(struct dentry *dentry)
{
	struct rdentry *rdentry = NULL;
	struct rinode *rinode = NULL;


	spin_lock(&dentry->d_lock);

	rdentry = rdentry_find(dentry);
	if (!rdentry) {
		spin_unlock(&dentry->d_lock);
		return;
	}

	rcu_assign_pointer(dentry->d_op, rdentry->rd_op_old);

	rinode = rdentry->rd_rinode;

	if (rinode) {
		rinode_del(rinode->ri_inode);
		spin_lock(&rinode->ri_lock);
		list_del_init(&rdentry->rd_rinode_list);
		spin_unlock(&rinode->ri_lock);
		rdentry_put(rdentry);
	}

	spin_unlock(&dentry->d_lock);

	call_rcu(&rdentry->rd_rcu, rdentry_del_rcu);

	rdentry_put(rdentry);
}

int rfs_d_revalidate(struct dentry *dentry, struct nameidata *nd)
{
	struct rdentry *rdentry = NULL;
	struct chain *chain = NULL;
	struct inode *inode = NULL;
	struct rfs_args args;
	struct context cont;
	int rv = 1;

	rdentry = rdentry_find(dentry);

	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_revalidate)
			rv = dentry->d_op->d_revalidate(dentry, nd);

		return rv;
	}

	spin_lock(&rdentry->rd_lock);
	chain = chain_get(rdentry->rd_chain);
	spin_unlock(&rdentry->rd_lock);

	args.args.d_revalidate.dentry = dentry;
	args.args.d_revalidate.nd = nd;

	INIT_LIST_HEAD(&cont.data_list);

	inode = dentry->d_inode;
	if (inode) {
		if (S_ISREG(inode->i_mode))
			args.type.id = RFS_REG_DOP_D_REVALIDATE;
		else if (S_ISDIR(inode->i_mode))
			args.type.id = RFS_DIR_DOP_D_REVALIDATE;
		else if (S_ISLNK(inode->i_mode))
			args.type.id = RFS_LNK_DOP_D_REVALIDATE;
		else if (S_ISCHR(inode->i_mode))
			args.type.id = RFS_CHR_DOP_D_REVALIDATE;
		else if (S_ISBLK(inode->i_mode))
			args.type.id = RFS_BLK_DOP_D_REVALIDATE;
		else if (S_ISFIFO(inode->i_mode))
			args.type.id = RFS_FIFO_DOP_D_REVALIDATE;
		else
			args.type.id = RFS_SOCK_DOP_D_REVALIDATE;
	} else
		args.type.id = RFS_NONE_DOP_D_REVALIDATE;

	if (!rfs_precall_flts(0, chain, &cont, &args)) {
		if (rdentry->rd_op_old && rdentry->rd_op_old->d_revalidate)
			rv = rdentry->rd_op_old->d_revalidate(args.args.d_revalidate.dentry, args.args.d_revalidate.nd);

		args.retv.rv_int = rv;
	}
		
	rfs_postcall_flts(0, chain, &cont, &args);

	rv = args.retv.rv_int;

	rdentry_put(rdentry);
	chain_put(chain);

	BUG_ON(!list_empty(&cont.data_list));

	return rv;
}

int rfs_d_hash(struct dentry *dentry, struct qstr *name)
{
	struct rdentry *rdentry;
	struct chain *chain = NULL;
	struct inode *inode = NULL;
	struct rfs_args args;
	struct context cont;
	int rv = 0;

	rdentry = rdentry_find(dentry);

	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_hash)
			rv = dentry->d_op->d_hash(dentry, name);

		return rv;
	}

	spin_lock(&rdentry->rd_lock);
	chain = chain_get(rdentry->rd_chain);
	spin_unlock(&rdentry->rd_lock);

	args.args.d_hash.dentry = dentry;
	args.args.d_hash.name = name;

	INIT_LIST_HEAD(&cont.data_list);

	inode = dentry->d_inode;
	if (inode) {
		if (S_ISREG(inode->i_mode))
			args.type.id = RFS_REG_DOP_D_HASH;
		else if (S_ISDIR(inode->i_mode))
			args.type.id = RFS_DIR_DOP_D_HASH;
		else if (S_ISLNK(inode->i_mode))
			args.type.id = RFS_LNK_DOP_D_HASH;
		else if (S_ISCHR(inode->i_mode))
			args.type.id = RFS_CHR_DOP_D_HASH;
		else if (S_ISBLK(inode->i_mode))
			args.type.id = RFS_BLK_DOP_D_HASH;
		else if (S_ISFIFO(inode->i_mode))
			args.type.id = RFS_FIFO_DOP_D_HASH;
		else
			args.type.id = RFS_SOCK_DOP_D_HASH;
	} else
		args.type.id = RFS_NONE_DOP_D_HASH;

	if (!rfs_precall_flts(0, chain, &cont, &args)) {
		if (rdentry->rd_op_old && rdentry->rd_op_old->d_hash)
			rv = rdentry->rd_op_old->d_hash(args.args.d_hash.dentry, args.args.d_hash.name);

		args.retv.rv_int = rv;
	}

	rfs_postcall_flts(0, chain, &cont, &args);

	rv = args.retv.rv_int;

	rdentry_put(rdentry);
	chain_put(chain);

	BUG_ON(!list_empty(&cont.data_list));

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
	struct rdentry *rdentry = NULL;
	struct chain *chain = NULL;
	struct inode *inode = NULL;
	struct rfs_args args;
	struct context cont;
	int rv = 0;

	rdentry = rdentry_find(dentry);
	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_compare)
			return dentry->d_op->d_compare(dentry, name1, name2);
		else
			return rfs_d_compare_default(name1, name2);
	}
	spin_lock(&rdentry->rd_lock);
	chain = chain_get(rdentry->rd_chain);
	spin_unlock(&rdentry->rd_lock);

	args.args.d_compare.dentry = dentry;
	args.args.d_compare.name1 = name1;
	args.args.d_compare.name2 = name2;

	INIT_LIST_HEAD(&cont.data_list);

	inode = dentry->d_inode;
	if (inode) {
		if (S_ISREG(inode->i_mode))
			args.type.id = RFS_REG_DOP_D_COMPARE;
		else if (S_ISDIR(inode->i_mode))
			args.type.id = RFS_DIR_DOP_D_COMPARE;
		else if (S_ISLNK(inode->i_mode))
			args.type.id = RFS_LNK_DOP_D_COMPARE;
		else if (S_ISCHR(inode->i_mode))
			args.type.id = RFS_CHR_DOP_D_COMPARE;
		else if (S_ISBLK(inode->i_mode))
			args.type.id = RFS_BLK_DOP_D_COMPARE;
		else if (S_ISFIFO(inode->i_mode))
			args.type.id = RFS_FIFO_DOP_D_COMPARE;
		else
			args.type.id = RFS_SOCK_DOP_D_COMPARE;
	} else
		args.type.id = RFS_NONE_DOP_D_COMPARE;

	if (!rfs_precall_flts(0, chain, &cont, &args)) {

		if (rdentry->rd_op_old && rdentry->rd_op_old->d_compare)
			rv = rdentry->rd_op_old->d_compare(args.args.d_compare.dentry, args.args.d_compare.name1, args.args.d_compare.name2);
		else
			rv = rfs_d_compare_default(args.args.d_compare.name1, args.args.d_compare.name2);

		args.retv.rv_int = rv;
	}

	rfs_postcall_flts(0, chain, &cont, &args);
	rv = args.retv.rv_int;

	rdentry_put(rdentry);
	chain_put(chain);

	BUG_ON(!list_empty(&cont.data_list));

	return rv;
}

int rfs_d_delete(struct dentry *dentry)
{
	struct rdentry *rdentry = NULL;
	struct chain *chain = NULL;
	struct inode *inode = NULL;
	struct rfs_args args;
	struct context cont;
	int rv = 0;

	rdentry = rdentry_find(dentry);
	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_delete)
			rv = dentry->d_op->d_delete(dentry);

		return rv;
	}

	spin_lock(&rdentry->rd_lock);
	chain = chain_get(rdentry->rd_chain);
	spin_unlock(&rdentry->rd_lock);

	args.args.d_delete.dentry = dentry;

	INIT_LIST_HEAD(&cont.data_list);

	inode = dentry->d_inode;
	if (inode) {
		if (S_ISREG(inode->i_mode))
			args.type.id = RFS_REG_DOP_D_DELETE;
		else if (S_ISDIR(inode->i_mode))
			args.type.id = RFS_DIR_DOP_D_DELETE;
		else if (S_ISLNK(inode->i_mode))
			args.type.id = RFS_LNK_DOP_D_DELETE;
		else if (S_ISCHR(inode->i_mode))
			args.type.id = RFS_CHR_DOP_D_DELETE;
		else if (S_ISBLK(inode->i_mode))
			args.type.id = RFS_BLK_DOP_D_DELETE;
		else if (S_ISFIFO(inode->i_mode))
			args.type.id = RFS_FIFO_DOP_D_DELETE;
		else
			args.type.id = RFS_SOCK_DOP_D_DELETE;
	} else
		args.type.id = RFS_NONE_DOP_D_DELETE;

	if (!rfs_precall_flts(0, chain, &cont, &args)) {

		if (rdentry->rd_op_old && rdentry->rd_op_old->d_delete)
			rv = rdentry->rd_op_old->d_delete(args.args.d_delete.dentry);

		args.retv.rv_int = rv;
	}

	rfs_postcall_flts(0, chain, &cont, &args);
	rv = args.retv.rv_int;

	rdentry_put(rdentry);
	chain_put(chain);

	BUG_ON(!list_empty(&cont.data_list));

	return rv;
}

void rfs_d_release(struct dentry *dentry)
{
	struct rdentry *rdentry = NULL;
	struct chain *chain = NULL;
	struct inode *inode = NULL;
	struct rfs_args args;
	struct context cont;

	rdentry = rdentry_find(dentry);
	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_release)
			dentry->d_op->d_release(dentry);
		return;
	}

	spin_lock(&rdentry->rd_lock);
	chain = chain_get(rdentry->rd_chain);
	spin_unlock(&rdentry->rd_lock);

	args.args.d_release.dentry = dentry;

	INIT_LIST_HEAD(&cont.data_list);

	inode = dentry->d_inode;
	if (inode) {
		if (S_ISREG(inode->i_mode))
			args.type.id = RFS_REG_DOP_D_RELEASE;
		else if (S_ISDIR(inode->i_mode))
			args.type.id = RFS_DIR_DOP_D_RELEASE;
		else if (S_ISLNK(inode->i_mode))
			args.type.id = RFS_LNK_DOP_D_RELEASE;
		else if (S_ISCHR(inode->i_mode))
			args.type.id = RFS_CHR_DOP_D_RELEASE;
		else if (S_ISBLK(inode->i_mode))
			args.type.id = RFS_BLK_DOP_D_RELEASE;
		else if (S_ISFIFO(inode->i_mode))
			args.type.id = RFS_FIFO_DOP_D_RELEASE;
		else
			args.type.id = RFS_SOCK_DOP_D_RELEASE;
	} else
		args.type.id = RFS_NONE_DOP_D_RELEASE;

	if (!rfs_precall_flts(0, chain, &cont, &args)) {

		if (rdentry->rd_op_old && rdentry->rd_op_old->d_release)
			rdentry->rd_op_old->d_release(args.args.d_release.dentry);
	} 

	rfs_postcall_flts(0, chain, &cont, &args);

	rdentry_del(dentry);
	rdentry_put(rdentry);
	chain_put(chain);

	BUG_ON(!list_empty(&cont.data_list));
}

void rfs_d_iput(struct dentry *dentry, struct inode *inode)
{
	struct rdentry *rdentry = NULL;
	struct rinode *rinode = NULL;
	struct chain *chain = NULL;
	struct rfs_args args;
	struct context cont;

	rdentry = rdentry_find(dentry);
	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_iput)
			dentry->d_op->d_iput(dentry, inode);
		else
			iput(inode);
		return;
	}

	spin_lock(&rdentry->rd_lock);
	chain = chain_get(rdentry->rd_chain);
	spin_unlock(&rdentry->rd_lock);

	args.args.d_iput.dentry = dentry;
	args.args.d_iput.inode = inode;

	INIT_LIST_HEAD(&cont.data_list);

	if (inode) {
		if (S_ISREG(inode->i_mode))
			args.type.id = RFS_REG_DOP_D_IPUT;
		else if (S_ISDIR(inode->i_mode))
			args.type.id = RFS_DIR_DOP_D_IPUT;
		else if (S_ISLNK(inode->i_mode))
			args.type.id = RFS_LNK_DOP_D_IPUT;
		else if (S_ISCHR(inode->i_mode))
			args.type.id = RFS_CHR_DOP_D_IPUT;
		else if (S_ISBLK(inode->i_mode))
			args.type.id = RFS_BLK_DOP_D_IPUT;
		else if (S_ISFIFO(inode->i_mode))
			args.type.id = RFS_FIFO_DOP_D_IPUT;
		else
			args.type.id = RFS_SOCK_DOP_D_IPUT;
	} else
		args.type.id = RFS_NONE_DOP_D_IPUT;

	if (!rfs_precall_flts(0, chain, &cont, &args)) {

		if (rdentry->rd_op_old && rdentry->rd_op_old->d_iput)
			rdentry->rd_op_old->d_iput(args.args.d_iput.dentry, args.args.d_iput.inode);
		else
			iput(args.args.d_iput.inode);
	}

	rfs_postcall_flts(0, chain, &cont, &args);

	rinode = rinode_find(inode);

	spin_lock(&rinode->ri_lock);
	list_del_init(&rdentry->rd_rinode_list);
	spin_unlock(&rinode->ri_lock);
	rdentry_put(rdentry);
	rinode_del(rinode->ri_inode);

	rdentry->rd_rinode = NULL;
	rinode_put(rinode);
	rdentry_set_ops(rdentry, rdentry->rd_ops);

	rdentry_put(rdentry);
	rinode_put(rinode);
	chain_put(chain);

	BUG_ON(!list_empty(&cont.data_list));
}

static void rdentry_set_none_ops(struct rdentry *rdentry, char *ops)
{
	if (ops[RFS_NONE_DOP_D_REVALIDATE])
		rdentry->rd_op_new.d_revalidate = rfs_d_revalidate;
	else
		rdentry->rd_op_new.d_revalidate = rdentry->rd_op_old ? rdentry->rd_op_old->d_revalidate : NULL;

	if (ops[RFS_NONE_DOP_D_HASH])
		rdentry->rd_op_new.d_hash = rfs_d_hash;
	else
		rdentry->rd_op_new.d_hash = rdentry->rd_op_old ? rdentry->rd_op_old->d_hash : NULL;

	if (ops[RFS_NONE_DOP_D_COMPARE])
		rdentry->rd_op_new.d_compare = rfs_d_compare;
	else
		rdentry->rd_op_new.d_compare = rdentry->rd_op_old ? rdentry->rd_op_old->d_compare : NULL;

	if (ops[RFS_NONE_DOP_D_DELETE])
		rdentry->rd_op_new.d_delete = rfs_d_delete;
	else
		rdentry->rd_op_new.d_delete = rdentry->rd_op_old ? rdentry->rd_op_old->d_delete : NULL;
}

static void rdentry_set_reg_ops(struct rdentry *rdentry, char *ops)
{
	if (ops[RFS_REG_DOP_D_REVALIDATE])
		rdentry->rd_op_new.d_revalidate = rfs_d_revalidate;
	else
		rdentry->rd_op_new.d_revalidate = rdentry->rd_op_old ? rdentry->rd_op_old->d_revalidate : NULL;

	if (ops[RFS_REG_DOP_D_HASH])
		rdentry->rd_op_new.d_hash = rfs_d_hash;
	else
		rdentry->rd_op_new.d_hash = rdentry->rd_op_old ? rdentry->rd_op_old->d_hash : NULL;

	if (ops[RFS_REG_DOP_D_COMPARE])
		rdentry->rd_op_new.d_compare = rfs_d_compare;
	else
		rdentry->rd_op_new.d_compare = rdentry->rd_op_old ? rdentry->rd_op_old->d_compare : NULL;

	if (ops[RFS_REG_DOP_D_DELETE])
		rdentry->rd_op_new.d_delete = rfs_d_delete;
	else
		rdentry->rd_op_new.d_delete = rdentry->rd_op_old ? rdentry->rd_op_old->d_delete : NULL;
}

static void rdentry_set_dir_ops(struct rdentry *rdentry, char *ops)
{
	if (ops[RFS_DIR_DOP_D_REVALIDATE])
		rdentry->rd_op_new.d_revalidate = rfs_d_revalidate;
	else
		rdentry->rd_op_new.d_revalidate = rdentry->rd_op_old ? rdentry->rd_op_old->d_revalidate : NULL;

	if (ops[RFS_DIR_DOP_D_HASH])
		rdentry->rd_op_new.d_hash = rfs_d_hash;
	else
		rdentry->rd_op_new.d_hash = rdentry->rd_op_old ? rdentry->rd_op_old->d_hash : NULL;

	if (ops[RFS_DIR_DOP_D_COMPARE])
		rdentry->rd_op_new.d_compare = rfs_d_compare;
	else
		rdentry->rd_op_new.d_compare = rdentry->rd_op_old ? rdentry->rd_op_old->d_compare : NULL;

	if (ops[RFS_DIR_DOP_D_DELETE])
		rdentry->rd_op_new.d_delete = rfs_d_delete;
	else
		rdentry->rd_op_new.d_delete = rdentry->rd_op_old ? rdentry->rd_op_old->d_delete : NULL;
}

static void rdentry_set_lnk_ops(struct rdentry *rdentry, char *ops)
{
	if (ops[RFS_LNK_DOP_D_REVALIDATE])
		rdentry->rd_op_new.d_revalidate = rfs_d_revalidate;
	else
		rdentry->rd_op_new.d_revalidate = rdentry->rd_op_old ? rdentry->rd_op_old->d_revalidate : NULL;

	if (ops[RFS_LNK_DOP_D_HASH])
		rdentry->rd_op_new.d_hash = rfs_d_hash;
	else
		rdentry->rd_op_new.d_hash = rdentry->rd_op_old ? rdentry->rd_op_old->d_hash : NULL;

	if (ops[RFS_LNK_DOP_D_COMPARE])
		rdentry->rd_op_new.d_compare = rfs_d_compare;
	else
		rdentry->rd_op_new.d_compare = rdentry->rd_op_old ? rdentry->rd_op_old->d_compare : NULL;

	if (ops[RFS_LNK_DOP_D_DELETE])
		rdentry->rd_op_new.d_delete = rfs_d_delete;
	else
		rdentry->rd_op_new.d_delete = rdentry->rd_op_old ? rdentry->rd_op_old->d_delete : NULL;
}

static void rdentry_set_chr_ops(struct rdentry *rdentry, char *ops)
{
	if (ops[RFS_CHR_DOP_D_REVALIDATE])
		rdentry->rd_op_new.d_revalidate = rfs_d_revalidate;
	else
		rdentry->rd_op_new.d_revalidate = rdentry->rd_op_old ? rdentry->rd_op_old->d_revalidate : NULL;

	if (ops[RFS_CHR_DOP_D_HASH])
		rdentry->rd_op_new.d_hash = rfs_d_hash;
	else
		rdentry->rd_op_new.d_hash = rdentry->rd_op_old ? rdentry->rd_op_old->d_hash : NULL;

	if (ops[RFS_CHR_DOP_D_COMPARE])
		rdentry->rd_op_new.d_compare = rfs_d_compare;
	else
		rdentry->rd_op_new.d_compare = rdentry->rd_op_old ? rdentry->rd_op_old->d_compare : NULL;

	if (ops[RFS_CHR_DOP_D_DELETE])
		rdentry->rd_op_new.d_delete = rfs_d_delete;
	else
		rdentry->rd_op_new.d_delete = rdentry->rd_op_old ? rdentry->rd_op_old->d_delete : NULL;
}

static void rdentry_set_blk_ops(struct rdentry *rdentry, char *ops)
{
	if (ops[RFS_BLK_DOP_D_REVALIDATE])
		rdentry->rd_op_new.d_revalidate = rfs_d_revalidate;
	else
		rdentry->rd_op_new.d_revalidate = rdentry->rd_op_old ? rdentry->rd_op_old->d_revalidate : NULL;

	if (ops[RFS_BLK_DOP_D_HASH])
		rdentry->rd_op_new.d_hash = rfs_d_hash;
	else
		rdentry->rd_op_new.d_hash = rdentry->rd_op_old ? rdentry->rd_op_old->d_hash : NULL;

	if (ops[RFS_BLK_DOP_D_COMPARE])
		rdentry->rd_op_new.d_compare = rfs_d_compare;
	else
		rdentry->rd_op_new.d_compare = rdentry->rd_op_old ? rdentry->rd_op_old->d_compare : NULL;

	if (ops[RFS_BLK_DOP_D_DELETE])
		rdentry->rd_op_new.d_delete = rfs_d_delete;
	else
		rdentry->rd_op_new.d_delete = rdentry->rd_op_old ? rdentry->rd_op_old->d_delete : NULL;
}

static void rdentry_set_fifo_ops(struct rdentry *rdentry, char *ops)
{
	if (ops[RFS_FIFO_DOP_D_RELEASE])
		rdentry->rd_op_new.d_release = rfs_d_release;
	else
		rdentry->rd_op_new.d_release = rdentry->rd_op_old ? rdentry->rd_op_old->d_release : NULL;

	if (ops[RFS_FIFO_DOP_D_REVALIDATE])
		rdentry->rd_op_new.d_revalidate = rfs_d_revalidate;
	else
		rdentry->rd_op_new.d_revalidate = rdentry->rd_op_old ? rdentry->rd_op_old->d_revalidate : NULL;

	if (ops[RFS_FIFO_DOP_D_HASH])
		rdentry->rd_op_new.d_hash = rfs_d_hash;
	else
		rdentry->rd_op_new.d_hash = rdentry->rd_op_old ? rdentry->rd_op_old->d_hash : NULL;

	if (ops[RFS_FIFO_DOP_D_COMPARE])
		rdentry->rd_op_new.d_compare = rfs_d_compare;
	else
		rdentry->rd_op_new.d_compare = rdentry->rd_op_old ? rdentry->rd_op_old->d_compare : NULL;

	if (ops[RFS_FIFO_DOP_D_DELETE])
		rdentry->rd_op_new.d_delete = rfs_d_delete;
	else
		rdentry->rd_op_new.d_delete = rdentry->rd_op_old ? rdentry->rd_op_old->d_delete : NULL;
}

static void rdentry_set_sock_ops(struct rdentry *rdentry, char *ops)
{
	if (ops[RFS_SOCK_DOP_D_REVALIDATE])
		rdentry->rd_op_new.d_revalidate = rfs_d_revalidate;
	else
		rdentry->rd_op_new.d_revalidate = rdentry->rd_op_old ? rdentry->rd_op_old->d_revalidate : NULL;

	if (ops[RFS_SOCK_DOP_D_HASH])
		rdentry->rd_op_new.d_hash = rfs_d_hash;
	else
		rdentry->rd_op_new.d_hash = rdentry->rd_op_old ? rdentry->rd_op_old->d_hash : NULL;

	if (ops[RFS_SOCK_DOP_D_COMPARE])
		rdentry->rd_op_new.d_compare = rfs_d_compare;
	else
		rdentry->rd_op_new.d_compare = rdentry->rd_op_old ? rdentry->rd_op_old->d_compare : NULL;

	if (ops[RFS_SOCK_DOP_D_DELETE])
		rdentry->rd_op_new.d_delete = rfs_d_delete;
	else
		rdentry->rd_op_new.d_delete = rdentry->rd_op_old ? rdentry->rd_op_old->d_delete : NULL;
}

void rdentry_set_ops(struct rdentry *rdentry, struct ops *ops)
{
	umode_t mode;

	if (!rdentry->rd_rinode || !rdentry->rd_rinode->ri_inode) {
		rdentry_set_none_ops(rdentry, ops->o_ops);
		rdentry->rd_op_new.d_iput = rfs_d_iput;
		rdentry->rd_op_new.d_release = rfs_d_release;
		return;
	}

	mode = rdentry->rd_rinode->ri_inode->i_mode;

	if (S_ISREG(mode))
		rdentry_set_reg_ops(rdentry, ops->o_ops);

	else if (S_ISDIR(mode))
		rdentry_set_dir_ops(rdentry, ops->o_ops);

	else if (S_ISLNK(mode))
		rdentry_set_lnk_ops(rdentry, ops->o_ops);

	else if (S_ISCHR(mode))
		rdentry_set_chr_ops(rdentry, ops->o_ops);

	else if (S_ISBLK(mode))
		rdentry_set_blk_ops(rdentry, ops->o_ops);

	else if (S_ISFIFO(mode))
		rdentry_set_fifo_ops(rdentry, ops->o_ops);

	else if (S_ISSOCK(mode))
		rdentry_set_sock_ops(rdentry, ops->o_ops);

	rdentry->rd_op_new.d_iput = rfs_d_iput;
	rdentry->rd_op_new.d_release = rfs_d_release;
}

int rdentry_cache_create(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	rdentry_cache = kmem_cache_create("rdentry_cache", sizeof(struct rdentry), 0, SLAB_RECLAIM_ACCOUNT, NULL, NULL);
#else
	rdentry_cache = kmem_cache_create("rdentry_cache", sizeof(struct rdentry), 0, SLAB_RECLAIM_ACCOUNT, NULL);
#endif
	if (!rdentry_cache)
		return -ENOMEM;

	return 0;
}

void rdentry_cache_destroy(void)
{
	kmem_cache_destroy(rdentry_cache);
}

int rfs_attach_data_dentry(rfs_filter filter, struct dentry *dentry,
		struct rfs_priv_data *data, struct rfs_priv_data **exist)
{
	struct filter *flt;
	struct rdentry *rdentry;
	struct rfs_priv_data *found;

	flt = (struct filter *)filter;

	if (!flt || !dentry || !data || !exist)
		return -EINVAL;

	rdentry = rdentry_find(dentry);
	if (!rdentry)
		return -ENODATA;

	spin_lock(&rdentry->rd_lock);

	if (chain_find_flt(rdentry->rd_chain, flt) == -1) {
		spin_unlock(&rdentry->rd_lock);
		rdentry_put(rdentry);
		return -ENOENT;
	}

	found = rfs_find_data(&rdentry->rd_data, flt);
	if (found) {
		*exist = rfs_get_data(found);
		spin_unlock(&rdentry->rd_lock);
		rdentry_put(rdentry);
		return -EEXIST;
	}

	rfs_get_data(data);
	list_add_tail(&data->list, &rdentry->rd_data);
	*exist = NULL;
	spin_unlock(&rdentry->rd_lock);

	rdentry_put(rdentry);

	return 0;
}

int rfs_detach_data_dentry(rfs_filter filter, struct dentry *dentry,
		struct rfs_priv_data **data)
{
	struct filter *flt;
	struct rdentry *rdentry;
	struct rfs_priv_data *found;

	flt = (struct filter *)filter;
	
	if (!flt || !dentry || !data)
		return -EINVAL;

	rdentry = rdentry_find(dentry);
	if (!rdentry)
		return -ENODATA;

	spin_lock(&rdentry->rd_lock);
	found = rfs_find_data(&rdentry->rd_data, flt);
	if (!found) {
		spin_unlock(&rdentry->rd_lock);
		rdentry_put(rdentry);
		return -ENODATA;
	}

	list_del(&found->list);
	*data = found;

	spin_unlock(&rdentry->rd_lock);

	rdentry_put(rdentry);

	return 0;
}

int rfs_get_data_dentry(rfs_filter filter, struct dentry *dentry,
		struct rfs_priv_data **data)
{
	struct filter *flt;
	struct rdentry *rdentry;
	struct rfs_priv_data *found;

	flt = (struct filter *)filter;
	
	if (!flt || !dentry || !data)
		return -EINVAL;

	rdentry = rdentry_find(dentry);
	if (!rdentry)
		return -ENODATA;

	spin_lock(&rdentry->rd_lock);
	found = rfs_find_data(&rdentry->rd_data, flt);
	if (!found) {
		spin_unlock(&rdentry->rd_lock);
		rdentry_put(rdentry);
		return -ENODATA;
	}

	*data = rfs_get_data(found);

	spin_unlock(&rdentry->rd_lock);

	rdentry_put(rdentry);

	return 0;
}

EXPORT_SYMBOL(rfs_attach_data_dentry);
EXPORT_SYMBOL(rfs_detach_data_dentry);
EXPORT_SYMBOL(rfs_get_data_dentry);
