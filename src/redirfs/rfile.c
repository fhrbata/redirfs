#include "redir.h"

static kmem_cache_t *rfile_cache = NULL;
unsigned long long rfile_cnt = 0;
spinlock_t rfile_cnt_lock = SPIN_LOCK_UNLOCKED;
extern atomic_t rfiles_freed;
extern wait_queue_head_t rfiles_wait;

struct file_operations rfs_file_ops = {
	.owner = THIS_MODULE,
	.open = rfs_open
};

static struct rfile *rfile_alloc(struct file *file)
{
	struct rfile *rfile;
	struct rinode *rinode = NULL;
	const struct file_operations *op_old;
	unsigned long flags;

	
	rfile = kmem_cache_alloc(rfile_cache, GFP_KERNEL);
	if (!rfile)
		return ERR_PTR(RFS_ERR_NOMEM);
	
	INIT_LIST_HEAD(&rfile->rf_rdentry_list);
	INIT_RCU_HEAD(&rfile->rf_rcu);
	rfile->rf_path = NULL;
	rfile->rf_chain = NULL;
	rfile->rf_file = file;
	rfile->rf_rdentry = NULL;
	atomic_set(&rfile->rf_count, 1);
	spin_lock_init(&rfile->rf_lock);
	

	if (file->f_op->open == rfs_open) {
		rinode = rinode_find(file->f_dentry->d_inode);
		if (!rinode)
			op_old = file->f_dentry->d_inode->i_fop;
		else
			op_old = rinode->ri_fop_old;

	} else 
		op_old = (struct file_operations *)file->f_op;

	if (op_old)
		memcpy(&rfile->rf_op_new, op_old, 
				sizeof(struct file_operations));
	else
		memset(&rfile->rf_op_new, 0, 
				sizeof(struct file_operations));

	rfile->rf_op_old = (struct file_operations *)op_old;

	rinode_put(rinode);

	spin_lock_irqsave(&rfile_cnt_lock, flags);
	rfile_cnt++;
	spin_unlock_irqrestore(&rfile_cnt_lock, flags);

	return rfile;
}

inline struct rfile *rfile_get(struct rfile* rfile)
{
	BUG_ON(!atomic_read(&rfile->rf_count));
	atomic_inc(&rfile->rf_count);
	return rfile;
}

inline void rfile_put(struct rfile *rfile)
{
	unsigned long flags;

	if (!rfile || IS_ERR(rfile))
		return;

	BUG_ON(!atomic_read(&rfile->rf_count));
	if (!atomic_dec_and_test(&rfile->rf_count))
		return;

	path_put(rfile->rf_path);
	chain_put(rfile->rf_chain);
	rdentry_put(rfile->rf_rdentry);
	kmem_cache_free(rfile_cache, rfile);

	spin_lock_irqsave(&rfile_cnt_lock, flags);
	if (!--rfile_cnt)
		atomic_set(&rfiles_freed, 1);
	spin_unlock_irqrestore(&rfile_cnt_lock, flags);

	if (atomic_read(&rfiles_freed))
		wake_up_interruptible(&rfiles_wait);
}

inline struct rfile* rfile_find(struct file *file)
{
	struct rfile *rfile = NULL;
	const struct file_operations *f_op;


	rcu_read_lock();
	f_op = rcu_dereference(file->f_op);
	if (f_op) {
		if (f_op->open == rfs_open) {
			rfile = container_of(f_op, struct rfile, rf_op_new);
			rfile = rfile_get(rfile);
		}
	}
	rcu_read_unlock();

	return rfile;
}

struct rfile *rfile_add(struct file *file)
{
	struct rfile *rfile_new;
	struct rdentry *rdentry;
	struct rdentry *rdentry_tmp;


	rfile_new = rfile_alloc(file);
	if (IS_ERR(rfile_new))
		return rfile_new;

	rdentry = rdentry_find(file->f_dentry);

	if (!rdentry) {
		rcu_assign_pointer(file->f_op, rfile_new->rf_op_old);
		rfile_put(rfile_new);
		return NULL;
	}

	spin_lock(&rdentry->rd_lock);

	rdentry_tmp = rdentry_find(file->f_dentry);

	if (rdentry_tmp) {

		rfile_new->rf_rdentry = rdentry_get(rdentry);
		rfile_new->rf_chain = chain_get(rdentry->rd_chain);
		rfile_new->rf_path = path_get(rdentry->rd_path);

		rcu_assign_pointer(file->f_op, &rfile_new->rf_op_new);

		list_add_tail(&rfile_new->rf_rdentry_list, &rdentry->rd_rfiles);
		rfile_get(rfile_new);

		rfile_set_ops(rfile_new, rdentry->rd_ops);
	}


	spin_unlock(&rdentry->rd_lock);
	rdentry_put(rdentry_tmp);
	rdentry_put(rdentry);

	return rfile_get(rfile_new);
}

static void rfile_del_rcu(struct rcu_head *head)
{
	struct rfile *rfile = NULL;

	
	rfile = container_of(head, struct rfile, rf_rcu);
	rfile_put(rfile);
}

void rfile_del(struct file *file)
{
	struct rfile *rfile = NULL;


	rfile = rfile_find(file);
	if (!rfile)
		return;

	list_del_init(&rfile->rf_rdentry_list);
	rfile_put(rfile);

	rcu_assign_pointer(file->f_op, rfile->rf_op_old);
	rfile_put(rfile);

	call_rcu(&rfile->rf_rcu, rfile_del_rcu);
}

int rfs_open(struct inode *inode, struct file *file)
{
	struct rinode *rinode = NULL;
	const struct file_operations *fop = NULL;
	struct rfile *rfile = NULL;
	struct path *path = NULL;
	struct chain *chain = NULL;
	struct rfs_args args;
	int rv = 0;
	int cnt = 0;

	fop = file->f_op;
	rinode = rinode_find(inode);

	if (!rinode) {
		rcu_assign_pointer(file->f_op, inode->i_fop);
		if (file->f_op && file->f_op->open)
			rv = file->f_op->open(inode, file);
		fops_put(fop);
		return rv;
	}

	spin_lock(&rinode->ri_lock);
	path = path_get(rinode->ri_path);
	chain = chain_get(rinode->ri_chain);
	spin_unlock(&rinode->ri_lock);

	args.args.f_open.inode = inode;
	args.args.f_open.file = file;

	if (S_ISREG(inode->i_mode))
		args.type.id = RFS_REG_FOP_OPEN;
	else if (S_ISDIR(inode->i_mode))
		args.type.id = RFS_DIR_FOP_OPEN;

	if (!rfs_precall_flts(chain, NULL, &args, &cnt)) {
		if (rinode->ri_fop_old && rinode->ri_fop_old->open)
			rv = rinode->ri_fop_old->open(args.args.f_open.inode, args.args.f_open.file);

		args.retv.rv_int = rv;
	}

	rfs_postcall_flts(chain, NULL, &args, &cnt);

	rv = args.retv.rv_int;

	if (!rv) {
		rfile = rfile_add(file);
		BUG_ON(IS_ERR(rfile));
	}

	rinode_put(rinode);
	rfile_put(rfile);
	path_put(path);
	chain_put(chain);
	fops_put(fop);

	return rv;
}

int rfs_release(struct inode *inode, struct file *file)
{
	struct rfile *rfile = NULL;
	struct path *path = NULL;
	struct chain *chain = NULL;
	struct rfs_args args;
	int rv = 0;
	int cnt = 0;

	rfile = rfile_find(file);
	if (!rfile) {
		if (file->f_op && file->f_op->release)
			return file->f_op->release(inode, file);
	}

	spin_lock(&rfile->rf_lock);
	path = path_get(rfile->rf_path);
	chain = chain_get(rfile->rf_chain);
	spin_unlock(&rfile->rf_lock);

	args.args.f_release.inode = inode;
	args.args.f_release.file = file;

	if (S_ISREG(inode->i_mode))
		args.type.id = RFS_REG_FOP_OPEN;
	else if (S_ISDIR(inode->i_mode))
		args.type.id = RFS_DIR_FOP_OPEN;

	if (!rfs_precall_flts(chain, NULL, &args, &cnt)) {
		if (rfile->rf_op_old && rfile->rf_op_old->release)
			rv = rfile->rf_op_old->release(args.args.f_release.inode, args.args.f_release.file);

		args.retv.rv_int = rv;
	}

	rfs_postcall_flts(chain, NULL, &args, &cnt);

	rv = args.retv.rv_int;

	spin_lock(&rfile->rf_rdentry->rd_lock);
	rfile_del(file);
	spin_unlock(&rfile->rf_rdentry->rd_lock);

	rfile_put(rfile);
	path_put(path);
	chain_put(chain);

	return rv;
}

int rfs_readdir(struct file *file, void *buf, filldir_t filler)
{
	struct rfile *rfile = NULL;
	struct path *path = NULL;
	struct chain *chain = NULL;
	struct rfs_args args;
	int rv = 0;
	int cnt = 0;

	rfile = rfile_find(file);
	if (!rfile) {
		if (file->f_op && file->f_op->readdir)
			return file->f_op->readdir(file, buf, filler);
	}

	spin_lock(&rfile->rf_lock);
	path = path_get(rfile->rf_path);
	chain = chain_get(rfile->rf_chain);
	spin_unlock(&rfile->rf_lock);

	args.args.f_readdir.file = file;
	args.args.f_readdir.buf = buf;
	args.args.f_readdir.filldir = filler;
	args.type.id = RFS_DIR_FOP_READDIR;

	if (!rfs_precall_flts(chain, NULL, &args, &cnt)) {
		if (rfile->rf_op_old && rfile->rf_op_old->readdir)
			rv = rfile->rf_op_old->readdir(args.args.f_readdir.file, args.args.f_readdir.buf, args.args.f_readdir.filldir);

		args.retv.rv_int = rv;
	}
	
	rfs_postcall_flts(chain, NULL, &args, &cnt);
	rv = args.retv.rv_int;

	rfile_put(rfile);
	path_put(path);
	chain_put(chain);

	return rv;
}

ssize_t rfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	struct rfile *rfile = NULL;
	struct path *path = NULL;
	struct chain *chain = NULL;
	struct rfs_args args;
	ssize_t rv = 0;
	int cnt = 0;

	rfile = rfile_find(file);
	if (!rfile) {
		if (file->f_op && file->f_op->read)
			return file->f_op->read(file, buf, count, pos);
	}

	spin_lock(&rfile->rf_lock);
	path = path_get(rfile->rf_path);
	chain = chain_get(rfile->rf_chain);
	spin_unlock(&rfile->rf_lock);

	args.args.f_read.file = file;
	args.args.f_read.buf = buf;
	args.args.f_read.count = count;
	args.args.f_read.pos = pos;
	args.type.id = RFS_REG_FOP_READ;
	
	if (!rfs_precall_flts(chain, NULL, &args, &cnt)) {
		if (rfile->rf_op_old && rfile->rf_op_old->read)
			rv = rfile->rf_op_old->read(file, buf, count, pos);

		args.retv.rv_ssize = rv;
	}
	
	rfs_postcall_flts(chain, NULL, &args, &cnt);
	rv = args.retv.rv_int;

	rfile_put(rfile);
	path_put(path);
	chain_put(chain);

	return rv;
}

ssize_t rfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	struct rfile *rfile = NULL;
	struct path *path = NULL;
	struct chain *chain = NULL;
	struct rfs_args args;
	ssize_t rv = 0;
	int cnt = 0;

	rfile = rfile_find(file);
	if (!rfile) {
		if (file->f_op && file->f_op->write)
			return file->f_op->write(file, buf, count, pos);
	}

	spin_lock(&rfile->rf_lock);
	path = path_get(rfile->rf_path);
	chain = chain_get(rfile->rf_chain);
	spin_unlock(&rfile->rf_lock);

	args.args.f_write.file = file;
	args.args.f_write.buf = buf;
	args.args.f_write.count = count;
	args.args.f_write.pos = pos;
	args.type.id = RFS_REG_FOP_WRITE;

	if (!rfs_precall_flts(chain, NULL, &args, &cnt)) {
		if (rfile->rf_op_old && rfile->rf_op_old->write)
			rv = rfile->rf_op_old->write(file, buf, count, pos);

		args.retv.rv_ssize = rv;
	}
	
	rfs_postcall_flts(chain, NULL, &args, &cnt);
	rv = args.retv.rv_int;

	rfile_put(rfile);
	path_put(path);
	chain_put(chain);

	return rv;
}

void rfile_set_dir_ops(struct rfile *rfile, int *ops)
{
	if (ops[RFS_DIR_FOP_READDIR])
		rfile->rf_op_new.readdir = rfs_readdir;
	else
		rfile->rf_op_new.readdir = rfile->rf_op_old ? rfile->rf_op_old->readdir : NULL;
}

void rfile_set_reg_ops(struct rfile *rfile, int *ops)
{
	if (ops[RFS_REG_FOP_READ])
		rfile->rf_op_new.read = rfs_read;
	else
		rfile->rf_op_new.read = rfile->rf_op_old ? rfile->rf_op_old->read : NULL;

	if (ops[RFS_REG_FOP_WRITE])
		rfile->rf_op_new.write = rfs_write;
	else
		rfile->rf_op_new.write = rfile->rf_op_old ? rfile->rf_op_old->write : NULL;
}

void rfile_set_ops(struct rfile *rfile, struct ops *ops)
{
	umode_t mode = rfile->rf_rdentry->rd_rinode->ri_inode->i_mode;


	if (S_ISREG(mode))
		rfile_set_reg_ops(rfile, ops->o_ops);
	else if (S_ISDIR(mode))
		rfile_set_dir_ops(rfile, ops->o_ops);

	rfile->rf_op_new.open = rfs_open;
	rfile->rf_op_new.release = rfs_release;
}

int rfile_cache_create(void)
{
	rfile_cache = kmem_cache_create("rfile_cache",
					  sizeof(struct rfile),
					  0, SLAB_RECLAIM_ACCOUNT,
					  NULL, NULL);
	if (!rfile_cache)
		return -1;

	return 0;

}

void rfile_cache_destroy(void)
{
	kmem_cache_destroy(rfile_cache);
}

