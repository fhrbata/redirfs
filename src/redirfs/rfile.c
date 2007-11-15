#include "redir.h"

static struct kmem_cache *rfile_cache = NULL;
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
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&rfile->rf_rdentry_list);
	INIT_LIST_HEAD(&rfile->rf_data);
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

	rfile->rf_op_new.owner = THIS_MODULE;
	rfile->rf_op_old = (struct file_operations *)op_old;

	rinode_put(rinode);

	rfile->rf_op_new.open = rfs_open;

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
	struct rfs_priv_data *data;
	struct rfs_priv_data *tmp;

	if (!rfile || IS_ERR(rfile))
		return;

	BUG_ON(!atomic_read(&rfile->rf_count));
	if (!atomic_dec_and_test(&rfile->rf_count))
		return;

	path_put(rfile->rf_path);
	chain_put(rfile->rf_chain);
	rdentry_put(rfile->rf_rdentry);

	list_for_each_entry_safe(data, tmp, &rfile->rf_data, list) {
		spin_lock_irqsave(&rfile->rf_lock, flags);
		list_del(&data->list);
		spin_unlock_irqrestore(&rfile->rf_lock, flags);
		rfs_put_data(data);
	}

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
		fops_put(file->f_op);
		fops_get(rfile_new->rf_op_old);
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

		fops_put(file->f_op);
		fops_get(&rfile_new->rf_op_new);
		rcu_assign_pointer(file->f_op, &rfile_new->rf_op_new);
		rfile_get(rfile_new);

		list_add_tail(&rfile_new->rf_rdentry_list, &rdentry->rd_rfiles);
		rfile_get(rfile_new);

		rfile_set_ops(rfile_new, rdentry->rd_ops);

	} else {
		rfile_put(rfile_new);
		rfile_new = NULL;
	}


	spin_unlock(&rdentry->rd_lock);
	rdentry_put(rdentry_tmp);
	rdentry_put(rdentry);

	return rfile_new;
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

	fops_put(file->f_op);
	fops_get(rfile->rf_op_old);
	rcu_assign_pointer(file->f_op, rfile->rf_op_old);
	rfile_put(rfile);

	call_rcu(&rfile->rf_rcu, rfile_del_rcu);
}

int rfs_open(struct inode *inode, struct file *file)
{
	struct rinode *rinode = NULL;
	struct rfile *rfile = NULL;
	struct chain *chain = NULL;
	struct rfs_args args;
	struct context cont;
	int rv = 0;

	rinode = rinode_find(inode);

	if (!rinode) {
		fops_put(file->f_op);
		fops_get(inode->i_fop);
		rcu_assign_pointer(file->f_op, inode->i_fop);
		if (file->f_op && file->f_op->open)
			rv = file->f_op->open(inode, file);

		return rv;
	}

	spin_lock(&rinode->ri_lock);
	chain = chain_get(rinode->ri_chain);
	spin_unlock(&rinode->ri_lock);

	args.args.f_open.inode = inode;
	args.args.f_open.file = file;

	INIT_LIST_HEAD(&cont.data_list);

	if (S_ISREG(inode->i_mode))
		args.type.id = RFS_REG_FOP_OPEN;
	else if (S_ISDIR(inode->i_mode))
		args.type.id = RFS_DIR_FOP_OPEN;
	else if (S_ISLNK(inode->i_mode))
		args.type.id = RFS_LNK_FOP_OPEN;
	else if (S_ISCHR(inode->i_mode))
		args.type.id = RFS_CHR_FOP_OPEN;
	else if (S_ISBLK(inode->i_mode))
		args.type.id = RFS_BLK_FOP_OPEN;
	else if (S_ISFIFO(inode->i_mode))
		args.type.id = RFS_FIFO_FOP_OPEN;
	else 
		BUG();

	if (!rfs_precall_flts(0, chain, &cont, &args)) {
		if (rinode->ri_fop_old && rinode->ri_fop_old->open)
			rv = rinode->ri_fop_old->open(args.args.f_open.inode, args.args.f_open.file);

		args.retv.rv_int = rv;
	}

	if (!rv) {
		rfile = rfile_add(file);
		BUG_ON(IS_ERR(rfile));
	}

	rfs_postcall_flts(0, chain, &cont, &args);

	rv = args.retv.rv_int;

	if (rv && rfile) {
		spin_lock(&rfile->rf_rdentry->rd_lock);
		rfile_del(file);
		spin_unlock(&rfile->rf_rdentry->rd_lock);
	}

	rinode_put(rinode);
	rfile_put(rfile);
	chain_put(chain);

	BUG_ON(!list_empty(&cont.data_list));

	return rv;
}

int rfs_release(struct inode *inode, struct file *file)
{
	struct rfile *rfile = NULL;
	struct chain *chain = NULL;
	struct rfs_args args;
	struct context cont;
	int rv = 0;

	rfile = rfile_find(file);
	if (!rfile) {
		if (file->f_op && file->f_op->release)
			rv = file->f_op->release(inode, file);

		return rv;
	}

	spin_lock(&rfile->rf_lock);
	chain = chain_get(rfile->rf_chain);
	spin_unlock(&rfile->rf_lock);

	args.args.f_release.inode = inode;
	args.args.f_release.file = file;

	INIT_LIST_HEAD(&cont.data_list);

	if (S_ISREG(inode->i_mode))
		args.type.id = RFS_REG_FOP_RELEASE;
	else if (S_ISDIR(inode->i_mode))
		args.type.id = RFS_DIR_FOP_RELEASE;
	else if (S_ISLNK(inode->i_mode))
		args.type.id = RFS_LNK_FOP_RELEASE;
	else if (S_ISCHR(inode->i_mode))
		args.type.id = RFS_CHR_FOP_RELEASE;
	else if (S_ISBLK(inode->i_mode))
		args.type.id = RFS_BLK_FOP_RELEASE;
	else if (S_ISFIFO(inode->i_mode))
		args.type.id = RFS_FIFO_FOP_RELEASE;
	else 
		BUG();

	if (!rfs_precall_flts(0, chain, &cont, &args)) {
		if (rfile->rf_op_old && rfile->rf_op_old->release)
			rv = rfile->rf_op_old->release(args.args.f_release.inode, args.args.f_release.file);

		args.retv.rv_int = rv;
	}

	rfs_postcall_flts(0, chain, &cont, &args);

	rv = args.retv.rv_int;

	spin_lock(&rfile->rf_rdentry->rd_lock);
	rfile_del(file);
	spin_unlock(&rfile->rf_rdentry->rd_lock);

	rfile_put(rfile);
	chain_put(chain);

	BUG_ON(!list_empty(&cont.data_list));

	return rv;
}

int rfs_flush(struct file *file, fl_owner_t id)
{
	struct rfile *rfile = NULL;
	struct chain *chain = NULL;
	struct inode *inode = NULL;
	struct rfs_args args;
	struct context cont;
	int rv = 0;

	rfile = rfile_find(file);
	if (!rfile) {
		if (file->f_op && file->f_op->flush)
			return file->f_op->flush(file, id);

		return rv;
	}

	spin_lock(&rfile->rf_lock);
	chain = chain_get(rfile->rf_chain);
	spin_unlock(&rfile->rf_lock);

	args.args.f_flush.file = file;
	args.args.f_flush.id = id;

	INIT_LIST_HEAD(&cont.data_list);

	inode = file->f_dentry->d_inode;

	if (S_ISREG(inode->i_mode))
		args.type.id = RFS_REG_FOP_FLUSH;
	else if (S_ISDIR(inode->i_mode))
		args.type.id = RFS_DIR_FOP_FLUSH;
	else if (S_ISLNK(inode->i_mode))
		args.type.id = RFS_LNK_FOP_FLUSH;
	else if (S_ISCHR(inode->i_mode))
		args.type.id = RFS_CHR_FOP_FLUSH;
	else if (S_ISBLK(inode->i_mode))
		args.type.id = RFS_BLK_FOP_FLUSH;
	else if (S_ISFIFO(inode->i_mode))
		args.type.id = RFS_FIFO_FOP_FLUSH;
	else 
		BUG();

	if (!rfs_precall_flts(0, chain, &cont, &args)) {
		if (rfile->rf_op_old && rfile->rf_op_old->flush)
			rv = rfile->rf_op_old->flush(args.args.f_flush.file, args.args.f_flush.id);

		args.retv.rv_int = rv;
	}

	rfs_postcall_flts(0, chain, &cont, &args);
	rv = args.retv.rv_int;

	rfile_put(rfile);
	chain_put(chain);

	BUG_ON(!list_empty(&cont.data_list));

	return rv;
}

int rfs_readdir(struct file *file, void *buf, filldir_t filler)
{
	struct rfile *rfile = NULL;
	struct chain *chain = NULL;
	struct rfs_args args;
	struct context cont;
	int rv = 0;

	rfile = rfile_find(file);
	if (!rfile) {
		if (file->f_op && file->f_op->readdir)
			return file->f_op->readdir(file, buf, filler);

		return -ENOTDIR;
	}

	spin_lock(&rfile->rf_lock);
	chain = chain_get(rfile->rf_chain);
	spin_unlock(&rfile->rf_lock);

	args.args.f_readdir.file = file;
	args.args.f_readdir.buf = buf;
	args.args.f_readdir.filldir = filler;

	INIT_LIST_HEAD(&cont.data_list);

	if (S_ISDIR(file->f_dentry->d_inode->i_mode))
		args.type.id = RFS_DIR_FOP_READDIR;
	else
		BUG();

	if (!rfs_precall_flts(0, chain, &cont, &args)) {
		if (rfile->rf_op_old && rfile->rf_op_old->readdir)
			rv = rfile->rf_op_old->readdir(args.args.f_readdir.file,
					args.args.f_readdir.buf,
					args.args.f_readdir.filldir);
		else
			rv = -ENOTDIR;

		args.retv.rv_int = rv;
	}

	rfs_postcall_flts(0, chain, &cont, &args);
	rv = args.retv.rv_int;

	rfile_put(rfile);
	chain_put(chain);

	BUG_ON(!list_empty(&cont.data_list));

	return rv;
}

loff_t rfs_llseek(struct file *file, loff_t offset, int origin)
{
	struct rfile *rfile = NULL;
	struct chain *chain = NULL;
	struct rfs_args args;
	struct context cont;
	loff_t rv = 0;
	umode_t mode;

	rfile = rfile_find(file);
	if (!rfile) {
		if (file->f_mode & FMODE_LSEEK) {
			if (file->f_op && file->f_op->llseek)
				return file->f_op->llseek(file, offset, origin);
			else
				return default_llseek(file, offset, origin);
		}

		return no_llseek(file, offset, origin);
	}

	spin_lock(&rfile->rf_lock);
	chain = chain_get(rfile->rf_chain);
	spin_unlock(&rfile->rf_lock);

	args.args.f_llseek.file = file;
	args.args.f_llseek.offset = offset;
	args.args.f_llseek.origin = origin;

	INIT_LIST_HEAD(&cont.data_list);

	mode = file->f_dentry->d_inode->i_mode;

	if (S_ISREG(mode))
		args.type.id = RFS_REG_FOP_LLSEEK;
	else if (S_ISLNK(mode))
		args.type.id = RFS_LNK_FOP_LLSEEK;
	else if (S_ISCHR(mode))
		args.type.id = RFS_CHR_FOP_LLSEEK;
	else if (S_ISBLK(mode))
		args.type.id = RFS_BLK_FOP_LLSEEK;
	else if (S_ISFIFO(mode))
		args.type.id = RFS_FIFO_FOP_LLSEEK;
	else
		BUG();

	if (!rfs_precall_flts(0, chain, &cont, &args)) {
		if (file->f_mode & FMODE_LSEEK) {
			if (rfile->rf_op_old && rfile->rf_op_old->llseek)
				rv = rfile->rf_op_old->llseek(args.args.f_llseek.file, args.args.f_llseek.offset, args.args.f_llseek.origin);
			else
				rv = default_llseek(args.args.f_llseek.file, args.args.f_llseek.offset, args.args.f_llseek.origin);
		} else
			rv = no_llseek(args.args.f_llseek.file, args.args.f_llseek.offset, args.args.f_llseek.origin);

		args.retv.rv_loff = rv;
	}

	rfs_postcall_flts(0, chain, &cont, &args);
	rv = args.retv.rv_loff;

	rfile_put(rfile);
	chain_put(chain);

	BUG_ON(!list_empty(&cont.data_list));

	return rv;
}

static ssize_t rfs_read_call(struct filter *flt, struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	struct rfile *rfile = NULL;
	struct chain *chain = NULL;
	struct rfs_args args;
	struct context cont;
	ssize_t rv = 0;
	umode_t mode;
	int idx_start = 0;

	rfile = rfile_find(file);
	if (!rfile) {
		if (file->f_op && file->f_op->read)
			return file->f_op->read(file, buf, count, pos);

		return do_sync_read(file, buf, count, pos);
	}

	spin_lock(&rfile->rf_lock);
	chain = chain_get(rfile->rf_chain);
	spin_unlock(&rfile->rf_lock);

	args.args.f_read.file = file;
	args.args.f_read.buf = buf;
	args.args.f_read.count = count;
	args.args.f_read.pos = pos;

	INIT_LIST_HEAD(&cont.data_list);

	mode = file->f_dentry->d_inode->i_mode;

	if (S_ISREG(mode))
		args.type.id = RFS_REG_FOP_READ;
	else if (S_ISLNK(mode))
		args.type.id = RFS_LNK_FOP_READ;
	else if (S_ISCHR(mode))
		args.type.id = RFS_CHR_FOP_READ;
	else if (S_ISBLK(mode))
		args.type.id = RFS_BLK_FOP_READ;
	else if (S_ISFIFO(mode))
		args.type.id = RFS_FIFO_FOP_READ;
	else
		BUG();

	idx_start = chain_flt_idx(chain, flt);

	if (!rfs_precall_flts(idx_start, chain, &cont, &args)) {
		if (rfile->rf_op_old && rfile->rf_op_old->read)
			rv = rfile->rf_op_old->read(args.args.f_read.file,
					args.args.f_read.buf,
					args.args.f_read.count,
					args.args.f_read.pos);
		else
			rv = do_sync_read(args.args.f_read.file,
					args.args.f_read.buf,
					args.args.f_read.count,
					args.args.f_read.pos);


		args.retv.rv_ssize = rv;
	}

	rfs_postcall_flts(idx_start, chain, &cont, &args);
	rv = args.retv.rv_ssize;

	rfile_put(rfile);
	chain_put(chain);

	BUG_ON(!list_empty(&cont.data_list));

	return rv;
}

ssize_t rfs_read_subcall(rfs_filter flt, union rfs_op_args *args)
{
	return rfs_read_call(flt, args->f_read.file, args->f_read.buf, args->f_read.count, args->f_read.pos);
}

ssize_t rfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	return rfs_read_call(NULL, file, buf, count, pos);
}

ssize_t rfs_write_call(struct filter *flt, struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	struct rfile *rfile = NULL;
	struct chain *chain = NULL;
	struct rfs_args args;
	struct context cont;
	ssize_t rv = 0;
	int idx_start = 0;
	umode_t mode;

	rfile = rfile_find(file);
	if (!rfile) {
		if (file->f_op && file->f_op->write)
			return file->f_op->write(file, buf, count, pos);

		return do_sync_write(file, buf, count, pos);
	}

	spin_lock(&rfile->rf_lock);
	chain = chain_get(rfile->rf_chain);
	spin_unlock(&rfile->rf_lock);

	args.args.f_write.file = file;
	args.args.f_write.buf = buf;
	args.args.f_write.count = count;
	args.args.f_write.pos = pos;

	INIT_LIST_HEAD(&cont.data_list);

	mode = file->f_dentry->d_inode->i_mode;

	if (S_ISREG(mode))
		args.type.id = RFS_REG_FOP_WRITE;
	else if (S_ISLNK(mode))
		args.type.id = RFS_LNK_FOP_WRITE;
	else if (S_ISCHR(mode))
		args.type.id = RFS_CHR_FOP_WRITE;
	else if (S_ISBLK(mode))
		args.type.id = RFS_BLK_FOP_WRITE;
	else if (S_ISFIFO(mode))
		args.type.id = RFS_FIFO_FOP_WRITE;
	else
		BUG();

	idx_start = chain_flt_idx(chain, flt);

	if (!rfs_precall_flts(idx_start, chain, &cont, &args)) {
		if (rfile->rf_op_old && rfile->rf_op_old->write)
			rv = rfile->rf_op_old->write(args.args.f_write.file,
					args.args.f_write.buf,
					args.args.f_write.count,
					args.args.f_write.pos);
		else
			rv = do_sync_write(args.args.f_write.file,
					args.args.f_write.buf,
					args.args.f_write.count,
					args.args.f_write.pos);

		args.retv.rv_ssize = rv;
	}

	rfs_postcall_flts(idx_start, chain, &cont, &args);
	rv = args.retv.rv_ssize;

	rfile_put(rfile);
	chain_put(chain);

	BUG_ON(!list_empty(&cont.data_list));

	return rv;
}

ssize_t rfs_write_subcall(rfs_filter flt, union rfs_op_args *args)
{
	return rfs_write_call(flt, args->f_write.file, args->f_write.buf, args->f_write.count, args->f_write.pos);
}

ssize_t rfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	return rfs_write_call(NULL, file, buf, count, pos);
}

static ssize_t rfs_aio_read_call(struct filter *flt, struct kiocb *iocb,
		const struct iovec *iov, unsigned long nr_segs, loff_t pos)
{
	struct rfile *rfile = NULL;
	struct file *file = iocb->ki_filp;
	struct chain *chain = NULL;
	struct rfs_args args;
	struct context cont;
	ssize_t rv = 0;
	int idx_start = 0;
	umode_t mode;

	rfile = rfile_find(file);
	if (!rfile) {
		if (file->f_op && file->f_op->aio_read)
			return file->f_op->aio_read(iocb, iov, nr_segs, pos);

		return -EINVAL;
	}

	spin_lock(&rfile->rf_lock);
	chain = chain_get(rfile->rf_chain);
	spin_unlock(&rfile->rf_lock);

	args.args.f_aio_read.iocb = iocb;
	args.args.f_aio_read.iov = iov;
	args.args.f_aio_read.nr_segs = nr_segs;
	args.args.f_aio_read.pos = pos;

	INIT_LIST_HEAD(&cont.data_list);

	mode = file->f_dentry->d_inode->i_mode;

	if (S_ISREG(mode))
		args.type.id = RFS_REG_FOP_AIO_READ;
	else if (S_ISLNK(mode))
		args.type.id = RFS_LNK_FOP_AIO_READ;
	else if (S_ISCHR(mode))
		args.type.id = RFS_CHR_FOP_AIO_READ;
	else if (S_ISBLK(mode))
		args.type.id = RFS_BLK_FOP_AIO_READ;
	else if (S_ISFIFO(mode))
		args.type.id = RFS_FIFO_FOP_AIO_READ;
	else
		BUG();

	idx_start = chain_flt_idx(chain, flt);

	if (!rfs_precall_flts(idx_start, chain, &cont, &args)) {
		if (rfile->rf_op_old && rfile->rf_op_old->aio_read)
			rv = rfile->rf_op_old->aio_read(args.args.f_aio_read.iocb,
					args.args.f_aio_read.iov,
					args.args.f_aio_read.nr_segs,
					args.args.f_aio_read.pos);
		else
			rv = -EINVAL;

		args.retv.rv_ssize = rv;
	}

	rfs_postcall_flts(idx_start, chain, &cont, &args);
	rv = args.retv.rv_ssize;

	rfile_put(rfile);
	chain_put(chain);

	BUG_ON(!list_empty(&cont.data_list));

	return rv;
}

ssize_t rfs_aio_read_subcall(rfs_filter flt, union rfs_op_args *args)
{
	return rfs_aio_read_call(flt, args->f_aio_read.iocb, args->f_aio_read.iov,
			args->f_aio_read.nr_segs, args->f_aio_read.pos);
}

ssize_t rfs_aio_read(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos)
{
	return rfs_aio_read_call(NULL, iocb, iov, nr_segs, pos);
}

static ssize_t rfs_aio_write_call(struct filter *flt, struct kiocb *iocb,
		const struct iovec *iov, unsigned long nr_segs, loff_t pos)
{
	struct rfile *rfile = NULL;
	struct file *file = iocb->ki_filp;
	struct chain *chain = NULL;
	struct rfs_args args;
	struct context cont;
	ssize_t rv = 0;
	int idx_start = 0;
	umode_t mode;

	rfile = rfile_find(file);
	if (!rfile) {
		if (file->f_op && file->f_op->aio_write)
			return file->f_op->aio_write(iocb, iov, nr_segs, pos);

		return -EINVAL;
	}

	spin_lock(&rfile->rf_lock);
	chain = chain_get(rfile->rf_chain);
	spin_unlock(&rfile->rf_lock);

	args.args.f_aio_write.iocb = iocb;
	args.args.f_aio_write.iov = iov;
	args.args.f_aio_write.nr_segs = nr_segs;
	args.args.f_aio_write.pos = pos;

	INIT_LIST_HEAD(&cont.data_list);

	mode = file->f_dentry->d_inode->i_mode;

	if (S_ISREG(mode))
		args.type.id = RFS_REG_FOP_AIO_WRITE;
	else if (S_ISLNK(mode))
		args.type.id = RFS_LNK_FOP_AIO_WRITE;
	else if (S_ISCHR(mode))
		args.type.id = RFS_CHR_FOP_AIO_WRITE;
	else if (S_ISBLK(mode))
		args.type.id = RFS_BLK_FOP_AIO_WRITE;
	else if (S_ISFIFO(mode))
		args.type.id = RFS_FIFO_FOP_AIO_WRITE;
	else
		BUG();

	idx_start = chain_flt_idx(chain, flt);

	if (!rfs_precall_flts(idx_start, chain, &cont, &args)) {
		if (rfile->rf_op_old && rfile->rf_op_old->aio_write)
			rv = rfile->rf_op_old->aio_write(args.args.f_aio_write.iocb,
					args.args.f_aio_write.iov,
					args.args.f_aio_write.nr_segs,
					args.args.f_aio_write.pos);
		else
			rv = -EINVAL;

		args.retv.rv_ssize = rv;
	}

	rfs_postcall_flts(idx_start, chain, &cont, &args);
	rv = args.retv.rv_ssize;

	rfile_put(rfile);
	chain_put(chain);

	BUG_ON(!list_empty(&cont.data_list));

	return rv;
}

ssize_t rfs_aio_write_subcall(rfs_filter flt, union rfs_op_args *args)
{
	return rfs_aio_write_call(flt, args->f_aio_write.iocb, args->f_aio_write.iov,
			args->f_aio_write.nr_segs, args->f_aio_write.pos);
}

ssize_t rfs_aio_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos)
{
	return rfs_aio_write_call(NULL, iocb, iov, nr_segs, pos);
}

static void rfile_set_reg_ops(struct rfile *rfile, char *ops)
{
	if (ops[RFS_REG_FOP_READ])
		rfile->rf_op_new.read = rfs_read;
	else
		rfile->rf_op_new.read = rfile->rf_op_old ? rfile->rf_op_old->read : NULL;

	if (ops[RFS_REG_FOP_WRITE])
		rfile->rf_op_new.write = rfs_write;
	else
		rfile->rf_op_new.write = rfile->rf_op_old ? rfile->rf_op_old->write : NULL;

	if (ops[RFS_REG_FOP_AIO_READ])
		rfile->rf_op_new.aio_read = rfs_aio_read;
	else
		rfile->rf_op_new.aio_read = rfile->rf_op_old ? rfile->rf_op_old->aio_read : NULL;

	if (ops[RFS_REG_FOP_AIO_WRITE])
		rfile->rf_op_new.aio_write = rfs_aio_write;
	else
		rfile->rf_op_new.aio_write = rfile->rf_op_old ? rfile->rf_op_old->aio_write : NULL;

	if (ops[RFS_REG_FOP_LLSEEK])
		rfile->rf_op_new.llseek = rfs_llseek;
	else
		rfile->rf_op_new.llseek = rfile->rf_op_old ? rfile->rf_op_old->llseek : NULL;

	if (ops[RFS_REG_FOP_FLUSH])
		rfile->rf_op_new.flush = rfs_flush;
	else
		rfile->rf_op_new.flush = rfile->rf_op_old ? rfile->rf_op_old->flush : NULL;
}

static void rfile_set_dir_ops(struct rfile *rfile, char *ops)
{
	if (ops[RFS_DIR_FOP_READDIR])
		rfile->rf_op_new.readdir = rfs_readdir;
	else
		rfile->rf_op_new.readdir = rfile->rf_op_old ? rfile->rf_op_old->readdir : NULL;

	if (ops[RFS_DIR_FOP_FLUSH])
		rfile->rf_op_new.flush = rfs_flush;
	else
		rfile->rf_op_new.flush = rfile->rf_op_old ? rfile->rf_op_old->flush : NULL;
}

static void rfile_set_chr_ops(struct rfile *rfile, char *ops)
{
	if (ops[RFS_CHR_FOP_READ])
		rfile->rf_op_new.read = rfs_read;
	else
		rfile->rf_op_new.read = rfile->rf_op_old ? rfile->rf_op_old->read : NULL;

	if (ops[RFS_CHR_FOP_WRITE])
		rfile->rf_op_new.write = rfs_write;
	else
		rfile->rf_op_new.write = rfile->rf_op_old ? rfile->rf_op_old->write : NULL;

	if (ops[RFS_CHR_FOP_AIO_READ])
		rfile->rf_op_new.aio_read = rfs_aio_read;
	else
		rfile->rf_op_new.aio_read = rfile->rf_op_old ? rfile->rf_op_old->aio_read : NULL;

	if (ops[RFS_CHR_FOP_AIO_WRITE])
		rfile->rf_op_new.aio_write = rfs_aio_write;
	else
		rfile->rf_op_new.aio_write = rfile->rf_op_old ? rfile->rf_op_old->aio_write : NULL;

	if (ops[RFS_CHR_FOP_LLSEEK])
		rfile->rf_op_new.llseek = rfs_llseek;
	else
		rfile->rf_op_new.llseek = rfile->rf_op_old ? rfile->rf_op_old->llseek : NULL;

	if (ops[RFS_CHR_FOP_FLUSH])
		rfile->rf_op_new.flush = rfs_flush;
	else
		rfile->rf_op_new.flush = rfile->rf_op_old ? rfile->rf_op_old->flush : NULL;
}

static void rfile_set_blk_ops(struct rfile *rfile, char *ops)
{
	if (ops[RFS_BLK_FOP_READ])
		rfile->rf_op_new.read = rfs_read;
	else
		rfile->rf_op_new.read = rfile->rf_op_old ? rfile->rf_op_old->read : NULL;

	if (ops[RFS_BLK_FOP_WRITE])
		rfile->rf_op_new.write = rfs_write;
	else
		rfile->rf_op_new.write = rfile->rf_op_old ? rfile->rf_op_old->write : NULL;

	if (ops[RFS_BLK_FOP_AIO_READ])
		rfile->rf_op_new.aio_read = rfs_aio_read;
	else
		rfile->rf_op_new.aio_read = rfile->rf_op_old ? rfile->rf_op_old->aio_read : NULL;

	if (ops[RFS_BLK_FOP_AIO_WRITE])
		rfile->rf_op_new.aio_write = rfs_aio_write;
	else
		rfile->rf_op_new.aio_write = rfile->rf_op_old ? rfile->rf_op_old->aio_write : NULL;

	if (ops[RFS_BLK_FOP_LLSEEK])
		rfile->rf_op_new.llseek = rfs_llseek;
	else
		rfile->rf_op_new.llseek = rfile->rf_op_old ? rfile->rf_op_old->llseek : NULL;

	if (ops[RFS_BLK_FOP_FLUSH])
		rfile->rf_op_new.flush = rfs_flush;
	else
		rfile->rf_op_new.flush = rfile->rf_op_old ? rfile->rf_op_old->flush : NULL;
}

static void rfile_set_fifo_ops(struct rfile *rfile, char *ops)
{
	if (ops[RFS_FIFO_FOP_READ])
		rfile->rf_op_new.read = rfs_read;
	else
		rfile->rf_op_new.read = rfile->rf_op_old ? rfile->rf_op_old->read : NULL;

	if (ops[RFS_FIFO_FOP_WRITE])
		rfile->rf_op_new.write = rfs_write;
	else
		rfile->rf_op_new.write = rfile->rf_op_old ? rfile->rf_op_old->write : NULL;

	if (ops[RFS_FIFO_FOP_AIO_READ])
		rfile->rf_op_new.aio_read = rfs_aio_read;
	else
		rfile->rf_op_new.aio_read = rfile->rf_op_old ? rfile->rf_op_old->aio_read : NULL;

	if (ops[RFS_FIFO_FOP_AIO_WRITE])
		rfile->rf_op_new.aio_write = rfs_aio_write;
	else
		rfile->rf_op_new.aio_write = rfile->rf_op_old ? rfile->rf_op_old->aio_write : NULL;

	if (ops[RFS_FIFO_FOP_LLSEEK])
		rfile->rf_op_new.llseek = rfs_llseek;
	else
		rfile->rf_op_new.llseek = rfile->rf_op_old ? rfile->rf_op_old->llseek : NULL;

	if (ops[RFS_FIFO_FOP_FLUSH])
		rfile->rf_op_new.flush = rfs_flush;
	else
		rfile->rf_op_new.flush = rfile->rf_op_old ? rfile->rf_op_old->flush : NULL;
}

static void rfile_set_lnk_ops(struct rfile *rfile, char *ops)
{
	if (ops[RFS_LNK_FOP_READ])
		rfile->rf_op_new.read = rfs_read;
	else
		rfile->rf_op_new.read = rfile->rf_op_old ? rfile->rf_op_old->read : NULL;

	if (ops[RFS_LNK_FOP_WRITE])
		rfile->rf_op_new.write = rfs_write;
	else
		rfile->rf_op_new.write = rfile->rf_op_old ? rfile->rf_op_old->write : NULL;

	if (ops[RFS_LNK_FOP_AIO_READ])
		rfile->rf_op_new.aio_read = rfs_aio_read;
	else
		rfile->rf_op_new.aio_read = rfile->rf_op_old ? rfile->rf_op_old->aio_read : NULL;

	if (ops[RFS_LNK_FOP_AIO_WRITE])
		rfile->rf_op_new.aio_write = rfs_aio_write;
	else
		rfile->rf_op_new.aio_write = rfile->rf_op_old ? rfile->rf_op_old->aio_write : NULL;

	if (ops[RFS_LNK_FOP_LLSEEK])
		rfile->rf_op_new.llseek = rfs_llseek;
	else
		rfile->rf_op_new.llseek = rfile->rf_op_old ? rfile->rf_op_old->llseek : NULL;

	if (ops[RFS_LNK_FOP_FLUSH])
		rfile->rf_op_new.flush = rfs_flush;
	else
		rfile->rf_op_new.flush = rfile->rf_op_old ? rfile->rf_op_old->flush : NULL;
}

void rfile_set_ops(struct rfile *rfile, struct ops *ops)
{
	umode_t mode = rfile->rf_rdentry->rd_rinode->ri_inode->i_mode;

	if (S_ISREG(mode))
		rfile_set_reg_ops(rfile, ops->o_ops);

	else if (S_ISDIR(mode))
		rfile_set_dir_ops(rfile, ops->o_ops);

	else if (S_ISLNK(mode))
		rfile_set_lnk_ops(rfile, ops->o_ops);

	else if (S_ISCHR(mode))
		rfile_set_chr_ops(rfile, ops->o_ops);

	else if (S_ISBLK(mode))
		rfile_set_blk_ops(rfile, ops->o_ops);

	else if (S_ISFIFO(mode))
		rfile_set_fifo_ops(rfile, ops->o_ops);

	else
		BUG();

	rfile->rf_op_new.open = rfs_open;
	rfile->rf_op_new.release = rfs_release;
}

int rfile_cache_create(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	rfile_cache = kmem_cache_create("rfile_cache", sizeof(struct rfile), 0, SLAB_RECLAIM_ACCOUNT, NULL, NULL);
#else
	rfile_cache = kmem_cache_create("rfile_cache", sizeof(struct rfile), 0, SLAB_RECLAIM_ACCOUNT, NULL);
#endif
	if (!rfile_cache)
		return -ENOMEM;

	return 0;

}

void rfile_cache_destroy(void)
{
	kmem_cache_destroy(rfile_cache);
}

int rfs_attach_data_file(rfs_filter filter, struct file *file,
		struct rfs_priv_data *data, struct rfs_priv_data **exist)
{
	struct filter *flt;
	struct rfile *rfile;
	struct rfs_priv_data *found;

	flt = (struct filter *)filter;

	if (!flt || !file || !data || !exist)
		return -EINVAL;

	rfile = rfile_find(file);
	if (!rfile)
		return -ENODATA;

	spin_lock(&rfile->rf_lock);

	if (chain_find_flt(rfile->rf_chain, flt) == -1) {
		spin_unlock(&rfile->rf_lock);
		rfile_put(rfile);
		return -ENOENT;
	}

	found = rfs_find_data(&rfile->rf_data, flt);
	if (found) {
		*exist = rfs_get_data(found);
		spin_unlock(&rfile->rf_lock);
		rfile_put(rfile);
		return -EEXIST;
	}

	rfs_get_data(data);
	list_add_tail(&data->list, &rfile->rf_data);
	*exist = NULL;
	spin_unlock(&rfile->rf_lock);

	rfile_put(rfile);

	return 0;
}

int rfs_detach_data_file(rfs_filter filter, struct file *file,
		struct rfs_priv_data **data)
{
	struct filter *flt;
	struct rfile *rfile;
	struct rfs_priv_data *found;

	flt = (struct filter *)filter;

	if (!flt || !file || !data)
		return -EINVAL;

	rfile = rfile_find(file);
	if (!rfile)
		return -ENODATA;

	spin_lock(&rfile->rf_lock);
	found = rfs_find_data(&rfile->rf_data, flt);
	if (!found) {
		spin_unlock(&rfile->rf_lock);
		rfile_put(rfile);
		return -ENODATA;
	}

	list_del(&found->list);
	*data = found;

	spin_unlock(&rfile->rf_lock);

	rfile_put(rfile);

	return 0;
}

int rfs_get_data_file(rfs_filter filter, struct file *file,
		struct rfs_priv_data **data)
{
	struct filter *flt;
	struct rfile *rfile;
	struct rfs_priv_data *found;

	flt = (struct filter *)filter;

	if (!flt || !file || !data)
		return -EINVAL;

	rfile = rfile_find(file);
	if (!rfile)
		return -ENODATA;

	spin_lock(&rfile->rf_lock);
	found = rfs_find_data(&rfile->rf_data, flt);
	if (!found) {
		spin_unlock(&rfile->rf_lock);
		rfile_put(rfile);
		return -ENODATA;
	}

	*data = rfs_get_data(found);

	spin_unlock(&rfile->rf_lock);

	rfile_put(rfile);

	return 0;
}

EXPORT_SYMBOL(rfs_attach_data_file);
EXPORT_SYMBOL(rfs_detach_data_file);
EXPORT_SYMBOL(rfs_get_data_file);
EXPORT_SYMBOL(rfs_read_subcall);
EXPORT_SYMBOL(rfs_write_subcall);
EXPORT_SYMBOL(rfs_aio_read_subcall);
EXPORT_SYMBOL(rfs_aio_write_subcall);

