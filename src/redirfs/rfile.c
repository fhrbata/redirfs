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
	struct data *data;
	struct data *tmp;

	if (!rfile || IS_ERR(rfile))
		return;

	BUG_ON(!atomic_read(&rfile->rf_count));
	if (!atomic_dec_and_test(&rfile->rf_count))
		return;

	path_put(rfile->rf_path);
	chain_put(rfile->rf_chain);
	rdentry_put(rfile->rf_rdentry);

	list_for_each_entry_safe(data, tmp, &rfile->rf_data, list) {
		data->cb(data->data);
		list_del(&data->list);
		flt_put(data->filter);
		kfree(data);
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

	rcu_assign_pointer(file->f_op, rfile->rf_op_old);
	rfile_put(rfile);

	call_rcu(&rfile->rf_rcu, rfile_del_rcu);
}

int rfs_open(struct inode *inode, struct file *file)
{
	struct rinode *rinode = NULL;
	const struct file_operations *fop = NULL;
	struct rfile *rfile = NULL;
	struct rpath *path = NULL;
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
	else if (S_ISLNK(inode->i_mode))
		args.type.id = RFS_LNK_FOP_OPEN;
	else if (S_ISCHR(inode->i_mode))
		args.type.id = RFS_CHR_FOP_OPEN;
	else if (S_ISBLK(inode->i_mode))
		args.type.id = RFS_BLK_FOP_OPEN;
	else if (S_ISFIFO(inode->i_mode))
		args.type.id = RFS_FIFO_FOP_OPEN;
	else 
		args.type.id = RFS_SOCK_FOP_OPEN;

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
	struct rpath *path = NULL;
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
		args.type.id = RFS_SOCK_FOP_RELEASE;

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
	struct rpath *path = NULL;
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
	if (S_ISDIR(file->f_dentry->d_inode->i_mode))
		args.type.id = RFS_DIR_FOP_READDIR;
	else
		BUG();

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

loff_t rfs_llseek(struct file *file, loff_t offset, int origin)
{
	struct rfile *rfile = NULL;
	struct rpath *path = NULL;
	struct chain *chain = NULL;
	struct rfs_args args;
	loff_t rv = 0;
	int cnt = 0;
	umode_t mode;

	rfile = rfile_find(file);
	if (!rfile) {
		if (file->f_op && file->f_op->llseek)
			return file->f_op->llseek(file, offset, origin);
	}

	spin_lock(&rfile->rf_lock);
	path = path_get(rfile->rf_path);
	chain = chain_get(rfile->rf_chain);
	spin_unlock(&rfile->rf_lock);

	args.args.f_llseek.file = file;
	args.args.f_llseek.offset = offset;
	args.args.f_llseek.origin = origin;

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
	else if (S_ISSOCK(mode))
		args.type.id = RFS_SOCK_FOP_LLSEEK;
	else
		BUG();

	if (!rfs_precall_flts(chain, NULL, &args, &cnt)) {
		if (rfile->rf_op_old && rfile->rf_op_old->llseek)
			rv = rfile->rf_op_old->llseek(file, offset, origin);

		args.retv.rv_loff = rv;
	}
	
	rfs_postcall_flts(chain, NULL, &args, &cnt);
	rv = args.retv.rv_loff;

	rfile_put(rfile);
	path_put(path);
	chain_put(chain);

	return rv;
}

ssize_t rfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	struct rfile *rfile = NULL;
	struct rpath *path = NULL;
	struct chain *chain = NULL;
	struct rfs_args args;
	ssize_t rv = 0;
	int cnt = 0;
	umode_t mode;

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
	else if (S_ISSOCK(mode))
		args.type.id = RFS_SOCK_FOP_READ;
	else
		BUG();

	if (!rfs_precall_flts(chain, NULL, &args, &cnt)) {
		if (rfile->rf_op_old && rfile->rf_op_old->read)
			rv = rfile->rf_op_old->read(file, buf, count, pos);

		args.retv.rv_ssize = rv;
	}
	
	rfs_postcall_flts(chain, NULL, &args, &cnt);
	rv = args.retv.rv_ssize;

	rfile_put(rfile);
	path_put(path);
	chain_put(chain);

	return rv;
}

ssize_t rfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	struct rfile *rfile = NULL;
	struct rpath *path = NULL;
	struct chain *chain = NULL;
	struct rfs_args args;
	ssize_t rv = 0;
	int cnt = 0;
	umode_t mode;

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
	else if (S_ISSOCK(mode))
		args.type.id = RFS_SOCK_FOP_WRITE;
	else
		BUG();

	if (!rfs_precall_flts(chain, NULL, &args, &cnt)) {
		if (rfile->rf_op_old && rfile->rf_op_old->write)
			rv = rfile->rf_op_old->write(file, buf, count, pos);

		args.retv.rv_ssize = rv;
	}
	
	rfs_postcall_flts(chain, NULL, &args, &cnt);
	rv = args.retv.rv_ssize;

	rfile_put(rfile);
	path_put(path);
	chain_put(chain);

	return rv;
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

	if (ops[RFS_REG_FOP_LLSEEK])
		rfile->rf_op_new.llseek = rfs_llseek;
	else
		rfile->rf_op_new.llseek = rfile->rf_op_old ? rfile->rf_op_old->llseek : NULL;
}

static void rfile_set_dir_ops(struct rfile *rfile, char *ops)
{
	if (ops[RFS_DIR_FOP_READDIR])
		rfile->rf_op_new.readdir = rfs_readdir;
	else
		rfile->rf_op_new.readdir = rfile->rf_op_old ? rfile->rf_op_old->readdir : NULL;
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

	if (ops[RFS_CHR_FOP_LLSEEK])
		rfile->rf_op_new.llseek = rfs_llseek;
	else
		rfile->rf_op_new.llseek = rfile->rf_op_old ? rfile->rf_op_old->llseek : NULL;
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

	if (ops[RFS_BLK_FOP_LLSEEK])
		rfile->rf_op_new.llseek = rfs_llseek;
	else
		rfile->rf_op_new.llseek = rfile->rf_op_old ? rfile->rf_op_old->llseek : NULL;
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

	if (ops[RFS_FIFO_FOP_LLSEEK])
		rfile->rf_op_new.llseek = rfs_llseek;
	else
		rfile->rf_op_new.llseek = rfile->rf_op_old ? rfile->rf_op_old->llseek : NULL;
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

	if (ops[RFS_LNK_FOP_LLSEEK])
		rfile->rf_op_new.llseek = rfs_llseek;
	else
		rfile->rf_op_new.llseek = rfile->rf_op_old ? rfile->rf_op_old->llseek : NULL;
}

static void rfile_set_sock_ops(struct rfile *rfile, char *ops)
{
	if (ops[RFS_SOCK_FOP_READ])
		rfile->rf_op_new.read = rfs_read;
	else
		rfile->rf_op_new.read = rfile->rf_op_old ? rfile->rf_op_old->read : NULL;

	if (ops[RFS_SOCK_FOP_WRITE])
		rfile->rf_op_new.write = rfs_write;
	else
		rfile->rf_op_new.write = rfile->rf_op_old ? rfile->rf_op_old->write : NULL;

	if (ops[RFS_SOCK_FOP_LLSEEK])
		rfile->rf_op_new.llseek = rfs_llseek;
	else
		rfile->rf_op_new.llseek = rfile->rf_op_old ? rfile->rf_op_old->llseek : NULL;
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

	else if (S_ISSOCK(mode))
		rfile_set_sock_ops(rfile, ops->o_ops);

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
		return -ENOMEM;

	return 0;

}

void rfile_cache_destroy(void)
{
	kmem_cache_destroy(rfile_cache);
}

int rfs_attach_data_file(rfs_filter filter, struct file *file, void *data, void (*cb)(void *))
{
	struct filter *flt;
	struct rfile *rfile;
	struct data *found;
	struct data *data_new;

	flt = (struct filter *)filter;

	if (!flt || !file || !cb)
		return -EINVAL;

	data_new = kmalloc(sizeof(struct data), GFP_KERNEL);
	if (!data_new)
		return -ENOMEM;

	rfile = rfile_find(file);
	if (!rfile) {
		kfree(data_new);
		return -ENODATA;
	}

	spin_lock(&rfile->rf_lock);

	if (chain_find_flt(rfile->rf_chain, flt) != -1) {
		spin_unlock(&rfile->rf_lock);
		rfile_put(rfile);
		return -ENOENT;
	}

	found = data_find(&rfile->rf_data, flt);
	if (found) {
		kfree(data_new);
		spin_unlock(&rfile->rf_lock);
		rfile_put(rfile);
		return -EEXIST;
	}

	INIT_LIST_HEAD(&data_new->list);
	data_new->data = data;
	data_new->cb = cb;
	data_new->filter = flt_get(flt);
	list_add_tail(&data_new->list, &rfile->rf_data);
	spin_unlock(&rfile->rf_lock);

	rfile_put(rfile);
	return 0;
}

int rfs_detach_data_file(rfs_filter *filter, struct file *file, void **data)
{
	struct filter *flt;
	struct rfile *rfile;
	struct data *found;

	flt = (struct filter *)filter;
	
	if (!flt || !file)
		return -EINVAL;

	rfile = rfile_find(file);
	if (!rfile)
		return -ENODATA;

	spin_lock(&rfile->rf_lock);
	found = data_find(&rfile->rf_data, flt);
	if (!found) {
		spin_unlock(&rfile->rf_lock);
		rfile_put(rfile);
		return -ENODATA;
	}

	list_del(&found->list);
	*data = found->data;
	flt_put(found->filter);
	kfree(found);

	spin_unlock(&rfile->rf_lock);

	rfile_put(rfile);

	return 0;
}

int rfs_get_data_file(rfs_filter *filter, struct file *file, void **data)
{
	struct filter *flt;
	struct rfile *rfile;
	struct data *found;

	flt = (struct filter *)filter;
	
	if (!flt || !file)
		return -EINVAL;

	rfile = rfile_find(file);
	if (!rfile)
		return -ENODATA;

	spin_lock(&rfile->rf_lock);
	found = data_find(&rfile->rf_data, flt);
	if (!found) {
		spin_unlock(&rfile->rf_lock);
		rfile_put(rfile);
		return -ENODATA;
	}

	*data = found->data;

	spin_unlock(&rfile->rf_lock);

	rfile_put(rfile);

	return 0;
}

EXPORT_SYMBOL(rfs_attach_data_file);
EXPORT_SYMBOL(rfs_detach_data_file);
EXPORT_SYMBOL(rfs_get_data_file);
