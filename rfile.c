#include "redir.h"

static kmem_cache_t *rfile_cache = NULL;
static unsigned long long rfile_cnt = 0;
static spinlock_t rfile_cnt_lock = SPIN_LOCK_UNLOCKED;
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

	
	rfile = kmem_cache_alloc(rfile_cache, GFP_KERNEL);
	if (!rfile)
		return ERR_PTR(-ENOMEM);
	
	INIT_LIST_HEAD(&rfile->rf_rdentry_list);
	INIT_RCU_HEAD(&rfile->rf_rcu);
	rfile->rf_path = NULL;
	rfile->rf_file = file;
	rfile->rf_rdentry = NULL;
	atomic_set(&rfile->rf_count, 1);
	

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

	spin_lock(&rfile_cnt_lock);
	rfile_cnt++;
	spin_unlock(&rfile_cnt_lock);

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
	if (!rfile || IS_ERR(rfile))
		return;

	BUG_ON(!atomic_read(&rfile->rf_count));
	if (!atomic_dec_and_test(&rfile->rf_count))
		return;

	path_put(rfile->rf_path);
	rdentry_put(rfile->rf_rdentry);
	kmem_cache_free(rfile_cache, rfile);

	spin_lock(&rfile_cnt_lock);
	if (!--rfile_cnt)
		atomic_set(&rfiles_freed, 1);
	spin_unlock(&rfile_cnt_lock);

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


	rfile_new = rfile_alloc(file);
	if (IS_ERR(rfile_new))
		return rfile_new;

	spin_lock(&file->f_dentry->d_lock);

	rdentry = rdentry_find(file->f_dentry);

	if (!rdentry) {
		rcu_assign_pointer(file->f_op, rfile_new->rf_op_old);
		rfile_put(rfile_new);
		spin_unlock(&file->f_dentry->d_lock);
		return NULL;
	}

	rfile_new->rf_rdentry = rdentry;
	rfile_new->rf_path = path_get(rdentry->rd_path);

	rcu_assign_pointer(file->f_op, &rfile_new->rf_op_new);

	list_add_tail(&rfile_new->rf_rdentry_list, &rdentry->rd_rfiles);
	rfile_get(rfile_new);

	rfile_set_ops(rfile_new, rdentry->rd_path);

	spin_unlock(&file->f_dentry->d_lock);

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
	struct rinode *rinode = rinode_find(inode);
	const struct file_operations *fop = file->f_op;
	struct rfile *rfile = NULL;
	int rv = 0;


	if (!rinode) {
		rcu_assign_pointer(file->f_op, inode->i_fop);
		if (file->f_op && file->f_op->open)
			rv = file->f_op->open(inode, file);
		fops_put(fop);
		return rv;
	}

	if (rinode->ri_fop_old && rinode->ri_fop_old->open)
		rv = rinode->ri_fop_old->open(inode, file);

	if (!rv) {
		rfile = rfile_add(file);
		BUG_ON(IS_ERR(rfile));
	}

	rinode_put(rinode);
	rfile_put(rfile);

	fops_put(fop);
	return rv;
}

int rfs_release(struct inode *inode, struct file *file)
{
	struct rfile *rfile = rfile_find(file);
	int rv = 0;


	if (!rfile) {
		if (file->f_op && file->f_op->release)
			rv = file->f_op->release(inode, file);
		return rv;
	}

	if (rfile->rf_op_old && rfile->rf_op_old->release)
		rv = rfile->rf_op_old->release(inode, file);

	spin_lock(&file->f_dentry->d_lock);
	rfile_del(file);
	spin_unlock(&file->f_dentry->d_lock);
	rfile_put(rfile);

	return rv;
}

void rfile_set_ops(struct rfile *rfile, struct path *path)
{
	spin_lock(&path->p_lock);

	rfile->rf_op_new.open = rfs_open;
	rfile->rf_op_new.release = rfs_release;

	spin_unlock(&path->p_lock);
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

