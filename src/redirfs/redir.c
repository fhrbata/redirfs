#include "redir.h"

DECLARE_WAIT_QUEUE_HEAD(rdentries_wait);
atomic_t rdentries_freed;
DECLARE_WAIT_QUEUE_HEAD(rinodes_wait);
atomic_t rinodes_freed;
DECLARE_WAIT_QUEUE_HEAD(rfiles_wait);
atomic_t rfiles_freed;
extern unsigned long long rdentry_cnt;
extern spinlock_t rdentry_cnt_lock;
extern unsigned long long rinode_cnt;
extern spinlock_t rinode_cnt_lock;
extern unsigned long long rfile_cnt;
extern spinlock_t rfile_cnt_lock;

struct data *data_find(struct list_head *head, struct filter *flt)
{
	struct data *loop;
	struct data *found;

	found = NULL;

	list_for_each_entry(loop, head, list) {
		if (loop->filter == flt) {
			found = loop;
			break;
		}
	}

	return found;
}

int rfs_precall_flts(struct chain *chain, struct context *context, struct rfs_args *args, int *cnt)
{
	enum rfs_retv (**ops)(rfs_context, struct rfs_args *);
	enum rfs_retv (*op)(rfs_context, struct rfs_args *);
	int retv;
	int i;

	if (!chain)
		return 0;

	args->type.call = RFS_PRECALL;
	*cnt = chain->c_flts_nr;

	for (i = 0; i < chain->c_flts_nr; i++) {
		if (!atomic_read(&chain->c_flts[i]->f_active))
			continue;

		ops = chain->c_flts[i]->f_pre_cbs;
		op = ops[args->type.id];
		if (op) {
			retv = op(context, args);
			if (retv == RFS_STOP) {
				*cnt = i + 1;
				return -1;
			}
		}
	}

	return 0;
}

int rfs_postcall_flts(struct chain *chain, struct context *context, struct rfs_args *args, int *cnt)
{
	enum rfs_retv (**ops)(rfs_context, struct rfs_args *);
	enum rfs_retv (*op)(rfs_context, struct rfs_args *);
	int retv;
	int i;

	if (!chain)
		return 0;

	args->type.call = RFS_POSTCALL;

	for (i = *cnt - 1; i >= 0; i--) {
		if (!atomic_read(&chain->c_flts[i]->f_active))
			continue;

		ops = chain->c_flts[i]->f_post_cbs;
		op = ops[args->type.id];
		if (op) {
			retv = op(context, args);
			if (retv == RFS_STOP) {
				*cnt = i;
				return -1;
			}
		}
	}

	return 0;
}

int rfs_replace_ops(struct rpath *path_old, struct rpath *path_new)
{
	struct rdentry *rdentry;
	struct rinode *rinode;
	struct rfile *rfile;
	struct chain *chain;
	struct ops *ops;

	rdentry = rdentry_add(path_old->p_dentry);
	if (IS_ERR(rdentry))
		return PTR_ERR(rdentry);

	if (path_old->p_flags & RFS_PATH_SINGLE) {
		chain = path_new->p_inchain_local;
		ops = path_new->p_ops_local;

	} else {
		chain = path_new->p_inchain;
		ops = path_new->p_ops;
	}

	if (path_old == path_new)
		rdentry->rd_root = 1;
	else 
		rdentry->rd_root = 0;

	rdentry_set_ops(rdentry, ops);

	spin_lock(&rdentry->rd_lock);
	
	path_put(rdentry->rd_path);
	chain_put(rdentry->rd_chain);
	ops_put(rdentry->rd_ops);
	rdentry->rd_path = path_get(path_new);
	rdentry->rd_chain = chain_get(chain);
	rdentry->rd_ops = ops_get(ops);

	list_for_each_entry(rfile, &rdentry->rd_rfiles, rf_rdentry_list) {
		rfile_set_ops(rfile, ops);

		spin_lock(&rfile->rf_lock);

		path_put(rfile->rf_path);
		chain_put(rfile->rf_chain);
		rfile->rf_path = path_get(path_new);
		rfile->rf_chain = chain_get(chain);

		spin_unlock(&rfile->rf_lock);
	}

	spin_unlock(&rdentry->rd_lock);

	rinode = rdentry->rd_rinode;

	if (rinode) {
		rinode_set_ops(rinode, ops);

		spin_lock(&rinode->ri_lock);

		path_put(rinode->ri_path);
		chain_put(rinode->ri_chain);
		rinode->ri_path = path_get(path_new);
		rinode->ri_chain = chain_get(chain);

		spin_unlock(&rinode->ri_lock);
	}

	rdentry_put(rdentry);

	return 0;
}

int rfs_replace_ops_cb(struct dentry *dentry, void *data)
{
	struct rpath *path;
	struct rdentry *rdentry;
	struct rinode *rinode;
	struct rfile *rfile;

	path = (struct rpath *)data;
	rdentry = rdentry_add(dentry);

	if (IS_ERR(rdentry))
		return PTR_ERR(rdentry);

	rinode = rdentry->rd_rinode;
	
	if (rinode) {
		spin_lock(&rinode->ri_lock);

		path_put(rinode->ri_path_set);
		chain_put(rinode->ri_chain_set);
		ops_put(rinode->ri_ops_set);
		rinode->ri_path_set = path_get(path);
		rinode->ri_chain_set = chain_get(path->p_inchain);;
		rinode->ri_ops_set = ops_get(path->p_ops);

		spin_unlock(&rinode->ri_lock);
	}

	if (dentry == path->p_dentry) {
		rdentry->rd_root = 1;
		if (path->p_flags & RFS_PATH_SINGLE) {
			rdentry_put(rdentry);
			return 0;
		}

	} else if (rdentry->rd_root && list_empty(&rdentry->rd_path->p_rem)) {
		if (!(rdentry->rd_path->p_flags & RFS_PATH_SUBTREE)) {
			rdentry_put(rdentry);
			return 0;
		}

		rdentry_put(rdentry);
		return 1;
	} else
		rdentry->rd_root = 0;

	rdentry_set_ops(rdentry, path->p_ops);

	spin_lock(&rdentry->rd_lock);
	
	path_put(rdentry->rd_path);
	chain_put(rdentry->rd_chain);
	ops_put(rdentry->rd_ops);
	rdentry->rd_path = path_get(path);
	rdentry->rd_chain = chain_get(path->p_inchain);
	rdentry->rd_ops = ops_get(path->p_ops);

	list_for_each_entry(rfile, &rdentry->rd_rfiles, rf_rdentry_list) {
		rfile_set_ops(rfile, path->p_ops);

		spin_lock(&rfile->rf_lock);

		path_put(rfile->rf_path);
		chain_put(rfile->rf_chain);
		rfile->rf_path = path_get(path);
		rfile->rf_chain = chain_get(path->p_inchain);

		spin_unlock(&rfile->rf_lock);
	}

	spin_unlock(&rdentry->rd_lock);

	if (!rinode) {
		rdentry_put(rdentry);
		return 0;
	}

	rinode_set_ops(rinode, path->p_ops);

	spin_lock(&rinode->ri_lock);

	path_put(rinode->ri_path);
	chain_put(rinode->ri_chain);
	rinode->ri_path = path_get(path);
	rinode->ri_chain = chain_get(path->p_inchain);;

	spin_unlock(&rinode->ri_lock);

	rdentry_put(rdentry);

	return 0;
}

int rfs_restore_ops_cb(struct dentry *dentry, void *data)
{
	struct rfile *rfile;
	struct rfile *tmp;
	struct rdentry *rdentry;
	struct rpath *path;

	path = (struct rpath *)data;
	rdentry = rdentry_find(dentry);

	if (!rdentry)
		return 0;
	
	if (rdentry->rd_root) {
		if (dentry != path->p_dentry) {
			if (!(rdentry->rd_path->p_flags & RFS_PATH_SUBTREE)) {
				rdentry_put(rdentry);
				return 0;
			} else {
				rdentry_put(rdentry);
				return 1;
			}
		}
	}

	rdentry_del(dentry);

	spin_lock(&rdentry->rd_lock);
	list_for_each_entry_safe(rfile, tmp, &rdentry->rd_rfiles, rf_rdentry_list) {
		rfile_del(rfile->rf_file);
	}
	spin_unlock(&rdentry->rd_lock);


	rdentry_put(rdentry);

	return 0; 
}

int rfs_set_ops(struct dentry *dentry, struct rpath *path)
{
	struct rdentry *rdentry;
	struct rinode *rinode;
	struct rfile *rfile;
	struct ops *ops;

	rdentry = rdentry_find(dentry);
	rinode = rdentry->rd_rinode;

	ops = path->p_ops_local;
	rdentry_set_ops(rdentry, ops);

	spin_lock(&rdentry->rd_lock);
	ops_put(rdentry->rd_ops);
	rdentry->rd_ops = ops_get(ops);

	list_for_each_entry(rfile, &rdentry->rd_rfiles, rf_rdentry_list) {
		rfile_set_ops(rfile, ops);
	}

	spin_unlock(&rdentry->rd_lock);

	if (rinode)
		rinode_set_ops(rinode, ops);

	rdentry_put(rdentry);

	return RFS_ERR_OK;
}

int rfs_set_ops_cb(struct dentry *dentry, void *data)
{
	struct rpath *path = (struct rpath *)data;
	struct rdentry *rdentry = rdentry_find(dentry);
	struct rinode *rinode;
	struct rfile *rfile = NULL;


	if (!rdentry)
		return 0;

	rinode = rdentry->rd_rinode;

	if (rinode) {
		spin_lock(&rinode->ri_lock);
		ops_put(rinode->ri_ops_set);
		rinode->ri_ops_set = ops_get(path->p_ops);
		spin_unlock(&rinode->ri_lock);
	}

	if (rdentry->rd_root) {
		if (dentry == path->p_dentry) {
			if (path->p_flags & RFS_PATH_SINGLE) {
				rdentry_put(rdentry);
				return 0;
			}

		} else {
			if (!(rdentry->rd_path->p_flags & RFS_PATH_SUBTREE)) {
				rdentry_put(rdentry);
				return 0;
			}
			
			rdentry_put(rdentry);
			return 1;
		}
	}

	spin_lock(&rdentry->rd_lock);
	ops_put(rdentry->rd_ops);
	rdentry->rd_ops = ops_get(path->p_ops);
	spin_unlock(&rdentry->rd_lock);

	rdentry_set_ops(rdentry, path->p_ops);

	if (rinode) {
		spin_lock(&rinode->ri_lock);
		ops_put(rinode->ri_ops_set);
		rinode->ri_ops_set = ops_get(path->p_ops);
		spin_unlock(&rinode->ri_lock);

		rinode_set_ops(rinode, path->p_ops);
	}

	spin_lock(&rdentry->rd_lock);

	list_for_each_entry(rfile, &rdentry->rd_rfiles, rf_rdentry_list) {
		rfile_set_ops(rfile, path->p_ops);
	}

	spin_unlock(&rdentry->rd_lock);

	rdentry_put(rdentry);

	return 0;
}

struct entry {
	struct list_head e_list;
	struct dentry *e_dentry;
};

int rfs_walk_dcache(struct dentry *root,
		    int (*dcb)(struct dentry *dentry, void *dentry_data),
		    void *dcb_data,
		    int (*mcb)(struct dentry *dentry, void *dentry_data),
		    void *mcb_data)
{
	LIST_HEAD(dirs);
	LIST_HEAD(sibs);
	struct entry *dir;
	struct entry *sib;
	struct entry *tmp;
	struct entry *subdir;
	struct dentry *dentry;
	struct inode *inode;
	struct inode *itmp;
	struct list_head *head;
	int res;


	dir = kmalloc(sizeof(struct entry), GFP_KERNEL);
	if (!dir) {
		BUG();
		return -1;
	}

	INIT_LIST_HEAD(&dir->e_list);
	dir->e_dentry = dget(root);
	list_add_tail(&dir->e_list, &dirs);

	while (!list_empty(&dirs)) {
		dir = list_entry(dirs.next, struct entry, e_list);

		res = dcb(dir->e_dentry, dcb_data);

		if (res < 0)
			goto err;

		if (res > 0)
			goto next_dir;

		inode = dir->e_dentry->d_inode;
		if (!inode)
			goto next_dir;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
		down(&inode->i_sem);
#else
		mutex_lock(&inode->i_mutex);
#endif
		spin_lock(&dcache_lock);

		head = &dir->e_dentry->d_subdirs;
		INIT_LIST_HEAD(&sibs);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
		list_for_each_entry(dentry, head, d_child) {
#else
		list_for_each_entry(dentry, head, d_u.d_child) {
#endif
			spin_lock(&dentry->d_lock);
			if (d_unhashed(dentry)) {
				spin_unlock(&dentry->d_lock);
				continue;
			}

			atomic_inc(&dentry->d_count);
			spin_unlock(&dentry->d_lock);

			sib = kmalloc(sizeof(struct entry), GFP_ATOMIC);
			if (!sib)
				goto err_lock;

			INIT_LIST_HEAD(&sib->e_list);
			sib->e_dentry = dentry;
			list_add_tail(&sib->e_list, &sibs);
		}

		spin_unlock(&dcache_lock);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
		up(&inode->i_sem);
#else
		mutex_unlock(&inode->i_mutex);
#endif
		list_for_each_entry_safe(sib, tmp, &sibs, e_list) {
			dentry = sib->e_dentry;
			itmp = dentry->d_inode;

			if (!itmp || !S_ISDIR(itmp->i_mode)) {
				if (dcb(dentry, dcb_data))
					goto err;
				goto next_sib;
			}

			subdir = kmalloc(sizeof(struct entry), GFP_KERNEL);
			if (!subdir) 
				goto err;

			INIT_LIST_HEAD(&subdir->e_list);
			subdir->e_dentry = dget(dentry);
			list_add_tail(&subdir->e_list, &dirs);
next_sib:
			list_del(&sib->e_list);
			dput(sib->e_dentry);
			kfree(sib);
		}
next_dir:
		list_del(&dir->e_list);
		dput(dir->e_dentry);
		kfree(dir);
	}

	return 0;

err_lock:
	spin_unlock(&dcache_lock);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
	up(&inode->i_sem);
#else
	mutex_unlock(&inode->i_mutex);
#endif

err:
	BUG();
	list_splice(&sibs, &dirs);
	list_for_each_entry_safe(dir, tmp, &dirs, e_list) {
		dput(dir->e_dentry);
		list_del(&dir->e_list);
		kfree(dir);
	}

	return -1;
}

static int __init rfs_init(void)
{
	atomic_set(&rdentries_freed, 0);
	atomic_set(&rinodes_freed, 0);
	atomic_set(&rfiles_freed, 0);

	if (rdentry_cache_create())
		return -1;

	if (rinode_cache_create())
		goto rdentry_de;

	if (rfile_cache_create())
    goto rinode_de;

#ifdef CONFIG_PROC_FS
	if (rfs_proc_init())
    goto rfile_de;
#endif
  
	if (redirctl_init())
    goto rfs_proc_de;

	return 0;	

rfs_proc_de:
#ifdef CONFIG_PROC_FS
	rfs_proc_destroy();
#endif
rfile_de:
  rfile_cache_destroy();
rinode_de:
	rinode_cache_destroy();
rdentry_de:
  rdentry_cache_destroy();
  return -1;
}

static void __exit rfs_exit(void)
{
	unsigned long long rdcnt;
	unsigned long long ricnt;
	unsigned long long rfcnt;
	unsigned long flags;

	spin_lock_irqsave(&rdentry_cnt_lock, flags);
	if (!rdentry_cnt)
		atomic_set(&rdentries_freed, 1);
	else
		atomic_set(&rdentries_freed, 0);
	rdcnt = rdentry_cnt;
	spin_unlock_irqrestore(&rdentry_cnt_lock, flags);

	spin_lock_irqsave(&rinode_cnt_lock, flags);
	if (!rinode_cnt)
		atomic_set(&rinodes_freed, 1);
	else
		atomic_set(&rinodes_freed, 0);
	ricnt = rinode_cnt;
	spin_unlock_irqrestore(&rinode_cnt_lock, flags);

	spin_lock_irqsave(&rfile_cnt_lock, flags);
	if (!rfile_cnt)
		atomic_set(&rfiles_freed, 1);
	else
		atomic_set(&rfiles_freed, 0);
	rfcnt = rfile_cnt;
	spin_unlock_irqrestore(&rfile_cnt_lock, flags);

	rfs_debug("rdentry_cnt: %Ld\n", rdcnt);
	rfs_debug("rinode_cnt: %Ld\n", ricnt);
	rfs_debug("rfile_cnt: %Ld\n", rfcnt);

	wait_event_interruptible(rdentries_wait, atomic_read(&rdentries_freed));
	rdentry_cache_destroy();

	wait_event_interruptible(rinodes_wait, atomic_read(&rinodes_freed));
	rinode_cache_destroy();

	wait_event_interruptible(rfiles_wait, atomic_read(&rfiles_freed));
	rfile_cache_destroy();

#ifdef CONFIG_PROC_FS
	rfs_proc_destroy();
#endif
	redirctl_destroy();
}

module_init(rfs_init);
module_exit(rfs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frantisek Hrbata <franta@redirfs.org>");
MODULE_DESCRIPTION("RedirFS - VFS callback framework");
