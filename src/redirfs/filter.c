#include "redir.h"

static spinlock_t flt_list_lock = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(flt_list);
extern struct list_head path_rem_list;
extern struct mutex path_list_mutex;
extern struct kset rfs_flt_kset;

struct filter *flt_get(struct filter *flt)
{
	unsigned long flags;

	spin_lock_irqsave(&flt->f_lock, flags);
	BUG_ON(!flt->f_count);
	flt->f_count++;
	spin_unlock_irqrestore(&flt->f_lock, flags);
	return flt;
}

void flt_put(struct filter *flt)
{
	unsigned long flags;
	int del;

	del = 0;

	if (!flt || IS_ERR(flt))
		return;

	spin_lock_irqsave(&flt->f_lock, flags);
	BUG_ON(!flt->f_count);
	flt->f_count--;
	if (!flt->f_count)
		del = 1;
	spin_unlock_irqrestore(&flt->f_lock, flags);

	if (!del)
		return;

	atomic_set(&flt->f_del, 1);
	wake_up_interruptible(&flt->f_wait);
}

struct filter *flt_alloc(struct rfs_filter_info *flt_info)
{
	struct filter *flt = NULL;
	char *flt_name = NULL;
	int flt_name_len = 0;
	enum rfs_retv (*op)(rfs_context, struct rfs_args *);
	int rv;

	flt_name_len = strlen(flt_info->name);
	flt = kmalloc(sizeof(struct filter), GFP_KERNEL);
	flt_name = kmalloc(flt_name_len + 1, GFP_KERNEL);

	if (!flt || !flt_name) {
		kfree(flt);
		kfree(flt_name);
		return ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(&flt->f_list);
	strncpy(flt_name, flt_info->name, flt_name_len);
	flt_name[flt_name_len] = 0;
	flt->f_name = flt_name;
	flt->f_priority = flt_info->priority;
	flt->f_count = 1;
	atomic_set(&flt->f_del, 0);
	spin_lock_init(&flt->f_lock);
	init_waitqueue_head(&flt->f_wait);
	memset(&flt->f_pre_cbs, 0, sizeof(op) * RFS_OP_END);
	memset(&flt->f_post_cbs, 0, sizeof(op) * RFS_OP_END);
	memset(&flt->f_kobj, 0, sizeof(struct kobject));
	flt->f_ctl_cb = flt_info->ctl_cb;
	
	if (flt_info->active)
		atomic_set(&flt->f_active, 1);
	else
		atomic_set(&flt->f_active, 0);

	flt->f_kobj.kset = &rfs_flt_kset;
	kobject_set_name(&flt->f_kobj, "%s", flt_name);
	if ((rv = kobject_register(&flt->f_kobj))) {
		kfree(flt_name);
		kfree(flt);
		return ERR_PTR(rv);
	}

	return flt;
}

int rfs_register_filter(void **filter, struct rfs_filter_info *filter_info)
{
	struct filter *pos;
	struct filter *flt;

	if (!filter || !filter_info)
		return -EINVAL;

	flt = flt_alloc(filter_info);
	if (IS_ERR(flt))
		return PTR_ERR(flt);

	spin_lock(&flt_list_lock);

	list_for_each_entry(pos, &flt_list, f_list) {
		if (pos->f_priority == filter_info->priority ||
		    strcmp(pos->f_name, filter_info->name) == 0) {
			spin_unlock(&flt_list_lock);
			flt_put(flt);
			return -EEXIST;
		}
	}

	list_add_tail(&flt->f_list, &flt_list);

	spin_unlock(&flt_list_lock);

	*filter = flt;

	return 0;
}

int rfs_unregister_filter(void *filter)
{
	struct rpath *loop;
	struct rpath *tmp;
	struct filter *flt;
	struct filter *pos;
	int found = 0;
	int retv;

	if (!filter)
		return -EINVAL;

	flt = (struct filter *)filter;

	spin_lock(&flt_list_lock);

	list_for_each_entry(pos, &flt_list, f_list) {
		if (pos == flt) {
			found = 1;
			break;
		}
	}

	if (!found) {
		spin_unlock(&flt_list_lock);
		return -ENOENT;
	}

	list_del(&flt->f_list);
	flt_put(flt);

	spin_unlock(&flt_list_lock);

	mutex_lock(&path_list_mutex);
	retv = rfs_path_walk(NULL, flt_rem_cb, flt);

	list_for_each_entry_safe(loop, tmp, &path_rem_list, p_rem) {
		list_del(&loop->p_rem);
		path_rem(loop);
	}

	mutex_unlock(&path_list_mutex);

	wait_event_interruptible(flt->f_wait, atomic_read(&flt->f_del));

	kobject_unregister(&flt->f_kobj);
	kfree(flt->f_name);
	kfree(flt);

	if (retv) 
		return retv;

	return 0;
}

int rfs_activate_filter(rfs_filter filter)
{
	struct filter *flt;

	flt = (struct filter *)filter;
	if (!flt)
		return -EINVAL;

	atomic_set(&flt->f_active, 1);

	return 0;
}

int rfs_deactivate_filter(rfs_filter filter)
{
	struct filter *flt;

	flt = (struct filter *)filter;
	if (!flt)
		return -EINVAL;

	atomic_set(&flt->f_active, 0);

	return 0;
}

int rfs_set_operations(void *filter, struct rfs_op_info ops_info[])
{
	struct filter *flt = (struct filter *)filter;
	int i = 0;
	int retv;

	if (!flt)
		return -EINVAL;

	while (ops_info[i].op_id != RFS_OP_END) {
		flt->f_pre_cbs[ops_info[i].op_id] = ops_info[i].pre_cb;
		flt->f_post_cbs[ops_info[i].op_id] = ops_info[i].post_cb;
		i++;
	}

	mutex_lock(&path_list_mutex);
	retv = rfs_path_walk(NULL, flt_set_ops_cb, flt);
	mutex_unlock(&path_list_mutex);

	return retv;
}

int flt_add_local(struct rpath *path, struct filter *flt)
{
	struct chain *inchain_local = NULL;
	struct chain *exchain_local = NULL;
	struct rpath *path_cmp = path;
	struct ops *ops = NULL;
	struct rpath *path_go = path;
	int retv;

	if (chain_find_flt(path->p_inchain_local, flt) == -1) {
		inchain_local = chain_add_flt(path->p_inchain_local, flt);
		if (IS_ERR(inchain_local))
			return PTR_ERR(inchain_local);

		chain_put(path->p_inchain_local);
		path->p_inchain_local = inchain_local;

		if (chain_find_flt(path->p_exchain_local, flt) != -1) {
			exchain_local = chain_rem_flt(path->p_exchain_local, flt);
			if (IS_ERR(exchain_local))
				return PTR_ERR(exchain_local);

			chain_put(path->p_exchain_local);
			path->p_exchain_local = exchain_local;
		}
	}

	while (path_cmp) {
		if (!(path_cmp->p_flags & RFS_PATH_SUBTREE))
			path_cmp = path_cmp->p_parent;
		
		else if (!list_empty(&path->p_rem))
			path_cmp = path_cmp->p_parent;
		
		else
			break;
	}

	if (path_cmp) {
		if (!chain_cmp(path_cmp->p_inchain, path->p_inchain_local) &&
		    !chain_cmp(path_cmp->p_exchain, path->p_exchain_local)) {

			chain_put(path->p_inchain_local);
			path->p_inchain_local = NULL;

			chain_put(path->p_exchain_local);
			path->p_exchain_local = NULL;

			ops_put(path->p_ops_local);
			path->p_ops_local = NULL;

			path->p_flags &= ~RFS_PATH_SINGLE;

			if (!(path->p_flags & RFS_PATH_SUBTREE))
				list_add_tail(&path->p_rem, &path_rem_list);

			path_go = path_cmp;
		}
	}

	if (!inchain_local && (path->p_flags & RFS_PATH_SINGLE))
		return 0;

	if (path->p_flags & RFS_PATH_SINGLE) {
		ops = ops_alloc();
		if (IS_ERR(ops))
			return PTR_ERR(ops);

		chain_get_ops(path_go->p_inchain_local, ops->o_ops);
		ops_put(path_go->p_ops_local);
		path_go->p_ops_local = ops;
	}

	retv = rfs_replace_ops(path, path_go, NULL);

	if (retv)
		return retv;

	return 0;
}

int flt_rem_local(struct rpath *path, struct filter *flt)
{
	struct chain *inchain_local = NULL;
	struct chain *exchain_local = NULL;
	struct rpath *path_go = path;
	struct rpath *path_cmp = path;
	struct dcache_data_cb data_cb;
	int inch_modified = 0;
	struct ops *ops = NULL;
	int aux = 0;
	int retv;
	int remove = 0;

	while (path_cmp) {
		if (!(path_cmp->p_flags & RFS_PATH_SUBTREE))
			path_cmp = path_cmp->p_parent;
		
		else if (!list_empty(&path_cmp->p_rem))
			path_cmp = path_cmp->p_parent;
		
		else
			break;
	}

	if (path_cmp)
		aux = chain_find_flt(path_cmp->p_inchain, flt) != -1 || 
		      chain_find_flt(path_cmp->p_exchain, flt) != -1;

	if (chain_find_flt(path->p_inchain_local, flt) != -1 &&
	    chain_find_flt(path->p_exchain_local, flt) == -1) {

		inch_modified = 1;
		inchain_local = chain_rem_flt(path->p_inchain_local, flt);
		if (IS_ERR(inchain_local))
			return PTR_ERR(inchain_local);

		chain_put(path->p_inchain_local);
		path->p_inchain_local = inchain_local;

		if (aux) {
			exchain_local = chain_add_flt(path->p_exchain_local, flt);
			if (IS_ERR(exchain_local))
				return PTR_ERR(exchain_local);
			
			chain_put(path->p_exchain_local);
			path->p_exchain_local = exchain_local;
		}
	}

	if (!aux && chain_find_flt(path->p_exchain_local, flt) != -1) {
		exchain_local = chain_rem_flt(path->p_exchain_local, flt);
		if (IS_ERR(exchain_local))
			return PTR_ERR(exchain_local);

		chain_put(path->p_exchain_local);
		path->p_exchain_local = exchain_local;
	}

	if (path_cmp) {
		if (!chain_cmp(path_cmp->p_inchain, path->p_inchain_local) &&
		    !chain_cmp(path_cmp->p_exchain, path->p_exchain_local)) {

			chain_put(path->p_inchain_local);
			path->p_inchain_local = NULL;

			chain_put(path->p_exchain_local);
			path->p_exchain_local = NULL;

			path_go = path_cmp;
		}
	}

	if (!path->p_inchain_local && !path->p_exchain_local) {
		path->p_flags &= ~RFS_PATH_SINGLE;
		ops_put(path->p_ops_local);
		path->p_ops_local = NULL;

		if (!(path->p_flags & RFS_PATH_SUBTREE)) 
			list_add_tail(&path->p_rem, &path_rem_list);

		if (!path_cmp)
			remove = 1;
	}

	if (!inch_modified && (path->p_flags & RFS_PATH_SINGLE))
		return 0;

	if (!remove) {
		if (path->p_flags & RFS_PATH_SINGLE) {
			ops = ops_alloc();
			if (IS_ERR(ops))
				return PTR_ERR(ops);

			chain_get_ops(path_go->p_inchain_local, ops->o_ops);
			ops_put(path_go->p_ops_local);
			path_go->p_ops_local = ops;
		}
		retv = rfs_replace_ops(path, path_go, flt);

	} else {
		
		data_cb.path = path;
		data_cb.filter = flt;

		retv = rfs_restore_ops_cb(path->p_dentry, path->p_mnt, &data_cb);
	}


	if (retv)
		return retv;

	return 0;
}

int flt_add_cb(struct rpath *path, void *data)
{
	struct filter *flt;
	struct chain *inchain = NULL;
	struct chain *exchain = NULL;
	struct rpath *path_go = path;
	struct rpath *path_cmp = path->p_parent;
	struct dcache_data_cb data_cb;
	struct ops *ops;
	int retv;

	flt = (struct filter *)data;

	if (!(path->p_flags & RFS_PATH_SUBTREE))
		return flt_add_local(path, flt);

	if (chain_find_flt(path->p_inchain, flt) == -1) {
		inchain = chain_add_flt(path->p_inchain, flt);
		if (IS_ERR(inchain))
			return PTR_ERR(inchain);

		chain_put(path->p_inchain);
		path->p_inchain = inchain;

		if (chain_find_flt(path->p_exchain, flt) != -1) {
			exchain = chain_rem_flt(path->p_exchain, flt);
			if (IS_ERR(exchain))
				return PTR_ERR(exchain);

			chain_put(path->p_exchain);
			path->p_exchain = exchain;
		}

		ops = ops_alloc();
		if (IS_ERR(ops))
			return PTR_ERR(ops);

		chain_get_ops(path->p_inchain, ops->o_ops);
		ops_put(path->p_ops);
		path->p_ops = ops;
	}

	if (path->p_flags & RFS_PATH_SINGLE) {
		retv = flt_add_local(path, flt);
		if (retv)
			return retv;
	}

	while (path_cmp) {
		if (!(path_cmp->p_flags & RFS_PATH_SUBTREE))
			path_cmp = path_cmp->p_parent;
		
		else if (!list_empty(&path_cmp->p_rem))
			path_cmp = path_cmp->p_parent;
		
		else
			break;
	}

	if (path_cmp) {
		if (!chain_cmp(path_cmp->p_inchain, path->p_inchain) &&
		    !chain_cmp(path_cmp->p_exchain, path->p_exchain)) {

			chain_put(path->p_inchain);
			path->p_inchain = NULL;

			chain_put(path->p_exchain);
			path->p_exchain = NULL;

			ops_put(path->p_ops);
			path->p_flags &= ~RFS_PATH_SUBTREE;

			if (!(path->p_flags & RFS_PATH_SINGLE))
				list_add_tail(&path->p_rem, &path_rem_list);

			path_go = path_cmp;
		}
	}

	if (!inchain && (path->p_flags & RFS_PATH_SUBTREE))
		return 0;

	data_cb.path = path_go;
	data_cb.filter = NULL;

	retv = rfs_walk_dcache(path->p_dentry, path->p_mnt, rfs_replace_ops_cb, &data_cb);

	if (retv)
		return retv;

	return 0;
}

int flt_rem_cb(struct rpath *path, void *data)
{
	struct filter *flt;
	struct chain *inchain = NULL;
	struct chain *exchain = NULL;
	struct rpath *path_go = path;
	struct rpath *path_cmp = path->p_parent;
	struct ops *ops;
	struct dcache_data_cb data_cb;
	int remove = 0;
	int inch_modified = 0;
	int aux = 0;
	int retv;

	flt = (struct filter *)data;

	if (!(path->p_flags & RFS_PATH_SUBTREE))
		return flt_rem_local(path, flt);

	while (path_cmp) {
		if (!(path_cmp->p_flags & RFS_PATH_SUBTREE))
			path_cmp = path_cmp->p_parent;
		
		else if (!list_empty(&path_cmp->p_rem))
			path_cmp = path_cmp->p_parent;
		
		else
			break;
	}

	if (path_cmp)
		aux = chain_find_flt(path_cmp->p_inchain, flt) != -1 || 
		      chain_find_flt(path_cmp->p_exchain, flt) != -1;

	if (chain_find_flt(path->p_exchain, flt) == -1 &&
	    chain_find_flt(path->p_inchain, flt) != -1) {

		inch_modified = 1;
		inchain = chain_rem_flt(path->p_inchain, flt);
		if (IS_ERR(inchain))
			return PTR_ERR(inchain);

		chain_put(path->p_inchain);
		path->p_inchain = inchain;

		if (aux) {
			exchain = chain_add_flt(path->p_exchain, flt);
			if (IS_ERR(exchain))
				return PTR_ERR(exchain);

			chain_put(path->p_exchain);
			path->p_exchain = exchain;
		}
	}
	
	if (!aux && chain_find_flt(path->p_exchain, flt) != -1) {
		exchain = chain_rem_flt(path->p_exchain, flt);
		if (IS_ERR(exchain))
			return PTR_ERR(exchain);

		chain_put(path->p_exchain);
		path->p_exchain = exchain;
	}

	if (path->p_flags & RFS_PATH_SINGLE) {
		retv = flt_rem_local(path, flt);
		if (retv)
			return retv;
	}

	if (path_cmp) {
		if (!chain_cmp(path_cmp->p_inchain, path->p_inchain) &&
		    !chain_cmp(path_cmp->p_exchain, path->p_exchain)) {

			chain_put(path->p_inchain);
			path->p_inchain = NULL;

			chain_put(path->p_exchain);
			path->p_exchain = NULL;

			path_go = path_cmp;
		}
	}

	if (!path->p_inchain && !path->p_exchain) {
		path->p_flags &= ~RFS_PATH_SUBTREE;
		ops_put(path->p_ops);
		path->p_ops = NULL;

		if (!(path->p_flags & RFS_PATH_SINGLE))
			list_add_tail(&path->p_rem, &path_rem_list);

		if (!path_cmp)
			remove = 1;
	}

	if (!inch_modified && (path->p_flags & RFS_PATH_SUBTREE))
		return 0;

	if (!remove) {
		if (path->p_flags & RFS_PATH_SUBTREE) {
			ops = ops_alloc();
			if (IS_ERR(ops))
				return PTR_ERR(ops);

			chain_get_ops(path_go->p_inchain, ops->o_ops);
			ops_put(path_go->p_ops);
			path_go->p_ops = ops;
		}

		data_cb.path = path_go;
		data_cb.filter = flt;

		retv = rfs_walk_dcache(path->p_dentry, path->p_mnt, rfs_replace_ops_cb, &data_cb);

	} else {
		data_cb.path = path;
		data_cb.filter = flt;

		retv = rfs_walk_dcache(path->p_dentry, path->p_mnt, rfs_restore_ops_cb, &data_cb);
	}

	if (retv)
		return retv;

	return 0;
}

int flt_set_ops_cb(struct rpath *path, void *data)
{
	struct filter *flt;
	struct ops *ops;
	int err;

	flt = (struct filter *)data;

	if (chain_find_flt(path->p_inchain_local, flt) != -1) {
		ops = ops_alloc();
		if (IS_ERR(ops))
			return PTR_ERR(ops);
		chain_get_ops(path->p_inchain_local, ops->o_ops);
		ops_put(path->p_ops_local);
		path->p_ops_local = ops;

		err = rfs_set_ops(path->p_dentry, path);
		if (err)
			return err;
	}

	if (chain_find_flt(path->p_inchain, flt) != -1) {
		ops = ops_alloc();
		if (IS_ERR(ops))
			return PTR_ERR(ops);
		chain_get_ops(path->p_inchain, ops->o_ops);
		ops_put(path->p_ops);
		path->p_ops = ops;

		return rfs_walk_dcache(path->p_dentry, path->p_mnt, rfs_set_ops_cb, path);
	}

	return 0;
}

EXPORT_SYMBOL(rfs_register_filter);
EXPORT_SYMBOL(rfs_unregister_filter);
EXPORT_SYMBOL(rfs_activate_filter);
EXPORT_SYMBOL(rfs_deactivate_filter);
EXPORT_SYMBOL(rfs_set_operations);

