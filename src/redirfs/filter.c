#include "redir.h"

static spinlock_t flt_list_lock = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(flt_list);
extern struct list_head path_rem_list;
extern struct mutex path_list_mutex;

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

	flt_name_len = strlen(flt_info->name);
	flt = kmalloc(sizeof(struct filter), GFP_KERNEL);
	flt_name = kmalloc(flt_name_len + 1, GFP_KERNEL);

	if (!flt || !flt_name) {
		kfree(flt);
		kfree(flt_name);
		return ERR_PTR(RFS_ERR_NOMEM);
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
	flt->mod_cb = NULL;
	
	if (flt_info->active)
		atomic_set(&flt->f_active, 1);
	else
		atomic_set(&flt->f_active, 0);

	return flt;
}

enum rfs_err rfs_register_filter(void **filter, struct rfs_filter_info *filter_info)
{
	struct filter *pos;
	struct filter *flt;

	if (!filter || !filter_info)
		return RFS_ERR_INVAL;

	flt = flt_alloc(filter_info);
	if (IS_ERR(flt))
		return PTR_ERR(flt);

	spin_lock(&flt_list_lock);

	list_for_each_entry(pos, &flt_list, f_list) {
		if (pos->f_priority == filter_info->priority ||
		    strcmp(pos->f_name, filter_info->name) == 0) {
			spin_unlock(&flt_list_lock);
			flt_put(flt);
			return RFS_ERR_EXIST;
		}
	}

	list_add_tail(&flt->f_list, &flt_list);

	spin_unlock(&flt_list_lock);

	*filter = flt;

	return RFS_ERR_OK;
}

enum rfs_err rfs_unregister_filter(void *filter)
{
	struct rpath *loop;
	struct rpath *tmp;
	struct filter *flt;
	struct filter *pos;
	int found = 0;
	int retv;

	if (!filter)
		return RFS_ERR_INVAL;

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
		return RFS_ERR_NOENT;
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
#if defined(RFS_DEBUG)
	path_dump();
#endif
	mutex_unlock(&path_list_mutex);

	wait_event_interruptible(flt->f_wait, atomic_read(&flt->f_del));

	kfree(flt->f_name);
	kfree(flt);

	if (retv) 
		return retv;

	return RFS_ERR_OK;
}

enum rfs_err rfs_activate_filter(rfs_filter filter)
{
	struct filter *flt;

	flt = (struct filter *)filter;
	if (!flt)
		return RFS_ERR_INVAL;

	atomic_set(&flt->f_active, 1);

	return RFS_ERR_OK;
}

enum rfs_err rfs_deactivate_filter(rfs_filter filter)
{
	struct filter *flt;

	flt = (struct filter *)filter;
	if (!flt)
		return RFS_ERR_INVAL;

	atomic_set(&flt->f_active, 0);

	return RFS_ERR_OK;
}

enum rfs_err rfs_set_operations(void *filter, struct rfs_op_info ops_info[])
{
	struct filter *flt = (struct filter *)filter;
	int i = 0;
	int retv;

	if (!flt)
		return RFS_ERR_INVAL;

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

enum rfs_err rfs_set_mod_cb(rfs_filter filter, enum rfs_err (*mod_cb)(union rfs_mod *))
{
	struct filter *flt = (struct filter *)filter;

	if (!flt)
		return RFS_ERR_INVAL;

	flt->mod_cb = mod_cb;

	return RFS_ERR_OK;
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
		return RFS_ERR_OK;

	if (path->p_flags & RFS_PATH_SINGLE) {
		ops = ops_alloc();
		if (IS_ERR(ops))
			return PTR_ERR(ops);

		chain_get_ops(path_go->p_inchain_local, ops->o_ops);
		ops_put(path_go->p_ops_local);
		path_go->p_ops_local = ops;
	}

	retv = rfs_replace_ops(path, path_go);

	if (retv)
		return retv;

	return RFS_ERR_OK;
}

int flt_rem_local(struct rpath *path, struct filter *flt)
{
	struct chain *inchain_local = NULL;
	struct chain *exchain_local = NULL;
	struct rpath *path_go = path;
	struct rpath *path_cmp = path;
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
		path->p_exchain = exchain_local;
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

	if (!inchain_local && (path->p_flags & RFS_PATH_SINGLE))
		return RFS_ERR_OK;


	if (!remove) {
		if (path->p_flags & RFS_PATH_SINGLE) {
			ops = ops_alloc();
			if (IS_ERR(ops))
				return PTR_ERR(ops);

			chain_get_ops(path_go->p_inchain, ops->o_ops);
			ops_put(path_go->p_ops_local);
			path_go->p_ops_local = ops;
		}
		retv = rfs_replace_ops(path, path_go);
	} else 
		retv = rfs_restore_ops_cb(path->p_dentry, path);


	if (retv)
		return retv;

	return RFS_ERR_OK;
}

int flt_add_cb(struct rpath *path, void *data)
{
	struct filter *flt;
	struct chain *inchain = NULL;
	struct chain *exchain = NULL;
	struct rpath *path_go = path;
	struct rpath *path_cmp = path->p_parent;
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
		return RFS_ERR_OK;

	if (path->p_flags & RFS_PATH_SUBTREE) {
		ops = ops_alloc();
		if (IS_ERR(ops))
			return PTR_ERR(ops);

		chain_get_ops(path_go->p_inchain, ops->o_ops);
		ops_put(path_go->p_ops);
		path_go->p_ops = ops;
	}

	retv = rfs_walk_dcache(path->p_dentry, rfs_replace_ops_cb, path_go, NULL, NULL);

	if (retv)
		return retv;

	return RFS_ERR_OK;
}

int flt_rem_cb(struct rpath *path, void *data)
{
	struct filter *flt;
	struct chain *inchain = NULL;
	struct chain *exchain = NULL;
	struct rpath *path_go = path;
	struct rpath *path_cmp = path->p_parent;
	struct ops *ops;
	int remove = 0;
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

	if (!inchain && (path->p_flags & RFS_PATH_SUBTREE))
		return RFS_ERR_OK;

	if (!remove) {
		if (path->p_flags & RFS_PATH_SUBTREE) {
			ops = ops_alloc();
			if (IS_ERR(ops))
				return PTR_ERR(ops);

			chain_get_ops(path_go->p_inchain, ops->o_ops);
			ops_put(path_go->p_ops);
			path_go->p_ops = ops;
		}

		retv = rfs_walk_dcache(path->p_dentry, rfs_replace_ops_cb, path_go, NULL, NULL);
	} else 
		retv = rfs_walk_dcache(path->p_dentry, rfs_restore_ops_cb, path, NULL, NULL);

	if (retv)
		return retv;

	return RFS_ERR_OK;
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

		return rfs_walk_dcache(path->p_dentry, rfs_set_ops_cb, path, NULL, NULL);
	}

	return RFS_ERR_OK;
}


int flt_proc_info(char *buf, int size)
{
	struct filter *flt;
	int len = 0;
	char active;


	if ((len + 36) > size)
		goto out;
	len += sprintf(buf + len, "%-10s\t%-10s\t%-10s\n", "name", "priority", "active");

	spin_lock(&flt_list_lock);

	list_for_each_entry(flt, &flt_list, f_list) {
		if ((len + strlen(flt->f_name) + 36) > size)
			goto out;
		active = atomic_read(&flt->f_active) ? 'y' : 'n';
		len += sprintf(buf + len, "%-10s\t%-10d\t%-10c\n", flt->f_name, flt->f_priority, active);
	}
out:
	spin_unlock(&flt_list_lock);
	return len;
}

int flt_get_by_name(rfs_filter *filter, char *name)
{
	struct filter *flt;
	int retval;

	spin_lock(&flt_list_lock);
	list_for_each_entry(flt, &flt_list, f_list){
		if (strcmp(flt->f_name, name) == 0){
			*filter = flt;
			goto ok;
		}
	}
	retval = -1;
	goto end;
ok:
	retval = 0;
end:
	spin_unlock(&flt_list_lock);
	return(retval);
}

int flt_get_all_infos(struct rfs_filter_info **filters_info, int *count)
{
	struct filter *flt;
	struct rfs_filter_info *filter_info;
	int i = 0;
	int namememlen;
	int retval;

	i = 0;
	spin_lock(&flt_list_lock);
        list_for_each_entry(flt, &flt_list, f_list){
		i++;
	}
	
	if (i > 0){
		*filters_info = (struct rfs_filter_info *) kmalloc(sizeof(struct rfs_filter_info) * i, GFP_KERNEL);
		if (!(*filters_info)){
			retval = -1;
			goto end;
		}

		i = 0;
		list_for_each_entry(flt, &flt_list, f_list){
			filter_info = &((*filters_info)[i]);
			namememlen = strlen(flt->f_name) + 1;
			filter_info->name = (char *) kmalloc(namememlen, GFP_KERNEL);
			if (!filter_info){
				retval = -1;
				goto cleanup;
			}
			memcpy(filter_info->name, flt->f_name, namememlen);
			filter_info->priority = flt->f_priority;
			filter_info->active = atomic_read(&flt->f_active);
			i++;
		}
	}

	retval = 0;
	*count = i;
	goto end;
cleanup:
	while(i-- > 0){
		filter_info = &((*filters_info)[i]);
		kfree(filter_info->name);
	}
	kfree(*filters_info);
	*filters_info = NULL;
end:
	spin_unlock(&flt_list_lock);
	return(retval);
}

enum rfs_err flt_execute_mod_cb(struct filter *flt, union rfs_mod *mod)
{
	if (!flt){
		return(RFS_ERR_NOENT);
	}
	if (flt->mod_cb){
		return(flt->mod_cb(mod));
	}
	return(RFS_ERR_OPNOTSUPP);
}

EXPORT_SYMBOL(rfs_register_filter);
EXPORT_SYMBOL(rfs_unregister_filter);
EXPORT_SYMBOL(rfs_activate_filter);
EXPORT_SYMBOL(rfs_deactivate_filter);
EXPORT_SYMBOL(rfs_set_operations);
EXPORT_SYMBOL(rfs_set_mod_cb);

