#include "redir.h"

LIST_HEAD(path_list);
LIST_HEAD(path_rem_list);
DEFINE_MUTEX(path_list_mutex);

int path_normalize(const char *path, char *buf, int len)
{
	int path_len;
	const char *s;
	char *d;

	if (!path)
		return RFS_ERR_INVAL;

	s = path;
	d = buf;
	path_len = strlen(path);
	if (path_len >= len)
		return RFS_ERR_NAMETOOLONG;

	if (*s != '/')
		return RFS_ERR_INVAL;

	while (*s == '/')
		s++;
	*d++ = '/';

	while (*s) {
		while (*s && (*s != '/'))
			*d++ = *s++;

		while (*s == '/')
			s++;

		if (*s)
			*d++ = '/';
	}
	
	*d = '\0';

	return 0;
}

struct path *path_alloc(const char *path_name)
{
	struct nameidata nd;
	struct path *path;
	char *path_buf;
	int path_len;

	if (!path_name)
		return ERR_PTR(RFS_ERR_INVAL);

	if (path_lookup(path_name, LOOKUP_FOLLOW, &nd))
		return ERR_PTR(RFS_ERR_NOENT);

	path_len = strlen(path_name);

	path = kmalloc(sizeof(struct path), GFP_KERNEL);
	path_buf = kmalloc(path_len + 1, GFP_KERNEL);

	if (!path || !path_buf) {
		path_release(&nd);
		kfree(path);
		kfree(path_buf);
		return ERR_PTR(RFS_ERR_NOMEM);
	}
	
	strncpy(path_buf, path_name, path_len);
	path_buf[path_len] = 0;

	path->p_inchain = NULL;
	path->p_exchain = NULL;
	path->p_inchain_local = NULL;
	path->p_exchain_local = NULL;
	path->p_dentry = dget(nd.dentry);
	path->p_path = path_buf;
	path->p_len = path_len;
	path->p_parent = NULL;
	path->p_count = 1;
	path->p_flags = 0;
	path->p_ops = NULL;
	path->p_ops_local = NULL;
	spin_lock_init(&path->p_lock);
	INIT_LIST_HEAD(&path->p_sibpath);
	INIT_LIST_HEAD(&path->p_subpath);
	INIT_LIST_HEAD(&path->p_rem);

	path_release(&nd);

	return path;
}

struct path *path_get(struct path *path)
{
	unsigned long flags;

	if (!path)
		return NULL;

	spin_lock_irqsave(&path->p_lock, flags);
	BUG_ON(!path->p_count);
	path->p_count++;
	spin_unlock_irqrestore(&path->p_lock, flags);

	return path;
}

void path_put(struct path *path)
{
	unsigned long flags;

	int del = 0;

	if (!path || IS_ERR(path))
		return;

	spin_lock_irqsave(&path->p_lock, flags);
	BUG_ON(!path->p_count);
	path->p_count--;
	if (!path->p_count)
		del = 1;
	spin_unlock_irqrestore(&path->p_lock, flags);

	if (!del)
		return;

	path_put(path->p_parent);
	dput(path->p_dentry);
	kfree(path->p_path);
	kfree(path);
}

struct path *path_find(const char *path_name, int parent)
{
	struct list_head *end;
	struct list_head *act;
	struct path *loop;
	struct path *found = NULL;
	int path_len;

	end = &path_list;
	act = end->next;

	path_len = strlen(path_name);

	while (act != end) {
		loop = list_entry(act, struct path, p_sibpath);

		if (loop->p_len > path_len) {
			act = act->next;
			continue;
		}

		if (!strncmp(loop->p_path, path_name, loop->p_len)) {
			if (parent && (loop->p_flags & RFS_PATH_SUBTREE)) 
				found = loop;

			else if (path_len == loop->p_len) {

				found = loop;
				break;
			}

			act = end = &loop->p_subpath;
		}

		act = act->next;
	}

	if (found)
		found = path_get(found);

	return found;
}

struct path *path_add(const char *path_name)
{
	struct path *path;
	struct path *parent;
	struct path *loop;
	struct list_head *head;
	struct list_head *act;
	struct list_head *tmp;
	int path_len;

	path = path_find(path_name, 0);

	if (path) 
		return path;

	path = path_alloc(path_name);

	if (IS_ERR(path))
		return path;

	path_len = strlen(path_name);
	parent = path_find(path_name, 1);

	if (parent)
		head = &parent->p_subpath;
	else
		head = &path_list;

	list_for_each_safe(act, tmp, head) {
		loop = list_entry(act, struct path, p_sibpath);

		if (loop->p_len < path_len)
			continue;

		if (!strncmp(loop->p_path, path_name, path_len)) {
			list_move(&loop->p_sibpath, &path->p_subpath);
			path_put(loop->p_parent);
			loop->p_parent = path_get(path);
		}
	}

	path->p_parent = path_get(parent);
	list_add(&path->p_sibpath, head);

	path_get(path);
	path_put(parent);

	return path;
}

void path_rem(struct path *path)
{
	struct list_head *act;
	struct list_head *tmp;
	struct list_head *dst;
	struct path *loop;
	struct path *parent;

	parent = path->p_parent;

	if (parent)
		dst = &parent->p_subpath;
	else
		dst = &path_list;

	list_for_each_safe(act, tmp, &path->p_subpath) {
		loop = list_entry(act, struct path, p_sibpath);
		list_move(&loop->p_sibpath, dst);
		path_put(loop->p_parent);
		path_get(path->p_parent);
	}

	list_del(&path->p_sibpath);
	path_put(parent);
	path_put(path);
}

int rfs_path_walk(struct path *path, int walkcb(struct path*, void*), void *datacb)
{
	struct list_head *act;
	struct list_head *end;
	struct list_head *par;
	struct path *loop;
	int stop;


	if (path)
		end = &path->p_subpath;
	else
		end = &path_list;

	act = par = end->next;

	if (path) {
		stop = walkcb(path, datacb);
		if (stop)
			return stop;
	}

	while (act != end) {
		loop = list_entry(act, struct path, p_sibpath);
		stop = walkcb(loop, datacb);

		if (stop)
			return stop;

		if (!list_empty(&loop->p_subpath))
			act = par = &loop->p_subpath;

		act = act->next;

		while (act == par && act != end) {
			loop = loop->p_parent;
			par = &loop->p_parent->p_subpath;
			act = loop->p_sibpath.next;
		}
			
	}

	return 0;
}

#if defined(RFS_DEBUG)
static int path_dump_cb(struct path *path, void *data)
{
	struct filter *flt;
	int i;
	char active;


	rfs_debug("+++ path: %s +++\n", path->p_path);

	rfs_debug("inchain %p:",path->p_inchain);
	if (path->p_inchain) {
		for (i = 0; i < path->p_inchain->c_flts_nr; i++) {
			flt = path->p_inchain->c_flts[i];
			active = atomic_read(&flt->f_active) ? 'y' : 'n';
			rfs_debug(" -> %s(g,+,%c,%d)", flt->f_name, active, flt->f_priority);
		}
	}
	rfs_debug("\n");

	rfs_debug("exchain %p:",path->p_exchain);
	if (path->p_exchain) {
		for (i = 0; i < path->p_exchain->c_flts_nr; i++) {
			flt = path->p_exchain->c_flts[i];
			active = atomic_read(&flt->f_active) ? 'y' : 'n';
			rfs_debug(" -> %s(g,+,%c,%d)", flt->f_name, active, flt->f_priority);
		}
	}
	rfs_debug("\n");

	rfs_debug("inchain_local %p:", path->p_inchain_local);
	if (path->p_inchain_local) {
		for (i = 0; i < path->p_inchain_local->c_flts_nr; i++) {
			flt = path->p_inchain_local->c_flts[i];
			active = atomic_read(&flt->f_active) ? 'y' : 'n';
			rfs_debug(" -> %s(l,+,%c,%d)", flt->f_name, active, flt->f_priority);
		}
	}
	rfs_debug("\n");

	rfs_debug("exchain_local %p:", path->p_exchain_local);
	if (path->p_exchain_local) {
		for (i = 0; i < path->p_exchain_local->c_flts_nr; i++) {
			flt = path->p_exchain_local->c_flts[i];
			active = atomic_read(&flt->f_active) ? 'y' : 'n';
			rfs_debug(" -> %s(l,+,%c,%d)", flt->f_name, active, flt->f_priority);
		}
	}
	rfs_debug("\n");

	rfs_debug("--- path: %s ---\n", path->p_path);

	return 0;
}

void path_dump(void)
{
	rfs_debug("++++++++++ paths dump ++++++++++\n");

	rfs_path_walk(NULL, path_dump_cb, NULL);

	rfs_debug("---------- paths dump ----------\n");
}
#endif


enum rfs_err rfs_set_path(rfs_filter filter, struct rfs_path_info *path_info)
{
	struct filter *flt = (struct filter *)filter;
	struct path *path = NULL;
	struct path *parent = NULL;
	struct path *loop;
	struct path *tmp;
	struct chain *inchain = NULL;
	struct chain *exchain = NULL;
	char *path_name = NULL;
	struct nameidata nd;
	int retv = RFS_ERR_OK;
	int path_len;

	if (!flt || !path_info)
		return RFS_ERR_INVAL;

	if (!(path_info->flags & (RFS_PATH_SINGLE | RFS_PATH_SUBTREE)))
		return RFS_ERR_INVAL;

	if (!(path_info->flags & (RFS_PATH_INCLUDE | RFS_PATH_EXCLUDE)))
		return RFS_ERR_INVAL;

	if (path_lookup(path_info->path, LOOKUP_FOLLOW, &nd))
		return RFS_ERR_NOENT;

	if (path_info->flags & RFS_PATH_SUBTREE) {
		if (!S_ISDIR(nd.dentry->d_inode->i_mode)) {
			path_release(&nd);
			return RFS_ERR_NOTDIR;
		}
	}

	path_release(&nd);

	path_len = strlen(path_info->path) + 1;
	path_name = kmalloc(path_len, GFP_KERNEL);

	if (!path_name)
		return RFS_ERR_NOMEM;
	
	retv = path_normalize(path_info->path, path_name, path_len);
	if (retv) {
		kfree(path_name);
		return retv;
	}

	mutex_lock(&path_list_mutex);

	path = path_find(path_name, 0);
	parent = path_find(path_name, 1);

	if (path) {
		if (path_info->flags & RFS_PATH_SINGLE) {
			if (!(path->p_flags & RFS_PATH_SINGLE)) {
				if (path->p_flags & RFS_PATH_SUBTREE) {
					inchain = chain_copy(path->p_inchain);
					exchain = chain_copy(path->p_exchain);

				} else if (parent) {
					inchain = chain_copy(parent->p_inchain);
					exchain = chain_copy(parent->p_exchain);
				}

				if (IS_ERR(inchain)) {
					retv = PTR_ERR(inchain);
					goto exit;
				}

				if (IS_ERR(exchain)) {
					retv = PTR_ERR(exchain);
					goto exit;
				}

				path->p_inchain_local = chain_get(inchain);
				path->p_exchain_local = chain_get(exchain);
				path->p_flags |= RFS_PATH_SINGLE;
			}

		} else { 
			if (parent && !(path->p_flags & RFS_PATH_SUBTREE)) {
				inchain = chain_copy(parent->p_inchain);
				if (IS_ERR(inchain)) {
					retv = PTR_ERR(inchain);
					goto exit;
				}

				exchain = chain_copy(parent->p_exchain);
				if (IS_ERR(exchain)) {
					retv = PTR_ERR(exchain);
					goto exit;
				}

				path->p_inchain = chain_get(inchain);
				path->p_exchain = chain_get(exchain);
				path->p_flags |= RFS_PATH_SUBTREE;
			}
		}
	}

	if (!path && parent) {
		if (path_info->flags & RFS_PATH_INCLUDE) {
			if (chain_find_flt(parent->p_inchain, flt) != -1)
				path = path_get(parent);

		} else {
			if (chain_find_flt(parent->p_exchain, flt) != -1)
				path = path_get(parent);
		}
	}

	if (!path) {
		path = path_add(path_name);
		if (IS_ERR(path)) {
			retv = PTR_ERR(path);
			goto exit;
		}

		if (path_info->flags & RFS_PATH_SINGLE)
			path->p_flags |= RFS_PATH_SINGLE;
		else
			path->p_flags |= RFS_PATH_SUBTREE;

		if (parent) {
			inchain = chain_copy(parent->p_inchain);
			if (IS_ERR(inchain)) {
				retv = PTR_ERR(inchain);
				goto exit;
			}

			exchain = chain_copy(parent->p_exchain);
			if (IS_ERR(exchain)) {
				retv = PTR_ERR(exchain);
				goto exit;
			}

			if (path->p_flags & RFS_PATH_SINGLE) {
				path->p_inchain_local = chain_get(inchain);
				path->p_exchain_local = chain_get(exchain);

			} else {
				path->p_inchain = chain_get(inchain);
				path->p_exchain = chain_get(exchain);
			}
		}
	}

	if (path_info->flags & RFS_PATH_SINGLE)
		if (path_info->flags & RFS_PATH_INCLUDE)
			retv = flt_add_local(path, flt);
		else
			retv = flt_rem_local(path, flt);
	else 
		if (path_info->flags & RFS_PATH_INCLUDE)
			retv = rfs_path_walk(path, flt_add_cb, flt);
		else
			retv = rfs_path_walk(path, flt_rem_cb, flt);

	list_for_each_entry_safe(loop, tmp, &path_rem_list, p_rem) {
		list_del(&loop->p_rem);
		path_rem(loop);
	}

#if defined(RFS_DEBUG)
	path_dump();
#endif
exit:
	chain_put(inchain);
	chain_put(exchain);
	path_put(path);
	path_put(parent);
	kfree(path_name);
	mutex_unlock(&path_list_mutex);

	return retv;
}

struct path_proc_data {
	char *buf;
	int size;
	int len;

};

static int path_proc_info_cb(struct path *path, void *data)
{
	struct path_proc_data *info = NULL;
	struct filter *flt = NULL;
	char active;
	int i = 0;


	info = (struct path_proc_data *)data;

	if ((info->len + strlen(path->p_path) + 1) > info->size)
		return -1;

	info->len += sprintf(info->buf + info->len, "%s", path->p_path);

	if (path->p_inchain) {
		for (i = 0; i < path->p_inchain->c_flts_nr; i++) {
			flt = path->p_inchain->c_flts[i];
			if ((info->len + strlen(flt->f_name) + 16) > info->size)
				return -1;

			active = atomic_read(&flt->f_active) ? 'y' : 'n';
			info->len += sprintf(info->buf + info->len, " -> %s(g,+,%c,%d)", flt->f_name, active, flt->f_priority);
		}
	}

	if (path->p_exchain) {
		for (i = 0; i < path->p_exchain->c_flts_nr; i++) {
			flt = path->p_exchain->c_flts[i];
			if ((info->len + strlen(flt->f_name) + 16) > info->size)
				return -1;

			active = atomic_read(&flt->f_active) ? 'y' : 'n';
			info->len += sprintf(info->buf + info->len, " -> %s(g,-,%c,%d)", flt->f_name, active, flt->f_priority);
		}
	}

	if (path->p_inchain_local) {
		for (i = 0; i < path->p_inchain_local->c_flts_nr; i++) {
			flt = path->p_inchain_local->c_flts[i];
			if ((info->len + strlen(flt->f_name) + 16) > info->size)
				return -1;

			active = atomic_read(&flt->f_active) ? 'y' : 'n';
			info->len += sprintf(info->buf + info->len, " -> %s(l,+,%c,%d)", flt->f_name, active, flt->f_priority);
		}
	}

	if (path->p_exchain_local) {
		for (i = 0; i < path->p_exchain_local->c_flts_nr; i++) {
			flt = path->p_exchain_local->c_flts[i];
			if ((info->len + strlen(flt->f_name) + 16) > info->size)
				return -1;

			active = atomic_read(&flt->f_active) ? 'y' : 'n';
			info->len += sprintf(info->buf + info->len, " -> %s(l,-,%c,%d)", flt->f_name, active, flt->f_priority);
		}
	}

	info->len += sprintf(info->buf + info->len, "\n");

	return 0;
}               

int path_proc_info(char *buf, int size)
{               
	struct path_proc_data info = {buf, size, 0};

	mutex_lock(&path_list_mutex);
	rfs_path_walk(NULL, path_proc_info_cb, &info);
	mutex_unlock(&path_list_mutex);

	return info.len;
}

EXPORT_SYMBOL(rfs_set_path);
