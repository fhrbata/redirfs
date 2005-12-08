#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/smp_lock.h>
#include <linux/list.h>
#include "root.h"
#include "filter.h"
#include "operations.h"
#include "inode.h"
#include "file.h"
#include "debug.h"

extern struct redirfs_operations_t redirfs_fw_ops;
static spinlock_t redirfs_root_list_lock = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(redirfs_root_list);
static spinlock_t redirfs_remove_roots_list_lock = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(redirfs_remove_roots_list);

static struct redirfs_root_t *redirfs_alloc_root(const char *path)
{
	struct redirfs_root_t *root;
	struct nameidata nd;
	char *root_path;
	size_t root_path_len;
	int err;


	redirfs_debug("started");

	if (!path)
		return ERR_PTR(-EINVAL);

	root_path_len = strlen(path);

	err = path_lookup(path, LOOKUP_FOLLOW, &nd);
	if (err)
		return ERR_PTR(err);

	if (!S_ISDIR(nd.dentry->d_inode->i_mode))
		return ERR_PTR(-ENOTDIR);

	root = kmalloc(sizeof(struct redirfs_root_t), GFP_KERNEL);
	root_path = kmalloc(root_path_len + 1, GFP_KERNEL);

	if (!root || !root_path) {
		kfree(root);
		kfree(root_path);
		return ERR_PTR(-ENOMEM);
	}

	redirfs_flt_arr_init(&root->attached_flts);
	redirfs_flt_arr_init(&root->detached_flts);

	err = redirfs_flt_arr_create(&root->attached_flts,
				REDIRFS_DEFAULT_ROOT_FLT_NUM); 
	if (err) 
		return ERR_PTR(err);

	err = redirfs_flt_arr_create(&root->detached_flts,
				REDIRFS_DEFAULT_ROOT_FLT_NUM); 
	if (err) 
		return ERR_PTR(err);

	strncpy(root_path, path, root_path_len + 1);

	root->dentry = dget(nd.dentry);
	root->path = root_path;
	root->fw_ops = &redirfs_fw_ops;
	root->parent = NULL;
	root->ref_cnt = 1;
	root->flags = 0;
	spin_lock_init(&root->lock);

	INIT_LIST_HEAD(&root->subroots);
	INIT_LIST_HEAD(&root->sibroots);
	INIT_LIST_HEAD(&root->files);

	redirfs_init_ops(&root->new_ops, &root->vfs_ops);
	redirfs_init_orig_ops(&root->orig_ops);
	redirfs_init_cnts(&root->new_ops_cnts);


	if (root->dentry && root->dentry->d_op) {
		root->orig_ops.dops = root->dentry->d_op;
		memcpy(root->new_ops.dops, root->dentry->d_op, sizeof(struct dentry_operations));

		root->new_ops.dops->d_iput = root->fw_ops->dops->d_iput;
		redirfs_init_dops_arr(root->orig_ops.dops_arr, root->orig_ops.dops);
	} else
		root->new_ops.dops->d_iput = root->fw_ops->dops->d_iput;

	redirfs_debug("ended");

	return root;
}

static struct redirfs_root_t *__redirfs_rget(struct redirfs_root_t *root)
{
	if (!root)
		return NULL;

	if (!root->ref_cnt)
		BUG();
	root->ref_cnt += 1;

	return root;
}

struct redirfs_root_t *redirfs_rget(struct redirfs_root_t *root)
{
	struct redirfs_root_t *rv;
	redirfs_debug("started");

	if (!root)
		return NULL;

	spin_lock(&root->lock);
	
	rv = __redirfs_rget(root);

	spin_unlock(&root->lock);

	redirfs_debug("ended");

	return rv;
}

void redirfs_rput(struct redirfs_root_t *root)
{
	int not_used = 0;

	
	redirfs_debug("started");

	if (!root)
		return;

	spin_lock(&root->lock);
	root->ref_cnt -= 1;
	if (!root->ref_cnt)
		not_used = 1;
	spin_unlock(&root->lock);

	if (!not_used)
		return;

	redirfs_rput(root->parent);
	dput(root->dentry);
	kfree(root->path);
	redirfs_flt_arr_destroy(&root->attached_flts);
	redirfs_flt_arr_destroy(&root->detached_flts);
	kfree(root);
	
	redirfs_debug("ended");
}

static struct redirfs_root_t *__redirfs_find_root_parent(struct redirfs_root_t *root)
{
	struct redirfs_root_t *parent = NULL;
	struct redirfs_root_t *loop = NULL;
	size_t path_len = 0;
	size_t loop_len = 0;
	struct list_head *end;
	struct list_head *act;


	redirfs_debug("started");

	path_len = strlen(root->path);

	end = &redirfs_root_list;
	act = end->next;

	while (act != end) {
		loop = list_entry(act, struct redirfs_root_t, sibroots);
		loop_len = strlen(loop->path);

		if (loop_len > path_len) {
			act = act->next;
			continue;
		}

		if (!strncmp(loop->path, root->path, loop_len)) {
			end = &loop->subroots;
			act = end;
			parent = loop;
		}

		act = act->next;
	}

	redirfs_debug("ended");

	return parent;
}

static struct redirfs_root_t *redirfs_find_root_parent(struct redirfs_root_t *root)
{
	struct redirfs_root_t *parent;


	spin_lock(&redirfs_root_list_lock);
	parent = __redirfs_find_root_parent(root);
	spin_unlock(&redirfs_root_list_lock);

	return parent;
}

static struct redirfs_root_t *__redirfs_find_root(const char *path)
{
	struct redirfs_root_t *found = NULL;
	struct redirfs_root_t *loop = NULL;
	size_t path_len = 0;
	size_t loop_len = 0;
	struct list_head *end;
	struct list_head *act;


	redirfs_debug("started");

	path_len = strlen(path);

	end = &redirfs_root_list;
	act = end->next;

	while ((act != end) && !found) {
		loop = list_entry(act, struct redirfs_root_t, sibroots);

		loop_len = strlen(loop->path);

		if (loop_len > path_len) {
			act = act->next;
			continue;
		}

		if (!strncmp(loop->path, path, loop_len)) {
			if (path_len == loop_len)
				found = redirfs_rget(loop);

			end = &loop->subroots;
			act = end;
		}

		act = act->next;
	}

	redirfs_debug("ended");

	return found;
}

static struct redirfs_root_t *redirfs_find_root(const char *path)
{
	struct redirfs_root_t *root;


	redirfs_debug("started");

	spin_lock(&redirfs_root_list_lock);
	root = __redirfs_find_root(path);
	spin_unlock(&redirfs_root_list_lock);

	redirfs_debug("ended");

	return root;
}

static int redirfs_inherit_root(struct redirfs_root_t *par, struct redirfs_root_t *child)
{
	int rv = 0;


	spin_lock(&par->lock);
	spin_lock(&child->lock);

	memcpy(&child->vfs_ops, &par->vfs_ops, sizeof(struct redirfs_vfs_operations_t));
	memcpy(&child->new_ops_cnts, &par->new_ops_cnts, sizeof(struct redirfs_operations_counters_t));

	child->orig_ops.reg_iops = par->orig_ops.reg_iops;
	child->orig_ops.reg_fops = par->orig_ops.reg_fops;
	child->orig_ops.dir_iops = par->orig_ops.dir_iops;
	child->orig_ops.dir_fops = par->orig_ops.dir_fops;
	child->orig_ops.dops = par->orig_ops.dops;

	if (child->orig_ops.dops)
		redirfs_init_dops_arr(child->orig_ops.dops_arr, child->orig_ops.dops);

	if (child->orig_ops.reg_iops) {
		redirfs_init_iops_arr(child->orig_ops.reg_iops_arr, child->orig_ops.reg_iops); 
		redirfs_init_fops_arr(child->orig_ops.reg_fops_arr, child->orig_ops.reg_fops); 
	}

	if (child->orig_ops.dir_iops) {
		redirfs_init_iops_arr(child->orig_ops.dir_iops_arr, child->orig_ops.dir_iops); 
		redirfs_init_fops_arr(child->orig_ops.dir_fops_arr, child->orig_ops.dir_fops); 
	}

	if (redirfs_flt_arr_copy(&par->attached_flts, &child->attached_flts) ||
	    redirfs_flt_arr_copy(&par->attached_flts, &child->attached_flts)) 
		rv = -ENOMEM;

	spin_unlock(&child->lock);
	spin_unlock(&par->lock);

	return rv;
}

static struct redirfs_root_t *redirfs_add_root(struct redirfs_root_t *root)
{
	struct redirfs_root_t *ret_root = root;
	struct redirfs_root_t *new_root;
	struct redirfs_root_t *parent;
	struct list_head *end;
	struct list_head *act;
	struct redirfs_root_t *loop;
	size_t loop_len;
	size_t path_len;
	int rv = 0;

	
	redirfs_debug("started");

	spin_lock(&redirfs_root_list_lock);

	new_root = __redirfs_find_root(root->path);

	if (new_root) {
		ret_root = new_root;
		goto ret;
	}

	parent = __redirfs_find_root_parent(root);

	if (parent) {
		rv = redirfs_inherit_root(parent, root);
		if (rv) {
			ret_root = ERR_PTR(rv);
			goto ret;
		}

		end = &parent->subroots;
	} else
		end = &redirfs_root_list;

	act = end->next;
	path_len = strlen(root->path);

	while (act != end) {
		loop = list_entry(act, struct redirfs_root_t, sibroots);
		loop_len = strlen(loop->path);

		if (loop_len < path_len) {
			act = act->next;
			continue;
		}

		if (!strncmp(loop->path, root->path, path_len)) {
			act = act->next;
			list_move(&loop->sibroots, &root->subroots);
			redirfs_rput(loop->parent);
			spin_lock(&loop->lock);
			loop->parent = redirfs_rget(root);
			spin_unlock(&loop->lock);

		} else
			act = act->next;
	}

	spin_lock(&root->lock);
	root->parent = redirfs_rget(parent);
	spin_unlock(&root->lock);
	redirfs_rput(parent);
	redirfs_rget(root);

	list_add(&root->sibroots, end);

ret:
	spin_unlock(&redirfs_root_list_lock);

	redirfs_debug("ended");

	return ret_root;
}

static void redirfs_remove_root(struct redirfs_root_t *root)
{
	struct redirfs_root_t *parent;
	struct redirfs_root_t *loop;
	struct list_head *act;
	struct list_head *dst;
	struct list_head *tmp;


	redirfs_debug("started");

	spin_lock(&redirfs_root_list_lock);
	spin_lock(&root->lock);
	parent = root->parent;
	spin_unlock(&root->lock);

	if (parent)
		dst = &parent->subroots;
	else
		dst = &redirfs_root_list;

	list_for_each_safe(act, tmp, &root->subroots) {
		loop = list_entry(act, struct redirfs_root_t, sibroots);
		list_move(&loop->sibroots, dst);
		redirfs_rput(loop->parent);
		spin_lock(&loop->lock);
		loop->parent = redirfs_rget(parent);
		spin_unlock(&loop->lock);
	}

	list_del(&root->sibroots);
	redirfs_rput(root);

	spin_unlock(&redirfs_root_list_lock);

	redirfs_debug("ended");
}

int redirfs_walk_roots(struct redirfs_root_t *root,
		int (*walk_root)(struct redirfs_root_t *root, void *data),
		void *data)
{
	struct list_head *end;
	struct list_head *act;
	struct list_head *par;
	struct redirfs_root_t *loop;
	int stop = 0;


	redirfs_debug("started");
	spin_lock(&redirfs_root_list_lock);

	if (!root)
		end = &redirfs_root_list;
	else
		end = &root->subroots;

	act = end->next;
	par = end;

	if (root) {
		stop = walk_root(root, data);
		if (stop) {
			spin_unlock(&redirfs_root_list_lock);
			return stop;
		}
	}

	while (act != end) {
		loop = list_entry(act, struct redirfs_root_t, sibroots);
		stop = walk_root(loop, data);

		if (stop) {
			spin_unlock(&redirfs_root_list_lock);
			return stop;
		}

		if (!list_empty(&loop->subroots)) {
			par = &loop->subroots;
			act = par;
		}

		act = act->next;

		while ((act == par) && (act != end)) {
			loop = loop->parent;
			par = &loop->parent->subroots;
			act = loop->sibroots.next;
		}
	}

	spin_unlock(&redirfs_root_list_lock);

	redirfs_debug("ended");

	return 0;
}

void redirfs_set_root_ops(struct redirfs_root_t *root, int type)
{
	struct redirfs_flt_t *flt = NULL;
	int op = 0;
	int inc_op = 0;
	int i = 0;
	void ***pre_ops;
	void ***post_ops;
	void ***new_ops;
	void ***fw_ops;
	unsigned int *cnts;


	redirfs_debug("started");

	spin_lock(&root->lock);
	
	for(op = 0; op < root->new_ops.ops_arr_sizes[type]; op++) {
		for(i = 0; i < root->attached_flts.cnt; i++) {
			flt = root->attached_flts.arr[i];

			inc_op = 0;

			spin_lock(&flt->lock);

			pre_ops = redirfs_gettype(type, &flt->pre_ops);
			post_ops = redirfs_gettype(type, &flt->post_ops);

			if (*pre_ops[op]) 
				inc_op += 1;

			if (*post_ops[op])
				inc_op += 1;

			if (inc_op) {
				new_ops = redirfs_gettype(type, &root->new_ops);
				fw_ops = redirfs_gettype(type, root->fw_ops);
				cnts = redirfs_getcnt(type, &root->new_ops_cnts);
				if (*new_ops[op] != *fw_ops[op]) 
					*new_ops[op] = *fw_ops[op];
				cnts[op] += inc_op;
			}

			spin_unlock(&flt->lock);
		}
	}

	spin_unlock(&root->lock);

	redirfs_debug("ended");
}

void redirfs_set_reg_ops(struct redirfs_root_t *root, struct inode *inode)
{
	redirfs_debug("started");

	spin_lock(&root->lock);

	root->orig_ops.reg_iops = inode->i_op;
	root->orig_ops.reg_fops = inode->i_fop;

	redirfs_init_iops_arr(root->orig_ops.reg_iops_arr, root->orig_ops.reg_iops); 
	redirfs_init_fops_arr(root->orig_ops.reg_fops_arr, root->orig_ops.reg_fops); 

	memcpy(root->new_ops.reg_iops, inode->i_op, sizeof(struct inode_operations));
	memcpy(root->new_ops.reg_fops, inode->i_fop, sizeof(struct file_operations));

	spin_unlock(&root->lock);

	redirfs_debug("ended");
}

void redirfs_set_dir_ops(struct redirfs_root_t *root, struct inode *inode)
{
	redirfs_debug("started");

	spin_lock(&root->lock);

	root->orig_ops.dir_iops = inode->i_op;
	root->orig_ops.dir_fops = inode->i_fop;

	redirfs_init_iops_arr(root->orig_ops.dir_iops_arr, root->orig_ops.dir_iops); 
	redirfs_init_fops_arr(root->orig_ops.dir_fops_arr, root->orig_ops.dir_fops); 

	memcpy(root->new_ops.dir_iops, inode->i_op, sizeof(struct inode_operations));
	memcpy(root->new_ops.dir_fops, inode->i_fop, sizeof(struct file_operations));

	spin_unlock(&root->lock);
	
	redirfs_debug("ended");
}

static int redirfs_test_root(struct redirfs_root_t *root, void *dentry)
{
	redirfs_debug("started");

	if ((struct dentry*)dentry == root->dentry)
		return 1;

	return 0;

	redirfs_debug("ended");
}

static int redirfs_is_root(struct dentry *dentry)
{
	redirfs_debug("started");
	redirfs_debug("ended");
	return redirfs_walk_roots(NULL, redirfs_test_root, dentry);
}

static void redirfs_set_files_orig_ops(struct redirfs_root_t *root)
{
	struct redirfs_file_t *rfile;
	struct list_head *act;
	struct list_head *tmp;
	mode_t mode;


	spin_lock(&root->lock);

	list_for_each_safe(act, tmp, &root->files) {
		rfile = list_entry(act, struct redirfs_file_t, root);
		mode = rfile->file->f_dentry->d_inode->i_mode;

		if (S_ISREG(mode)) 
			rfile->file->f_op = root->orig_ops.reg_fops;
		else if (S_ISDIR(mode))
			rfile->file->f_op = root->orig_ops.dir_fops;

		list_del(&rfile->root);
		INIT_LIST_HEAD(&rfile->root);
		redirfs_fhash_table_remove(rfile);
		redirfs_fput(rfile);
	}

	spin_unlock(&root->lock);
}

static void redirfs_disinherit_files(struct redirfs_root_t *parent, 
		struct redirfs_root_t *child)
{
	struct redirfs_file_t *rfile;
	struct dentry *dentry;
	struct list_head *act;
	struct list_head *tmp;
	mode_t mode;

	if (!parent || !child)
		return;

	spin_lock(&parent->lock);
	spin_lock(&child->lock);

	list_for_each_safe(act, tmp, &child->files) {
		rfile = list_entry(act, struct redirfs_file_t, root);
		dentry = rfile->file->f_dentry;
		mode =  dentry->d_inode->i_mode;
		if (S_ISREG(mode))
			rfile->file->f_op = parent->new_ops.reg_fops;
		else if (S_ISDIR(mode))
			rfile->file->f_op = parent->new_ops.dir_fops;

		list_move(&rfile->root, &parent->files);
	}

	spin_unlock(&child->lock);
	spin_unlock(&parent->lock);
}

static void redirfs_inherit_files(struct redirfs_root_t *parent,
		struct redirfs_root_t *child)
{
	struct redirfs_file_t *rfile;
	struct list_head *act;
	struct list_head *tmp;
	struct dentry *dentry;
	char *dentry_path;
	char kbuf[PAGE_SIZE];
	mode_t mode;


	if (!parent || !child)
		return;

	spin_lock(&parent->lock);
	spin_lock(&child->lock);

	list_for_each_safe(act, tmp, &parent->files) {
		rfile = list_entry(act, struct redirfs_file_t, root);
		dentry = rfile->file->f_dentry;
		mode =  dentry->d_inode->i_mode;
		dentry_path = d_path(dentry, rfile->file->f_vfsmnt, kbuf,
				PAGE_SIZE);

		if (strlen(dentry_path) < strlen(child->path))
			continue;

		if (!strncmp(child->path, dentry_path, strlen(child->path))) {
			if (S_ISREG(mode))
				rfile->file->f_op = child->new_ops.reg_fops;
			else if (S_ISDIR(mode))
				rfile->file->f_op = child->new_ops.dir_fops;

			list_move(&rfile->root, &child->files);
		}

	}

	spin_unlock(&child->lock);
	spin_unlock(&parent->lock);
}

static void redirfs_set_new_ops(struct dentry *dentry, void *data)
{
	struct redirfs_root_t *root = (struct redirfs_root_t *)data;
	int aux = 0;


	redirfs_debug("started");

	if (dentry && dentry->d_inode) {
		umode_t mode = dentry->d_inode->i_mode;

		if (S_ISREG(mode)) {
			spin_lock(&root->lock);
			aux = !root->orig_ops.reg_iops;
			spin_unlock(&root->lock);

			if (aux) {
				redirfs_set_reg_ops(root, dentry->d_inode);
				redirfs_set_root_ops(root, REDIRFS_I_REG);
				redirfs_set_root_ops(root, REDIRFS_F_REG);

				spin_lock(&root->lock);
				root->new_ops.reg_fops->open =
					root->fw_ops->reg_fops->open;
				root->new_ops.reg_fops->release =
					root->fw_ops->reg_fops->release;
				spin_unlock(&root->lock);
			}

			redirfs_add_inode(root, dentry->d_inode);

			spin_lock(&root->lock);
			dentry->d_inode->i_op = root->new_ops.reg_iops;
			dentry->d_inode->i_fop = root->new_ops.reg_fops;
			dentry->d_op = root->new_ops.dops;
			spin_unlock(&root->lock);

		} else if (S_ISDIR(mode)) {
			spin_lock(&root->lock);
			aux = !root->orig_ops.reg_iops;
			spin_unlock(&root->lock);

			if (aux) {
				redirfs_set_dir_ops(root, dentry->d_inode);
				redirfs_set_root_ops(root, REDIRFS_I_DIR);
				redirfs_set_root_ops(root, REDIRFS_F_DIR);

				spin_lock(&root->lock);
				root->new_ops.dir_iops->lookup =
					root->fw_ops->dir_iops->lookup;
				root->new_ops.dir_iops->mkdir =
					root->fw_ops->dir_iops->mkdir;
				root->new_ops.dir_iops->create =
					root->fw_ops->dir_iops->create;
				root->new_ops.dir_fops->open =
					root->fw_ops->dir_fops->open;
				root->new_ops.dir_fops->release =
					root->fw_ops->dir_fops->release;
				spin_unlock(&root->lock);
			}

			redirfs_add_inode(root, dentry->d_inode);

			spin_lock(&root->lock);
			dentry->d_inode->i_op = root->new_ops.dir_iops;
			dentry->d_inode->i_fop = root->new_ops.dir_fops;
			dentry->d_op = root->new_ops.dops;
			spin_unlock(&root->lock);
		}
	}
	
	redirfs_debug("ended");
}

static void redirfs_set_orig_ops(struct dentry *dentry, void *data)
{
	struct redirfs_root_t *root = (struct redirfs_root_t *)data;


	redirfs_debug("started");

	if (dentry && dentry->d_inode) {
		umode_t mode = dentry->d_inode->i_mode;

		if (S_ISREG(mode)) {
			spin_lock(&root->lock);
			if (root->orig_ops.reg_iops) {
				dentry->d_inode->i_op = root->orig_ops.reg_iops;
				dentry->d_inode->i_fop = root->orig_ops.reg_fops;
				dentry->d_op = root->orig_ops.dops;
			}
			spin_unlock(&root->lock);

		} else if (S_ISDIR(mode)) {
			spin_lock(&root->lock);
			if (root->orig_ops.dir_iops) {
				dentry->d_inode->i_op = root->orig_ops.dir_iops;
				dentry->d_inode->i_fop = root->orig_ops.dir_fops;
				dentry->d_op = root->orig_ops.dops;
			}
			spin_unlock(&root->lock);
		}

		redirfs_remove_inode(dentry->d_inode);
	}

	redirfs_debug("ended");
}

static void redirfs_walk_dcache(struct dentry *root, 
		void (*redirfs_walk_dentry)(struct dentry *dentry, void *dentry_data),
		void *dentry_data,
		void (*redirfs_mount_dentry)(struct dentry *dentry, void *mount_data),
		void *mount_data)
{
	struct list_head *end;
	struct list_head *act;
	struct list_head *parent;
	struct dentry *dentry;


	redirfs_debug("started");

	shrink_dcache_parent(root);

	spin_lock(&dcache_lock);
	
	end 	= &root->d_subdirs;
	act 	= end->next;
	parent 	= end;
	
	redirfs_walk_dentry(root, dentry_data);

	while (act != end) {
		dentry = list_entry(act, struct dentry, d_child);

		if (redirfs_is_root(dentry))
			goto skip_subtree;

		
		if (dentry->d_mounted) {
			if (redirfs_mount_dentry)
				redirfs_mount_dentry(dentry, mount_data);
			goto skip_subtree;
		}

		redirfs_walk_dentry(dentry, dentry_data);

		if (!list_empty(&dentry->d_subdirs)) {
			parent = &dentry->d_subdirs;
			act = parent;
		}
skip_subtree:
		act = act->next;

		while ((act == parent) && (act != end)) {
			dentry = dentry->d_parent;
			parent = &dentry->d_parent->d_subdirs;
			act = dentry->d_child.next;
		}
	}
	
	spin_unlock(&dcache_lock);

	redirfs_debug("ended");
}

static void redirfs_root_rejection(struct redirfs_root_t *root)
{
	struct redirfs_root_t *parent;


	parent = redirfs_rget(root->parent);

	if (parent) {
		if (redirfs_flt_arr_cmp(&root->attached_flts, &parent->attached_flts) || 
		    redirfs_flt_arr_cmp(&root->detached_flts, &parent->detached_flts)) {
			redirfs_rput(parent);
			return;
		}

	} else {
		if (redirfs_flt_arr_cnt(&root->attached_flts) ||
		    redirfs_flt_arr_cnt(&root->detached_flts))
			return;
	}


	spin_lock(&root->lock);
	root->flags |= REDIRFS_ROOT_REMOVE;
	spin_unlock(&root->lock);
	spin_lock(&redirfs_remove_roots_list_lock);
	list_add(&root->remove, &redirfs_remove_roots_list);
	spin_unlock(&redirfs_remove_roots_list_lock);
	redirfs_rget(root);
	redirfs_rput(parent);
}

static void redirfs_attach_flt_ops_to_root(struct redirfs_root_t *root,
		struct redirfs_flt_t *flt)
{
	int type = 0;
	int op = 0;
	int inc_op = 0;
	void ***root_orig_ops;
	void ***root_new_ops;
	void ***root_fw_ops;
	void ***flt_pre_ops;
	void ***flt_post_ops;
	unsigned int *root_cnts;


	spin_lock(&root->lock);
	spin_lock(&flt->lock);

	for (type = 0; type < REDIRFS_END; type++) {
		root_orig_ops = redirfs_gettype(type, &root->orig_ops);
		
		if (!root_orig_ops)
			continue;

		flt_pre_ops = redirfs_gettype(type, &flt->pre_ops);
		flt_post_ops = redirfs_gettype(type, &flt->post_ops);
			
		for (op = 0; op < root->new_ops.ops_arr_sizes[type]; op++) {
			inc_op = 0;

			if (*flt_pre_ops[op]) 
				inc_op += 1;

			if (*flt_post_ops[op]) 
				inc_op += 1;

			if (!inc_op) 
				continue;

			root_new_ops = redirfs_gettype(type, &root->new_ops);
			root_fw_ops = redirfs_gettype(type, root->fw_ops);
			root_cnts = redirfs_getcnt(type, &root->new_ops_cnts);

			if (*root_new_ops[op] != *root_fw_ops[op])
				*root_new_ops[op] = *root_fw_ops[op];

			root_cnts[op] += inc_op;
		}
	}

	spin_unlock(&flt->lock);
	spin_unlock(&root->lock);
}

static int redirfs_attach_flt(struct redirfs_root_t *root, void *data)
{
	struct redirfs_flt_t *flt;
	int rv = 0;


	flt = (struct redirfs_flt_t *)data;
	
	if (redirfs_flt_arr_get(&root->attached_flts, flt) >= 0)
		return 0;

	redirfs_attach_flt_ops_to_root(root, flt);

	redirfs_flt_arr_remove_flt(&root->detached_flts, flt);
	rv = redirfs_flt_arr_add_flt(&root->attached_flts, flt);
	if (rv) 
		return rv;

	redirfs_root_rejection(root);

	return 0;
}

static void redirfs_detach_flt_ops_from_root(struct redirfs_root_t *root,
		struct redirfs_flt_t *flt)
{
	int type = 0;
	int op = 0;
	int dec_op = 0;
	void ***root_orig_ops;
	void ***root_new_ops;
	void ***flt_pre_ops;
	void ***flt_post_ops;
	unsigned int *root_cnts;


	spin_lock(&root->lock);
	spin_lock(&flt->lock);

	for (type = 0; type < REDIRFS_END; type++) {
		root_orig_ops = redirfs_gettype(type, &root->orig_ops);

		if (!root_orig_ops[0])
			continue;

		flt_pre_ops = redirfs_gettype(type, &flt->pre_ops);
		flt_post_ops = redirfs_gettype(type, &flt->post_ops);

		for (op = 0; op < root->new_ops.ops_arr_sizes[type]; op++) {
			dec_op = 0;

			if (*flt_pre_ops[op]) 
				dec_op += 1;

			if (*flt_post_ops[op]) 
				dec_op += 1;

			if (!dec_op) 
				continue;

			root_new_ops = redirfs_gettype(type, &root->new_ops);
			root_cnts = redirfs_getcnt(type, &root->new_ops_cnts);

			root_cnts[op] -= dec_op;
			if (!root_cnts[op])
				*root_new_ops[op] = *root_orig_ops[op];
		}
	}

	spin_unlock(&flt->lock);
	spin_unlock(&root->lock);
}

int static redirfs_detach_flt(struct redirfs_root_t *root, void *data)
{
	struct redirfs_flt_t *flt;
	int rv = 0;


	flt = (struct redirfs_flt_t *)data;

	if (redirfs_flt_arr_get(&root->attached_flts, flt) == -1)
		return 0;

	redirfs_detach_flt_ops_from_root(root, flt);

	redirfs_flt_arr_remove_flt(&root->attached_flts, flt);
	rv = redirfs_flt_arr_add_flt(&root->detached_flts, flt);
	if (rv)
		return rv;

	redirfs_root_rejection(root);

	return 0;
}

int redirfs_remove_flt(struct redirfs_root_t *root, void *data)
{
	struct redirfs_flt_t *flt;


	flt = (struct redirfs_flt_t *)data;

	if (redirfs_flt_arr_get(&root->attached_flts, flt) >= 0) {
		redirfs_detach_flt_ops_from_root(root, flt);
		redirfs_flt_arr_remove_flt(&root->attached_flts, flt);
	} else
		redirfs_flt_arr_remove_flt(&root->detached_flts, flt);

	redirfs_root_rejection(root);

	return 0;
}

void redirfs_remove_roots(void)
{
	struct list_head *act;
	struct list_head *tmp;
	struct redirfs_root_t *root = NULL;
	struct redirfs_root_t *parent = NULL;


	redirfs_debug("started");

	spin_lock(&redirfs_remove_roots_list_lock);

	list_for_each_safe(act, tmp, &redirfs_remove_roots_list) {
		root = list_entry(act, struct redirfs_root_t, remove);

		parent = redirfs_rget(root->parent);

		if (parent) {
			redirfs_walk_dcache(root->dentry, redirfs_set_new_ops, parent, NULL, NULL);
			redirfs_disinherit_files(parent, root);
		} else {
			redirfs_walk_dcache(root->dentry, redirfs_set_orig_ops, root, NULL, NULL);
			redirfs_set_files_orig_ops(root);
		}

		redirfs_remove_root(root);
		list_del(&root->remove);
		redirfs_rput(parent);
		redirfs_rput(root);
	}

	spin_unlock(&redirfs_remove_roots_list_lock);

	redirfs_debug("ended");
}

int redirfs_include_path(redirfs_filter filter, const char *path)
{
	struct redirfs_root_t *root;
	struct redirfs_root_t *aux_root;
	int rv = 0;


	redirfs_debug("started");

	if (!filter || !path)
		return -EINVAL;

	spin_lock(&redirfs_remove_roots_list_lock);
	root = redirfs_find_root(path);

	if (root) {
		spin_lock(&root->lock);
		if (root->flags & REDIRFS_ROOT_REMOVE) {
			root->flags &= ~REDIRFS_ROOT_REMOVE;
			list_del(&root->remove);
		}
		spin_unlock(&root->lock);
	}

	spin_unlock(&redirfs_remove_roots_list_lock);

	if (!root) {
		root = redirfs_alloc_root(path);
		if (IS_ERR(root))
			return PTR_ERR(root);

		aux_root = root;
		root = redirfs_add_root(root);
		if (IS_ERR(root)) {
			redirfs_rput(root);
			return PTR_ERR(root);
		}
		
		if (root == aux_root) {
			redirfs_walk_dcache(root->dentry, redirfs_set_new_ops,
					(void *)root, NULL, NULL);

			redirfs_inherit_files(root->parent, root);
		} else
			redirfs_rput(aux_root);
	}

	rv = redirfs_walk_roots(root, redirfs_attach_flt, (void *)filter);
	if (rv)
		redirfs_walk_roots(root, redirfs_detach_flt, (void *)filter);
	
	redirfs_rput(root);
	redirfs_remove_roots();

	redirfs_debug("ended");

	return rv;
}

int redirfs_exclude_path(redirfs_filter filter, const char *path)
{
	struct redirfs_flt_t *flt;
	struct redirfs_root_t *root;
	struct redirfs_root_t *parent;
	struct redirfs_root_t *aux_root;


	if (!filter)
		return -EINVAL;

	flt = redirfs_uncover_flt(filter);

	root = redirfs_find_root(path);

	if (root) {
		redirfs_walk_roots(root, redirfs_detach_flt, (void *)flt);
		redirfs_rput(root);
		return 0;
	}

	root = redirfs_alloc_root(path);
	if (IS_ERR(root))
		return PTR_ERR(root);

	parent = redirfs_find_root_parent(root);
	if (!parent) {
		redirfs_rput(root);
		return -EINVAL;
	}

	if (redirfs_flt_arr_get(&parent->attached_flts, flt) == -1) {
		redirfs_rput(root);
		redirfs_rput(parent);
		return -EINVAL;
	}

	aux_root = root;
	root = redirfs_add_root(root);
	if (IS_ERR(root)) {
		redirfs_rput(root);
		redirfs_rput(parent);
		return PTR_ERR(root);
	}

	if (root == aux_root) {
		redirfs_walk_dcache(root->dentry, redirfs_set_new_ops,
				(void *)root, NULL, NULL);

		redirfs_inherit_files(root->parent, root);
	} else
		redirfs_rput(aux_root);

	redirfs_walk_roots(root, redirfs_detach_flt, (void *)flt);
	redirfs_rput(root);
	redirfs_rput(parent);
	redirfs_remove_roots();

	return 0;
}

struct redirfs_root_info_t {
	char *buf;
	int size;
	int len;

};

static int redirfs_root_info(struct redirfs_root_t *root, void *data)
{
	struct redirfs_root_info_t *info = NULL;
	struct redirfs_flt_t *flt = NULL;
	char active = 0;
	int i = 0;


	info = (struct redirfs_root_info_t *)data;

	spin_lock(&root->attached_flts.lock);

	if ((info->len + strlen(root->path) + 1) > info->size) goto err;
	info->len += sprintf(info->buf + info->len, "%s:", root->path);

	for(i = 0; i < root->attached_flts.cnt; i++) {
		flt = root->attached_flts.arr[i];
		active = atomic_read(&flt->active) ? '1' : '0';
		if ((info->len + strlen(flt->name) + 16) > info->size) goto err;
		info->len += sprintf(info->buf + info->len, " -> %s(+,%c,%d)", flt->name, active, flt->priority);
	}

	for(i = 0; i < root->detached_flts.cnt; i++) {
		flt = root->detached_flts.arr[i];
		active = atomic_read(&flt->active) ? '1' : '0';
		if ((info->len + strlen(flt->name) + 16) > info->size) goto err;
		info->len += sprintf(info->buf + info->len, " -> %s(-,%c,%d)", flt->name, active, flt->priority);
	}

	spin_unlock(&root->attached_flts.lock);

	info->len += sprintf(info->buf + info->len, "\n");

	return 0;

err:
	spin_unlock(&root->attached_flts.lock);
	return -1;
}

int redirfs_roots_info(char *buf, int size)
{	
	struct redirfs_root_info_t info = {buf, size, 0};
	

	redirfs_walk_roots(NULL, redirfs_root_info, &info);

	return info.len;
}

EXPORT_SYMBOL(redirfs_include_path);
EXPORT_SYMBOL(redirfs_exclude_path);
