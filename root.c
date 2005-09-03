#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/smp_lock.h>
#include <linux/list.h>
#include "root.h"
#include "filter.h"
#include "operations.h"
#include "inode.h"

extern spinlock_t inode_lock;
extern struct redirfs_operations_t redirfs_fw_ops;
static spinlock_t redirfs_root_list_lock = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(redirfs_root_list);
static spinlock_t redirfs_remove_root_list_lock = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(redirfs_remove_root_list);

static struct redirfs_root_t *redirfs_alloc_root(const char *path)
{
	struct redirfs_root_t *root;
	struct nameidata nd;
	char *root_path;
	size_t root_path_len;
	int err;

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

	strncpy(root_path, path, root_path_len + 1);

	root->dentry = dget(nd.dentry);
	root->lock = SPIN_LOCK_UNLOCKED;
	root->path = root_path;
	root->fw_ops = &redirfs_fw_ops;
	root->parent = NULL;
	atomic_set(&root->flt_cnt, 0);

	INIT_LIST_HEAD(&root->attached_flts);
	INIT_LIST_HEAD(&root->subroots);
	INIT_LIST_HEAD(&root->sibroots);
	INIT_LIST_HEAD(&root->remove);
	INIT_LIST_HEAD(&root->inodes);

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

	return root;
}

static void redirfs_free_root(struct redirfs_root_t *root)
{
	dput(root->dentry);
	kfree(root->path);
	kfree(root);
}

static struct redirfs_root_t *redirfs_find_root_parent(struct redirfs_root_t *root)
{
	struct redirfs_root_t *parent = NULL;
	struct redirfs_root_t *loop = NULL;
	size_t path_len = 0;
	size_t loop_len = 0;
	struct list_head *end;
	struct list_head *act;


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

	return parent;
}

static struct redirfs_root_t *redirfs_find_root(const char *path)
{
	struct redirfs_root_t *found = NULL;
	struct redirfs_root_t *loop = NULL;
	size_t path_len = 0;
	size_t loop_len = 0;
	struct list_head *end;
	struct list_head *act;


	path_len = strlen(path);

	end = &redirfs_root_list;
	act = end->next;

	while ((act != end) && !found) {
		loop = list_entry(act, struct redirfs_root_t, sibroots);
		loop_len = strlen(loop->path);

		if (loop_len != path_len) {
			act = act->next;
			continue;
		}

		if (!strncmp(loop->path, path, path_len)) {
			if (path_len == loop_len)
				found = loop;

			end = &loop->subroots;
			act = end;
		}

		act = act->next;
	}

	return found;
}

static void redirfs_add_root(struct redirfs_root_t *parent, struct redirfs_root_t *root)
{
	struct list_head *end;
	struct list_head *act;
	struct redirfs_root_t *loop;
	size_t loop_len;
	size_t path_len;

	
	if (parent) 
		end = &parent->subroots;
	else
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
			spin_lock(&loop->lock);
			loop->parent = root;
			spin_unlock(&loop->lock);

		} else
			act = act->next;
	}

	spin_lock(&root->lock);
	root->parent = parent;
	spin_unlock(&root->lock);
	list_add(&root->sibroots, end);
}

static void redirfs_remove_root(struct redirfs_root_t *root)
{
	struct redirfs_root_t *parent;
	struct redirfs_root_t *loop;
	struct list_head *end;
	struct list_head *act;
	struct list_head *dst;
	struct list_head *tmp;


	end = &root->subroots;
	act = end->next;

	spin_lock(&root->lock);
	parent = root->parent;
	spin_unlock(&root->lock);

	if (parent)
		dst = &parent->subroots;
	else
		dst = &redirfs_root_list;

	list_for_each_safe(act, tmp, end) {
		loop = list_entry(act, struct redirfs_root_t, sibroots);
		list_move(&loop->sibroots, dst);
		spin_lock(&loop->lock);
		loop->parent = parent;
		spin_unlock(&loop->lock);
	}

	list_del(&root->sibroots);
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


	if (!root)
		end = &redirfs_root_list;
	else
		end = &root->subroots;

	act = end->next;
	par = end;

	if (root) {
		stop = walk_root(root, data);
		if (stop)
			return stop;
	}

	while (act != end) {
		loop = list_entry(act, struct redirfs_root_t, sibroots);
		stop = walk_root(loop, data);

		if (stop)
			return stop;

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

	return 0;
}

static int redirfs_inherit_root(struct redirfs_root_t *par, struct redirfs_root_t *child)
{
	struct redirfs_ptr_t *ptr_par;
	struct redirfs_ptr_t *ptr_child;


	spin_lock(&par->lock);
	spin_lock(&child->lock);

	memcpy(&child->vfs_ops, &par->vfs_ops, sizeof(struct redirfs_vfs_operations_t));
	memcpy(&child->new_ops_cnts, &par->new_ops_cnts, sizeof(struct redirfs_operations_counters_t));

	child->orig_ops.reg_iops = par->orig_ops.reg_iops;
	child->orig_ops.reg_fops = par->orig_ops.reg_fops;
	child->orig_ops.dir_iops = par->orig_ops.dir_iops;
	child->orig_ops.dir_fops = par->orig_ops.dir_fops;

	if (child->orig_ops.reg_iops) {
		redirfs_init_iops_arr(child->orig_ops.reg_iops_arr, child->orig_ops.reg_iops); 
		redirfs_init_fops_arr(child->orig_ops.reg_fops_arr, child->orig_ops.reg_fops); 
	}

	if (child->orig_ops.dir_iops) {
		redirfs_init_iops_arr(child->orig_ops.dir_iops_arr, child->orig_ops.dir_iops); 
		redirfs_init_fops_arr(child->orig_ops.dir_fops_arr, child->orig_ops.dir_fops); 
	}

	list_for_each_entry(ptr_par, &par->attached_flts, ptr_list) {
		ptr_child = redirfs_alloc_ptr((void*)ptr_par->ptr_val);
		if (IS_ERR(ptr_child))
			return PTR_ERR(ptr_child);

		list_add(&ptr_child->ptr_list, &child->attached_flts);
		atomic_inc(&child->flt_cnt);
	}

	spin_unlock(&par->lock);
	spin_unlock(&child->lock);

	return 0;
}

void redirfs_set_root_ops(struct redirfs_root_t *root, int type)
{
	struct redirfs_flt_t *flt = NULL;
	struct redirfs_ptr_t *ptr;
	int op = 0;
	int inc_op = 0;
	void ***pre_ops;
	void ***post_ops;
	void ***new_ops;
	void ***fw_ops;
	unsigned int *cnts;

	
	for (op = 0; op < root->new_ops.ops_arr_sizes[type]; op++) {
		list_for_each_entry(ptr, &root->attached_flts, ptr_list) {
			flt = (struct redirfs_flt_t *)ptr->ptr_val;

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
}

void redirfs_set_reg_ops(struct redirfs_root_t *root, struct inode *inode)
{
	root->orig_ops.reg_iops = inode->i_op;
	root->orig_ops.reg_fops = inode->i_fop;

	redirfs_init_iops_arr(root->orig_ops.reg_iops_arr, root->orig_ops.reg_iops); 
	redirfs_init_fops_arr(root->orig_ops.reg_fops_arr, root->orig_ops.reg_fops); 

	memcpy(root->new_ops.reg_iops, inode->i_op, sizeof(struct inode_operations));
	memcpy(root->new_ops.reg_fops, inode->i_fop, sizeof(struct file_operations));
}

void redirfs_set_dir_ops(struct redirfs_root_t *root, struct inode *inode)
{
	root->orig_ops.dir_iops = inode->i_op;
	root->orig_ops.dir_fops = inode->i_fop;

	redirfs_init_iops_arr(root->orig_ops.dir_iops_arr, root->orig_ops.dir_iops); 
	redirfs_init_fops_arr(root->orig_ops.dir_fops_arr, root->orig_ops.dir_fops); 

	memcpy(root->new_ops.dir_iops, inode->i_op, sizeof(struct inode_operations));
	memcpy(root->new_ops.dir_fops, inode->i_fop, sizeof(struct file_operations));
}

static int redirfs_test_root(struct redirfs_root_t *root, void *data)
{
	struct redirfs_cb_data_t *cb_data = (struct redirfs_cb_data_t *)data;

	if (cb_data->dentry == root->dentry) {
		cb_data->i_val = 1;
		return 1;
	}

	return 0;
}

static int redirfs_is_root(struct dentry *dentry)
{
	struct redirfs_cb_data_t cb_data;

	
	cb_data.dentry = dentry;
	cb_data.i_val = 0;
	
	redirfs_walk_roots(NULL, redirfs_test_root, &cb_data);

	if (cb_data.i_val)
		return 1;

	return 0;
}

void redirfs_replace_files_ops(const char *path, struct dentry *root_dentry, struct
		file_operations *fops, int what)
{
	char *kbuf;
	char *dentry_path;
	struct super_block *sb = root_dentry->d_inode->i_sb;
	struct file *file;
	struct dentry *dentry;
	mode_t mode;

	
	kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	BUG_ON(!kbuf);

	file_list_lock();

	list_for_each_entry(file, &sb->s_files, f_list) {
		dentry = file->f_dentry;
		dentry_path = d_path(dentry, file->f_vfsmnt, kbuf, PAGE_SIZE);

		if (strlen(dentry_path) < strlen(path))
			continue;

		mode = file->f_dentry->d_inode->i_mode;

		if (!strncmp(path, dentry_path, strlen(path)))
		{
			if (S_ISREG(mode) && S_ISREG(what)) {
				if (!redirfs_is_root(dentry))
					file->f_op = fops;
				else 
					if (dentry == root_dentry)
						file->f_op = fops;

			} else if (S_ISDIR(mode) && S_ISDIR(what)) {
				if (!redirfs_is_root(dentry))
					file->f_op = fops;
				else 
					if (dentry == root_dentry)
						file->f_op = fops;
			}
		}
	}

	file_list_unlock();

	kfree(kbuf);
}

static void redirfs_set_new_ops(struct dentry *dentry, void *data)
{
	struct redirfs_root_t *root = (struct redirfs_root_t *)data;


	if (dentry && dentry->d_inode) {
		umode_t mode = dentry->d_inode->i_mode;

		if (S_ISREG(mode)) {
			if (!root->orig_ops.reg_iops) {
				redirfs_set_reg_ops(root, dentry->d_inode);
				redirfs_set_root_ops(root, REDIRFS_I_REG);
				redirfs_set_root_ops(root, REDIRFS_F_REG);
				redirfs_replace_files_ops(root->path, root->dentry, root->new_ops.reg_fops, S_IFREG);
			}

			redirfs_add_inode(root, dentry);

			dentry->d_inode->i_op = root->new_ops.reg_iops;
			dentry->d_inode->i_fop = root->new_ops.reg_fops;
			dentry->d_op = root->new_ops.dops;

		} else if (S_ISDIR(mode)) {
			if (!root->orig_ops.dir_iops) {
				redirfs_set_dir_ops(root, dentry->d_inode);
				redirfs_set_root_ops(root, REDIRFS_I_DIR);
				redirfs_set_root_ops(root, REDIRFS_F_DIR);

				root->new_ops.dir_iops->lookup = root->fw_ops->dir_iops->lookup;
				root->new_ops.dir_iops->mkdir = root->fw_ops->dir_iops->mkdir;
				root->new_ops.dir_iops->create = root->fw_ops->dir_iops->create;
				redirfs_replace_files_ops(root->path, root->dentry, root->new_ops.dir_fops, S_IFDIR);
			}

			redirfs_add_inode(root, dentry);

			dentry->d_inode->i_op = root->new_ops.dir_iops;
			dentry->d_inode->i_fop = root->new_ops.dir_fops;
			dentry->d_op = root->new_ops.dops;
		}
	}
}

static void redirfs_set_orig_ops(struct dentry *dentry, void *data)
{
	struct redirfs_root_t *root = (struct redirfs_root_t *)data;


	if (dentry && dentry->d_inode) {
		umode_t mode = dentry->d_inode->i_mode;

		redirfs_remove_inode(root, dentry);

		if (S_ISREG(mode)) {
			if (root->orig_ops.reg_iops) {
				dentry->d_inode->i_op = root->orig_ops.reg_iops;
				dentry->d_inode->i_fop = root->orig_ops.reg_fops;
				dentry->d_op = root->orig_ops.dops;
			}

		} else if (S_ISDIR(mode)) {
			if (root->orig_ops.dir_iops) {
				dentry->d_inode->i_op = root->orig_ops.dir_iops;
				dentry->d_inode->i_fop = root->orig_ops.dir_fops;
				dentry->d_op = root->orig_ops.dops;
			}
		}
	}
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


	shrink_dcache_parent(root);

	spin_lock(&dcache_lock);
	spin_lock(&inode_lock);
	
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
	
	spin_lock(&inode_lock);
	spin_unlock(&dcache_lock);
}

static struct list_head *redirfs_find_flt_pos(struct redirfs_root_t *root, struct redirfs_flt_t *flt_new)
{
	struct redirfs_flt_t *flt;
	struct redirfs_ptr_t *loop;
	struct list_head *found = &root->attached_flts;


	list_for_each_entry(loop, &root->attached_flts, ptr_list) {
		flt = (struct redirfs_flt_t *)loop->ptr_val;

		if (flt->turn > flt_new->turn) {
			found = loop->ptr_list.prev;
			break;
		}
	}

	return found;
}

struct list_head *redirfs_find_flt(struct redirfs_root_t *root, struct redirfs_flt_t *flt_find)
{
	struct redirfs_flt_t *flt;
	struct redirfs_ptr_t *loop;
	struct list_head *found = NULL;


	list_for_each_entry(loop, &root->attached_flts, ptr_list) {
		flt = (struct redirfs_flt_t *)loop->ptr_val;

		if (flt == flt_find) {
			found = &loop->ptr_list;
			break;
		}
	}

	return found;
}

static int redirfs_attach_flt(struct redirfs_root_t *root, void *data)
{
	struct redirfs_flt_t *flt;
	struct list_head *flt_pos;
	struct redirfs_ptr_t *ptr;
	int type = 0;
	int op = 0;
	int inc_op = 0;
	void ***root_orig_ops;
	void ***root_new_ops;
	void ***root_fw_ops;
	void ***flt_pre_ops;
	void ***flt_post_ops;
	unsigned int *root_cnts;

	flt = (struct redirfs_flt_t *)data;
	
	spin_lock(&flt->lock);
	spin_lock(&root->lock);

	flt_pos = redirfs_find_flt(root, flt);
	if (flt_pos)
		return 0;

	flt_pos = redirfs_find_flt_pos(root, flt);

	ptr = redirfs_alloc_ptr((void *)flt);
	if (!ptr)
		return -ENOMEM;

	for (type = 0; type < REDIRFS_END; type++) {
		root_orig_ops = redirfs_gettype(type, &root->orig_ops);
		
		if (root_orig_ops) {
			flt_pre_ops = redirfs_gettype(type, &flt->pre_ops);
			flt_post_ops = redirfs_gettype(type, &flt->post_ops);
			
			for (op = 0; op < root->new_ops.ops_arr_sizes[type]; op++) {
				inc_op = 0;

				if (*flt_pre_ops[op]) 
					inc_op += 1;

				if (*flt_post_ops[op]) 
					inc_op += 1;

				if (inc_op) {
					root_new_ops = redirfs_gettype(type, &root->new_ops);
					root_fw_ops = redirfs_gettype(type, root->fw_ops);
					root_cnts = redirfs_getcnt(type, &root->new_ops_cnts);

					if (*root_new_ops[op] != *root_fw_ops[op])
						*root_new_ops[op] = *root_fw_ops[op];
					root_cnts[op] += inc_op;
				}
			}
		}
	}

	list_add(&ptr->ptr_list, flt_pos);
	atomic_inc(&root->flt_cnt);

	spin_unlock(&root->lock);
	spin_unlock(&flt->lock);

	return 0;
}

int redirfs_detach_flt(struct redirfs_root_t *root, void *data)
{
	struct redirfs_flt_t *flt;
	struct list_head *flt_pos;
	int type = 0;
	int op = 0;
	int dec_op = 0;
	void ***root_orig_ops;
	void ***root_new_ops;
	void ***flt_pre_ops;
	void ***flt_post_ops;
	unsigned int *root_cnts;

	flt = (struct redirfs_flt_t *)data;
	
	spin_lock(&flt->lock);
	spin_lock(&root->lock);

	flt_pos = redirfs_find_flt(root, flt);

	if (!flt_pos)
		return 0;

	for (type = 0; type < REDIRFS_END; type++) {
		root_orig_ops = redirfs_gettype(type, &root->orig_ops);

		if (root_orig_ops) {
			flt_pre_ops = redirfs_gettype(type, &flt->pre_ops);
			flt_post_ops = redirfs_gettype(type, &flt->post_ops);

			for (op = 0; op < root->new_ops.ops_arr_sizes[type]; op++) {
				dec_op = 0;

				if (*flt_pre_ops[op]) 
					dec_op += 1;

				if (*flt_post_ops[op]) 
					dec_op += 1;

				if (dec_op) {
					root_new_ops = redirfs_gettype(type, &root->new_ops);
					root_cnts = redirfs_getcnt(type, &root->new_ops_cnts);

					root_cnts[op] -= dec_op;
					if (!root_cnts[op])
						*root_new_ops[op] = *root_orig_ops[op];
				}
			}
		}
	}

	list_del(flt_pos);

	if (atomic_dec_and_test(&root->flt_cnt)) {
		redirfs_walk_dcache(root->dentry, redirfs_set_orig_ops, root, NULL, NULL);
		if (root->orig_ops.reg_fops)
			redirfs_replace_files_ops(root->path, root->dentry, root->orig_ops.reg_fops, S_IFREG);
		if (root->orig_ops.dir_fops)
			redirfs_replace_files_ops(root->path, root->dentry, root->orig_ops.dir_fops, S_IFDIR);
		spin_lock(&redirfs_remove_root_list_lock);
		list_add(&root->remove, &redirfs_remove_root_list);
		spin_unlock(&redirfs_remove_root_list_lock);
	}

	spin_unlock(&root->lock);
	spin_unlock(&flt->lock);

	return 0;
}

void redirfs_remove_roots(struct redirfs_flt_t *flt)
{
	struct redirfs_root_t *root;
	struct list_head *loop;
	struct list_head *tmp;


	spin_lock(&redirfs_remove_root_list_lock);
	
	list_for_each_safe(loop, tmp, &redirfs_remove_root_list) {
		root =  list_entry(loop, struct redirfs_root_t, remove);
		
		redirfs_remove_root(root);
		redirfs_free_root(root);
		list_del(loop);

	}

	spin_unlock(&redirfs_remove_root_list_lock);
}

int redirfs_has_higher_root_flt(struct redirfs_root_t *root, struct redirfs_flt_t *flt)
{
	struct redirfs_root_t *parent;
	struct list_head *lh;
	
	
	parent = root;
	while (parent) {
		spin_lock(&root->lock);
		lh = redirfs_find_flt(parent, flt);
		spin_unlock(&root->lock);
		if (lh)
			return 1;
		parent = parent->parent;
	}

	return 0;
}

int redirfs_include_path(redirfs_filter filter, const char *path)
{
	struct redirfs_flt_t *flt;
	struct redirfs_root_t *root;
	struct redirfs_root_t *parent;
	int rv = 0;


	if (!filter || !path)
		return -EINVAL;

	flt = redirfs_uncover_flt(filter);

	spin_lock(&redirfs_root_list_lock);

	root = redirfs_find_root(path);

	if (!root) {
		root = redirfs_alloc_root(path);

		if (IS_ERR(root)) {
			spin_unlock(&redirfs_root_list_lock);
			return PTR_ERR(root);
		}

		parent = redirfs_find_root_parent(root);

		if (parent) {
			rv = redirfs_inherit_root(parent, root);
			if (rv) {
				redirfs_free_root(root);
				return rv;
			}
		}

		redirfs_add_root(parent, root);
		redirfs_walk_dcache(root->dentry, redirfs_set_new_ops, (void *)root, NULL, NULL);
		if (root->orig_ops.reg_fops)
			redirfs_replace_files_ops(root->path, root->dentry, root->new_ops.reg_fops, S_IFREG);
		if (root->orig_ops.dir_fops)
			redirfs_replace_files_ops(root->path, root->dentry, root->new_ops.dir_fops, S_IFDIR);
	}

	rv = redirfs_walk_roots(root, redirfs_attach_flt, (void *)flt);
	if (rv) {
		redirfs_walk_roots(root, redirfs_detach_flt, (void *)flt);
		spin_unlock(&redirfs_root_list_lock);
		return rv;
	}

	spin_unlock(&redirfs_root_list_lock);
	
	return 0;
}

int redirfs_exclude_path(redirfs_filter filter, const char *path)
{
	struct redirfs_flt_t *flt;
	struct redirfs_root_t *root;
	struct redirfs_root_t *parent;
	struct redirfs_ptr_t *ptr;
	int rv = 0;


	if (!filter)
		return -EINVAL;

	ptr = redirfs_alloc_ptr(NULL);
	if (!ptr)
		return -ENOMEM;

	flt = redirfs_uncover_flt(filter);

	spin_lock(&redirfs_root_list);

	root = redirfs_find_root(path);
	if (root) {
		redirfs_walk_roots(root, redirfs_detach_flt, (void *)flt);
		goto ret;
	}

	root = redirfs_alloc_root(path);
	if (IS_ERR(root)) {
		rv = PTR_ERR(root);
		goto ret;
	}

	parent = redirfs_find_root_parent(root);
	if (!parent) 
		goto free_mem;

	if (!redirfs_has_higher_root_flt(parent, flt))
		goto free_mem;

	rv = redirfs_inherit_root(parent, root);
	if (rv)
		goto free_mem;

	redirfs_walk_dcache(root->dentry, redirfs_set_new_ops, (void *)root, NULL, NULL);
	redirfs_walk_roots(root, redirfs_detach_flt, (void *)flt);
	redirfs_remove_roots(flt);

	ptr->ptr_val = (void *)root;

	goto ret;

free_mem:
	redirfs_free_root(root);
ret:
	spin_unlock(&redirfs_root_list);
	return rv;
}

EXPORT_SYMBOL(redirfs_include_path);
EXPORT_SYMBOL(redirfs_exclude_path);
