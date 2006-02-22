#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/smp_lock.h>
#include <linux/stat.h>
#include <linux/version.h>
#include "redirfs.h"
#include "operations.h"
#include "root.h"
#include "inode.h"
#include "file.h"
#include "debug.h"

extern spinlock_t redirfs_ihash_lock;
extern spinlock_t inode_lock;
extern spinlock_t redirfs_flt_list_lock;
extern int redirfs_proc_init(void);
extern void redirfs_proc_destroy(void);
struct redirfs_operations_t redirfs_fw_ops;
struct redirfs_vfs_operations_t redirfs_vfs_ops;

static int redirfs_pre_call_filters(struct redirfs_root_t *root, int type, int op, struct redirfs_context_t *context,  struct redirfs_args_t *args)
{
	struct redirfs_flt_t *flt;
	int rv = REDIRFS_RETV_CONTINUE;
	void ***pre_ops;
	struct redirfs_flt_arr_t flt_arr;
	int i = 0;
	enum redirfs_retv (*operation)(redirfs_context *, struct redirfs_args_t *) = NULL;


	args->info.type = type;
	args->info.op = op;
	
	redirfs_flt_arr_init(&flt_arr);
	if (redirfs_flt_arr_copy(&root->attached_flts, &flt_arr))
		BUG();

	for(i = 0; i < flt_arr.cnt; i++) {
		flt = flt_arr.arr[i];
		
		if (!atomic_read(&flt->active))
			continue;

		spin_lock(&flt->lock);

		pre_ops = redirfs_gettype(type, &flt->pre_ops);
		if (*pre_ops[op]) 
			operation = (enum redirfs_retv (*)(redirfs_context *, struct redirfs_args_t *)) (*pre_ops[op]);

		spin_unlock(&flt->lock);

		if (operation) {
			rv = operation((void *)context, args);
			if (rv == REDIRFS_RETV_STOP)
				break;
		}
	}

	redirfs_flt_arr_destroy(&flt_arr);

	return rv;
}

static int redirfs_post_call_filters(struct redirfs_root_t *root, int type, int op, struct redirfs_context_t *context, struct redirfs_args_t *args)
{
	struct redirfs_flt_t *flt;
	int rv = REDIRFS_RETV_CONTINUE;
	void ***post_ops;
	struct redirfs_flt_arr_t flt_arr;
	int i = 0;
	enum redirfs_retv (*operation)(redirfs_context *, struct redirfs_args_t *) = NULL;

	
	redirfs_flt_arr_init(&flt_arr);
	if (redirfs_flt_arr_copy(&root->attached_flts, &flt_arr))
		BUG();

	for(i = flt_arr.cnt - 1; i >=0; i--) {
		flt = flt_arr.arr[i];
		
		if (!atomic_read(&flt->active))
			continue;

		spin_lock(&flt->lock);

		post_ops = redirfs_gettype(type, &flt->post_ops);
		if (*post_ops[op]) 
			operation = (enum redirfs_retv (*)(redirfs_context *, struct redirfs_args_t *)) (*post_ops[op]);

		spin_unlock(&flt->lock);

		if (operation) {
			rv = operation((void *)context, args);
			if (rv == REDIRFS_RETV_STOP)
				break;
		}
	}

	redirfs_flt_arr_destroy(&flt_arr);

	return rv;

}

static void redirfs_d_iput(struct dentry *dentry, struct inode *inode)
{
	struct redirfs_inode_t *rinode;
	struct redirfs_root_t *root;
	struct redirfs_args_t args;
	char buff[PAGE_SIZE];
	void (*d_iput)(struct dentry *, struct inode *) = NULL; 
	

	rinode = redirfs_ifind(inode->i_sb, inode->i_ino);

	if (!rinode) {
		if (dentry->d_op->d_iput != redirfs_d_iput) {
			if (dentry->d_op->d_iput) {
				dentry->d_op->d_iput(dentry, inode);
				return;
			} else 
				return;
		} else {
			BUG();
			return;
		}
	}

	root = redirfs_rget(rinode->root);
	BUG_ON(!rinode->root);

	spin_lock(&root->lock);
	dentry->d_op = root->orig_ops.dops;

	if (S_ISREG(inode->i_mode)) {
		inode->i_op = root->orig_ops.reg_iops;
		inode->i_fop = root->orig_ops.reg_fops;

	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = root->orig_ops.dir_iops;
		inode->i_fop = root->orig_ops.dir_fops;
	}

	args.args.d_iput.dentry = dentry;
	args.args.d_iput.inode = inode;
	args.info.call = REDIRFS_PRECALL;

	if (root->orig_ops.dops && root->orig_ops.dops->d_iput)
		d_iput = root->orig_ops.dops->d_iput;

	spin_unlock(&root->lock);

	args.exts.full_path = redirfs_dpath(dentry, buff, PAGE_SIZE);

	redirfs_pre_call_filters(root, REDIRFS_DENTRY, REDIRFS_DOP_IPUT, NULL, &args);
	if (d_iput)
		d_iput(dentry, inode);
	else
		iput(inode);

	args.info.call = REDIRFS_POSTCALL;
	redirfs_post_call_filters(root, REDIRFS_DENTRY, REDIRFS_DOP_IPUT, NULL, &args);

	redirfs_ihash_table_remove(rinode);

	redirfs_iput(rinode);
	redirfs_rput(root);
}

static int redirfs_dir_create(struct inode *inode, struct dentry *dentry, int mode, struct nameidata *nd)
{
	struct redirfs_inode_t *rinode;
	struct redirfs_root_t *root;
	struct redirfs_args_t args;
	char buff[PAGE_SIZE];
	int aux = 0;
	int rv;


	rinode = redirfs_ifind(inode->i_sb, inode->i_ino);
	if (!rinode) {
		if (inode->i_op->create != redirfs_dir_create) {
			if (inode->i_op->create)
				return inode->i_op->create(inode, dentry, mode, nd);
			else
				return 0;
		} else {
			BUG();
			return -1;
		}
	}

	root = redirfs_rget(rinode->root);
	BUG_ON(!rinode->root);

	args.args.i_create.parent = inode;
	args.args.i_create.dentry = dentry;
	args.args.i_create.mode = mode;
	args.args.i_create.nd = nd;
	args.info.call = REDIRFS_POSTCALL;
	args.exts.full_path = redirfs_dpath(dentry, buff, PAGE_SIZE);

	rv = redirfs_pre_call_filters(root, REDIRFS_I_DIR, REDIRFS_IOP_CREATE, NULL, &args);

	if (rv == REDIRFS_RETV_STOP) {
		rv = args.retv.rv_int;
		goto exit;
	}

	rv = root->orig_ops.dir_iops->create(inode, dentry, mode, nd);
	spin_lock(&root->lock);
	aux = root->flags & REDIRFS_ROOT_REMOVE;
	spin_unlock(&root->lock);

	if (!aux && dentry->d_inode && S_ISREG(dentry->d_inode->i_mode)) {
		spin_lock(&rinode->lock);
		redirfs_rput(root);
		root = redirfs_rget(rinode->root);

		spin_lock(&root->lock);
		aux = !root->orig_ops.reg_iops;
		spin_unlock(&root->lock);

		if (aux) {
			redirfs_set_reg_ops(root, dentry->d_inode);
			redirfs_set_root_ops(root, REDIRFS_I_REG);
			redirfs_set_root_ops(root, REDIRFS_F_REG);

			spin_lock(&root->lock);
			root->new_ops.reg_fops->open = root->fw_ops->reg_fops->open;
			root->new_ops.reg_fops->release = root->fw_ops->reg_fops->release;
			spin_unlock(&root->lock);
		}

		redirfs_add_inode(root, dentry->d_inode);

		spin_lock(&root->lock);

		dentry->d_inode->i_op = root->new_ops.reg_iops;
		dentry->d_inode->i_fop = root->new_ops.reg_fops;
		dentry->d_op = root->new_ops.dops;
		
		spin_unlock(&root->lock);
		spin_unlock(&rinode->lock);
	}

	args.retv.rv_int = rv;
	args.info.call = REDIRFS_POSTCALL;
	rv = redirfs_post_call_filters(root, REDIRFS_I_DIR, REDIRFS_IOP_CREATE, NULL, &args);

	rv = args.retv.rv_int;

exit:
	redirfs_iput(rinode);
	redirfs_rput(root);
	return rv;
}

static struct dentry *redirfs_dir_lookup(struct inode *parent, struct dentry *dentry, struct nameidata *nd)
{
	struct dentry *rv = NULL;
	struct redirfs_inode_t *rinode;
	struct redirfs_root_t *root;
	struct redirfs_args_t args;
	char buff[PAGE_SIZE];
	int redirfs_rv;
	int aux = 0;


	rinode = redirfs_ifind(parent->i_sb, parent->i_ino);
	if (!rinode) {
		if (parent->i_op->lookup != redirfs_dir_lookup)
			if (parent->i_op->lookup)
				return parent->i_op->lookup(parent, dentry, nd);
			else
				return NULL;
		else {
			BUG();
			return NULL;
		}
	}

	root = redirfs_rget(rinode->root);
	BUG_ON(!rinode->root);

	args.args.i_lookup.parent = parent;
	args.args.i_lookup.dentry = dentry;
	args.args.i_lookup.nd = nd;
	args.info.call = REDIRFS_PRECALL;
	args.exts.full_path = redirfs_dpath(dentry, buff, PAGE_SIZE);

	redirfs_rv = redirfs_pre_call_filters(root, REDIRFS_I_DIR, REDIRFS_IOP_LOOKUP, NULL, &args);

	if (redirfs_rv == REDIRFS_RETV_STOP) {
		rv = args.retv.rv_dentry;
		goto exit;
	}

	rv = root->orig_ops.dir_iops->lookup(parent, dentry, nd);
	spin_lock(&root->lock);
	aux = root->flags & REDIRFS_ROOT_REMOVE;
	spin_unlock(&root->lock);

	if (!aux && dentry->d_inode && S_ISREG(dentry->d_inode->i_mode)) {
		spin_lock(&rinode->lock);
		redirfs_rput(root);
		root = redirfs_rget(rinode->root);

		spin_lock(&root->lock);
		aux = !root->orig_ops.reg_iops;
		spin_unlock(&root->lock);

		if (aux) {
			redirfs_set_reg_ops(root, dentry->d_inode);
			redirfs_set_root_ops(root, REDIRFS_I_REG);
			redirfs_set_root_ops(root, REDIRFS_F_REG);

			spin_lock(&root->lock);
			root->new_ops.reg_fops->open = root->fw_ops->reg_fops->open;
			root->new_ops.reg_fops->release = root->fw_ops->reg_fops->release;
			spin_unlock(&root->lock);
		}

		redirfs_add_inode(root, dentry->d_inode);

		spin_lock(&root->lock);

		dentry->d_inode->i_op = root->new_ops.reg_iops;
		dentry->d_inode->i_fop = root->new_ops.reg_fops;
		dentry->d_op = root->new_ops.dops;

		spin_unlock(&root->lock);
		spin_unlock(&rinode->lock);

	} else if (!aux && dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode) && !dentry->d_mounted) {
		spin_lock(&rinode->lock);
		redirfs_rput(root);
		root = redirfs_rget(rinode->root);

		spin_lock(&root->lock);
		aux = !root->orig_ops.dir_iops;
		spin_unlock(&root->lock);

		if (aux) {
			redirfs_set_dir_ops(root, dentry->d_inode);
			redirfs_set_root_ops(root, REDIRFS_I_DIR);
			redirfs_set_root_ops(root, REDIRFS_F_DIR);

			spin_lock(&root->lock);
			root->new_ops.dir_iops->lookup = root->fw_ops->dir_iops->lookup;
			root->new_ops.dir_iops->mkdir = root->fw_ops->dir_iops->mkdir;
			root->new_ops.dir_iops->create = root->fw_ops->dir_iops->create;
			root->new_ops.dir_fops->open = root->fw_ops->dir_fops->open;
			root->new_ops.dir_fops->release = root->fw_ops->dir_fops->release;
			spin_unlock(&root->lock);
		}

		redirfs_add_inode(root, dentry->d_inode);

		spin_lock(&root->lock);

		dentry->d_inode->i_op = root->new_ops.dir_iops;
		dentry->d_inode->i_fop = root->new_ops.dir_fops;
		dentry->d_op = root->new_ops.dops;

		spin_unlock(&root->lock);
		spin_unlock(&rinode->lock);
	}

	args.retv.rv_dentry = rv;
	args.info.call = REDIRFS_POSTCALL;

	redirfs_rv = redirfs_post_call_filters(root, REDIRFS_I_DIR, REDIRFS_IOP_LOOKUP, NULL, &args);

	rv = args.retv.rv_dentry;
exit:
	redirfs_iput(rinode);
	redirfs_rput(root);
	return rv;
}

static int redirfs_dir_mkdir(struct inode *parent, struct dentry *dentry, int mode)
{
	struct redirfs_inode_t *rinode;
	struct redirfs_root_t *root;
	struct redirfs_args_t args;
	char buff[PAGE_SIZE];
	int rv;
	int aux = 0;


	rinode = redirfs_ifind(parent->i_sb, parent->i_ino);
	if (!rinode) {
		if (parent->i_op->mkdir != redirfs_dir_mkdir)
			if (parent->i_op->mkdir)
				return parent->i_op->mkdir(parent, dentry, mode);
			else
				return -EPERM;
		else {
			BUG();
			return -EPERM;
		}
	}
		
	root = redirfs_rget(rinode->root);
	BUG_ON(!rinode->root);

	args.args.i_mkdir.parent = parent;
	args.args.i_mkdir.dentry = dentry;
	args.args.i_mkdir.mode = mode;
	args.info.call = REDIRFS_PRECALL;
	args.exts.full_path = redirfs_dpath(dentry, buff, PAGE_SIZE);

	rv = redirfs_pre_call_filters(root, REDIRFS_I_DIR, REDIRFS_IOP_MKDIR, NULL, &args);

	if (rv == REDIRFS_RETV_STOP) {
		rv = args.retv.rv_int;
		goto exit;
	}

	rv = root->orig_ops.dir_iops->mkdir(parent, dentry, mode);
	spin_lock(&root->lock);
	aux = root->flags & REDIRFS_ROOT_REMOVE;
	spin_unlock(&root->lock);

	if (!aux && dentry->d_inode)
		spin_lock(&rinode->lock);
		redirfs_rput(root);
		root = redirfs_rget(rinode->root);

		redirfs_add_inode(root, dentry->d_inode);

		spin_lock(&root->lock);
		dentry->d_inode->i_op = root->new_ops.dir_iops;
		dentry->d_inode->i_fop = root->new_ops.dir_fops;
		dentry->d_op = root->new_ops.dops;
		spin_unlock(&root->lock);

		spin_unlock(&rinode->lock);

	args.retv.rv_int = rv;
	args.info.call = REDIRFS_POSTCALL;

	rv = redirfs_post_call_filters(root, REDIRFS_I_DIR, REDIRFS_IOP_MKDIR, NULL, &args);

	rv = args.retv.rv_int;

exit:
	redirfs_iput(rinode);
	redirfs_rput(root);
	return rv;
}

static int redirfs_reg_permission(struct inode *inode, int mode, struct nameidata *nd)
{
	struct redirfs_inode_t *rinode;
	struct redirfs_root_t *root;
	struct redirfs_args_t args;
	char buff[PAGE_SIZE];
	int (*permission) (struct inode *, int, struct nameidata *) = NULL;
	int rv;
	

	rinode = redirfs_ifind(inode->i_sb, inode->i_ino);
	if (!rinode) {
		if (inode->i_op->permission != redirfs_reg_permission)
			if (inode->i_op->permission)
				return inode->i_op->permission(inode, mode, nd);
			else
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,9)
				return vfs_permission(inode, mode);
#else
				return generic_permission(inode, mode, NULL);
#endif
		else {
			BUG();
			return -EPERM;
		}
	}

	root = redirfs_rget(rinode->root);
	BUG_ON(!root);

	args.args.i_permission.inode = inode;
	args.args.i_permission.mode = mode;
	args.args.i_permission.nd = nd;
	args.info.call = REDIRFS_PRECALL;
	if (nd && nd->dentry)
		args.exts.full_path = redirfs_dpath(nd->dentry, buff, PAGE_SIZE);
	else
		args.exts.full_path = NULL;

	rv = redirfs_pre_call_filters(root, REDIRFS_I_REG, REDIRFS_IOP_PERMISSION, NULL, &args);

	if (rv == REDIRFS_RETV_STOP) {
		rv = args.retv.rv_int;
		goto exit;
	}

	spin_lock(&root->lock);
	if (root->orig_ops.reg_iops->permission)
		permission = root->orig_ops.reg_iops->permission;
	spin_unlock(&root->lock);


	if (permission)
		rv = permission(args.args.i_permission.inode, args.args.i_permission.mode, args.args.i_permission.nd);
	else
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,9)
		rv = vfs_permission(inode, mode);
#else
		rv = generic_permission(args.args.i_permission.inode, args.args.i_permission.mode, NULL);
#endif

	args.retv.rv_int = rv;
	args.info.call = REDIRFS_POSTCALL;

	rv = redirfs_post_call_filters(root, REDIRFS_I_REG, REDIRFS_IOP_PERMISSION, NULL, &args);
	
	rv = args.retv.rv_int;

exit:
	redirfs_iput(rinode);
	redirfs_rput(root);
	return rv;
}

static int redirfs_reg_open(struct inode *inode, struct file *file)
{
	struct redirfs_inode_t *rinode;
	struct redirfs_root_t *root;
	struct redirfs_args_t args;
	char buff[PAGE_SIZE];
	int remove_root = 0;
	int rv;
	int (*open) (struct inode *inode, struct file *file) = NULL;


	rinode = redirfs_ifind(inode->i_sb, inode->i_ino);
	if (!rinode) {
		if (file->f_op->open != redirfs_reg_open)
			if (file->f_op->open)
				return file->f_op->open(inode, file);
			else
				return 0;
		else {
			BUG();
			return 0;
		}
	}

	root = redirfs_rget(rinode->root);
	BUG_ON(!root);

	args.args.f_open.inode = inode;
	args.args.f_open.file = file;
	args.info.call = REDIRFS_PRECALL;
	args.exts.full_path = redirfs_dpath(file->f_dentry, buff, PAGE_SIZE);

	rv = redirfs_pre_call_filters(root, REDIRFS_F_REG, REDIRFS_FOP_OPEN, NULL, &args);

	if (rv == REDIRFS_RETV_STOP) {
		rv = args.retv.rv_int;
		goto exit;
	}

	spin_lock(&root->lock);
	if (root->orig_ops.reg_fops->open)
		open = root->orig_ops.reg_fops->open;
	spin_unlock(&root->lock);

	if (open)
		rv = open(inode, file);
	else
		rv = 0;
	
	args.retv.rv_int = rv;
	args.info.call = REDIRFS_POSTCALL;

	rv = redirfs_post_call_filters(root, REDIRFS_F_REG, REDIRFS_FOP_OPEN, NULL, &args);

	rv = args.retv.rv_int;

	spin_lock(&root->lock);
	remove_root = root->flags & REDIRFS_ROOT_REMOVE;
	spin_unlock(&root->lock);

	if (!remove_root)
		redirfs_add_file(root, file);
	else 
		file->f_op = root->orig_ops.reg_fops;

exit:
	redirfs_iput(rinode);
	redirfs_rput(root);
	return rv;

}

static int redirfs_reg_release(struct inode *inode, struct file *file)
{
	struct redirfs_inode_t *rinode;
	struct redirfs_root_t *root;
	struct redirfs_args_t args;
	char buff[PAGE_SIZE];
	int (*release) (struct inode *, struct file *) = NULL;
	int rv;


	rinode = redirfs_ifind(inode->i_sb, inode->i_ino);
	if (!rinode) {
		if (file->f_op->release != redirfs_reg_release)
			if (file->f_op->release)
				return file->f_op->release(inode, file);
			else
				return 0;
		else {
			BUG();
			return 0;
		}
	}

	root = redirfs_rget(rinode->root);
	BUG_ON(!root);

	redirfs_remove_file(root, file);

	args.args.f_release.inode = inode;
	args.args.f_release.file = file;
	args.info.call = REDIRFS_PRECALL;
	args.exts.full_path = redirfs_dpath(file->f_dentry, buff, PAGE_SIZE);

	rv = redirfs_pre_call_filters(root, REDIRFS_F_REG, REDIRFS_FOP_RELEASE, NULL, &args);
	

	if (rv == REDIRFS_RETV_STOP) {
		rv = args.retv.rv_int;
		goto exit;
	}

	spin_lock(&root->lock);
	if (root->orig_ops.reg_fops->release)
		release = root->orig_ops.reg_fops->release;
	spin_unlock(&root->lock);

	if (release)
		rv = release(inode, file);
	else
		rv = 0;

	args.retv.rv_int = rv;
	args.info.call = REDIRFS_POSTCALL;

	rv = redirfs_post_call_filters(root, REDIRFS_F_REG, REDIRFS_FOP_RELEASE, NULL, &args);

	rv = args.retv.rv_int;

exit:
	redirfs_iput(rinode);
	redirfs_rput(root);
	return rv;
}

static int redirfs_dir_open(struct inode *inode, struct file *file)
{
	struct redirfs_inode_t *rinode;
	struct redirfs_root_t *root;
	struct redirfs_args_t args;
	char buff[PAGE_SIZE];
	int remove_root = 0;
	int rv;
	int (*open) (struct inode *inode, struct file *file) = NULL;


	rinode = redirfs_ifind(inode->i_sb, inode->i_ino);
	if (!rinode) {
		if (file->f_op->open != redirfs_dir_open)
			if (file->f_op->open)
				return file->f_op->open(inode, file);
			else
				return 0;
		else {
			BUG();
			return 0;
		}
	}

	root = redirfs_rget(rinode->root);
	BUG_ON(!root);

	args.args.f_open.inode = inode;
	args.args.f_open.file = file;
	args.info.call = REDIRFS_PRECALL;
	args.exts.full_path = redirfs_dpath(file->f_dentry, buff, PAGE_SIZE);

	rv = redirfs_pre_call_filters(root, REDIRFS_F_DIR, REDIRFS_FOP_OPEN, NULL, &args);

	if (rv == REDIRFS_RETV_STOP) {
		rv = args.retv.rv_int;
		goto exit;
	}

	spin_lock(&root->lock);
	if (root->orig_ops.dir_fops->open)
		open = root->orig_ops.dir_fops->open;
	spin_unlock(&root->lock);

	if (open)
		rv = open(inode, file);
	else
		rv = 0;
	
	args.retv.rv_int = rv;
	args.info.call = REDIRFS_POSTCALL;

	rv = redirfs_post_call_filters(root, REDIRFS_F_DIR, REDIRFS_FOP_OPEN, NULL, &args);

	rv = args.retv.rv_int;

	spin_lock(&root->lock);
	remove_root = root->flags & REDIRFS_ROOT_REMOVE;
	spin_unlock(&root->lock);

	if (!remove_root)
		redirfs_add_file(root, file);
	else
		file->f_op = root->orig_ops.dir_fops;

exit:
	redirfs_iput(rinode);
	redirfs_rput(root);
	return rv;

}

static int redirfs_dir_release(struct inode *inode, struct file *file)
{
	struct redirfs_inode_t *rinode;
	struct redirfs_root_t *root;
	struct redirfs_args_t args;
	char buff[PAGE_SIZE];
	int (*release) (struct inode *, struct file *) = NULL;
	int rv;


	rinode = redirfs_ifind(inode->i_sb, inode->i_ino);
	if (!rinode) {
		if (file->f_op->release != redirfs_dir_release)
			if (file->f_op->release)
				return file->f_op->release(inode, file);
			else
				return 0;
		else {
			BUG();
			return 0;
		}
	}

	root = redirfs_rget(rinode->root);
	BUG_ON(!root);

	redirfs_remove_file(root, file);

	args.args.f_release.inode = inode;
	args.args.f_release.file = file;
	args.info.call = REDIRFS_PRECALL;
	args.exts.full_path = redirfs_dpath(file->f_dentry, buff, PAGE_SIZE);

	rv = redirfs_pre_call_filters(root, REDIRFS_F_DIR, REDIRFS_FOP_RELEASE, NULL, &args);
	
	if (rv == REDIRFS_RETV_STOP) {
		rv = args.retv.rv_int;
		goto exit;
	}

	spin_lock(&root->lock);
	if (root->orig_ops.dir_fops->release)
		release = root->orig_ops.dir_fops->release;
	spin_unlock(&root->lock);


	if (release)
		rv = release(inode, file);
	else
		rv = 0;

	args.retv.rv_int = rv;
	args.info.call = REDIRFS_POSTCALL;

	rv = redirfs_post_call_filters(root, REDIRFS_F_DIR, REDIRFS_FOP_RELEASE, NULL, &args);

	rv = args.retv.rv_int;

exit:
	redirfs_iput(rinode);
	redirfs_rput(root);
	return rv;
}

static int redirfs_reg_flush(struct file *file)
{
	struct redirfs_inode_t *rinode;
	struct redirfs_root_t *root;
	struct redirfs_args_t args;
	char buff[PAGE_SIZE];
	int (*flush) (struct file *) = NULL;
	int rv;

	rinode = redirfs_ifind(file->f_dentry->d_inode->i_sb, file->f_dentry->d_inode->i_ino);
	if (!rinode) {
		if (file->f_op->flush != redirfs_reg_flush)
			if (file->f_op->flush)
				file->f_op->flush(file);
			else
				return 0;
		else {
			BUG();
			return 0;
		}
	}

	root = redirfs_rget(rinode->root);
	BUG_ON(!root);

	args.args.f_flush.file = file;
	args.info.call = REDIRFS_PRECALL;
	args.exts.full_path = redirfs_dpath(file->f_dentry, buff, PAGE_SIZE);

	rv = redirfs_pre_call_filters(root, REDIRFS_F_REG, REDIRFS_FOP_FLUSH, NULL, &args);
	if (rv == REDIRFS_RETV_STOP) {
		rv = args.retv.rv_int;
		goto exit;
	}

	spin_lock(&root->lock);
	if (root->orig_ops.reg_fops->flush)
		flush = root->orig_ops.reg_fops->flush;
	spin_unlock(&root->lock);

	if (flush)
		rv = flush(file);
	else
		rv = 0;

	args.retv.rv_int = rv;
	args.info.call = REDIRFS_POSTCALL;
	rv = redirfs_post_call_filters(root, REDIRFS_F_REG, REDIRFS_FOP_FLUSH, NULL, &args);
	rv = args.retv.rv_int;

exit:
	redirfs_iput(rinode);
	redirfs_rput(root);
	return rv;
}

static int redirfs_dir_unlink(struct inode *inode, struct dentry *dentry)
{
	struct redirfs_inode_t *rinode;
	struct redirfs_root_t *root;
	struct redirfs_args_t args;
	char buff[PAGE_SIZE];
	int (*unlink) (struct inode *, struct dentry *) = NULL;
	int rv;

	rinode = redirfs_ifind(inode->i_sb, inode->i_ino);
	if (!rinode) {
		if (inode->i_op->unlink != redirfs_dir_unlink)
			if (inode->i_op->unlink)
				inode->i_op->unlink(inode, dentry);
			else
				return -EPERM;
		else {
			BUG();
			return -EPERM;
		}
	}

	root = redirfs_rget(rinode->root);
	BUG_ON(!root);

	args.args.i_unlink.dir = inode;
	args.args.i_unlink.dentry = dentry;
	args.info.call = REDIRFS_PRECALL;
	args.exts.full_path = redirfs_dpath(dentry, buff, PAGE_SIZE);

	rv = redirfs_pre_call_filters(root, REDIRFS_I_DIR, REDIRFS_IOP_UNLINK, NULL, &args);
	if (rv == REDIRFS_RETV_STOP) {
		rv = args.retv.rv_int;
		goto exit;
	}

	spin_lock(&root->lock);
	if (root->orig_ops.dir_iops->unlink)
		unlink = root->orig_ops.dir_iops->unlink;
	spin_unlock(&root->lock);

	if (unlink)
		rv = unlink(inode, dentry);
	else
		rv = 0;

	args.retv.rv_int = rv;
	args.info.call = REDIRFS_POSTCALL;
	rv = redirfs_post_call_filters(root, REDIRFS_I_DIR, REDIRFS_IOP_UNLINK, NULL, &args);
	rv = args.retv.rv_int;

exit:
	redirfs_iput(rinode);
	redirfs_rput(root);
	return rv;

}

static int redirfs_dir_rmdir(struct inode *inode, struct dentry *dentry)
{
	struct redirfs_inode_t *rinode;
	struct redirfs_root_t *root;
	struct redirfs_args_t args;
	char buff[PAGE_SIZE];
	int (*rmdir) (struct inode *, struct dentry *) = NULL;
	int rv;

	rinode = redirfs_ifind(inode->i_sb, inode->i_ino);
	if (!rinode) {
		if (inode->i_op->rmdir != redirfs_dir_rmdir)
			if (inode->i_op->rmdir)
				inode->i_op->rmdir(inode, dentry);
			else
				return -EPERM;
		else {
			BUG();
			return -EPERM;
		}
	}

	root = redirfs_rget(rinode->root);
	BUG_ON(!root);

	args.args.i_rmdir.dir = inode;
	args.args.i_rmdir.dentry = dentry;
	args.info.call = REDIRFS_PRECALL;
	args.exts.full_path = redirfs_dpath(dentry, buff, PAGE_SIZE);

	rv = redirfs_pre_call_filters(root, REDIRFS_I_DIR, REDIRFS_IOP_RMDIR, NULL, &args);
	if (rv == REDIRFS_RETV_STOP) {
		rv = args.retv.rv_int;
		goto exit;
	}

	spin_lock(&root->lock);
	if (root->orig_ops.dir_iops->rmdir)
		rmdir= root->orig_ops.dir_iops->rmdir;
	spin_unlock(&root->lock);

	if (rmdir)
		rv = rmdir(inode, dentry);
	else
		rv = 0;

	args.retv.rv_int = rv;
	args.info.call = REDIRFS_POSTCALL;
	rv = redirfs_post_call_filters(root, REDIRFS_I_DIR, REDIRFS_IOP_RMDIR, NULL, &args);
	rv = args.retv.rv_int;

exit:
	redirfs_iput(rinode);
	redirfs_rput(root);
	return rv;


}

static int __init redirfs_init(void)
{
	int rv = 0;


	redirfs_init_ops(&redirfs_fw_ops, &redirfs_vfs_ops);

	redirfs_fw_ops.dops->d_iput = redirfs_d_iput;
	redirfs_fw_ops.dir_iops->create = redirfs_dir_create;
	redirfs_fw_ops.dir_iops->lookup = redirfs_dir_lookup;
	redirfs_fw_ops.dir_iops->mkdir = redirfs_dir_mkdir;
	redirfs_fw_ops.reg_iops->permission = redirfs_reg_permission;
	redirfs_fw_ops.reg_fops->open = redirfs_reg_open;
	redirfs_fw_ops.reg_fops->release = redirfs_reg_release;
	redirfs_fw_ops.dir_fops->open = redirfs_dir_open;
	redirfs_fw_ops.dir_fops->release = redirfs_dir_release;
	redirfs_fw_ops.reg_fops->flush= redirfs_reg_flush;
	redirfs_fw_ops.dir_iops->unlink = redirfs_dir_unlink;
	redirfs_fw_ops.dir_iops->rmdir = redirfs_dir_rmdir;

	rv = redirfs_init_ihash_table(1<<14);
	if (rv) goto out;

	rv = redirfs_init_fhash_table(1<<14);
	if (rv) goto no_fhash_table;

	redirfs_init_icache();
	redirfs_init_fcache();

#ifdef CONFIG_PROC_FS
	rv = redirfs_proc_init();
	if (rv) goto no_proc_init;
#endif
	goto out;

no_proc_init:
	redirfs_destroy_fcache();
	redirfs_destroy_icache();
	redirfs_destroy_fhash_table();
no_fhash_table:
	redirfs_destroy_ihash_table();
out:
	return rv;
}

static void __exit redirfs_exit(void)
{
	redirfs_destroy_icache();
	redirfs_destroy_fcache();
	redirfs_destroy_ihash_table();
	redirfs_destroy_fhash_table();

#ifdef CONFIG_PROC_FS
	redirfs_proc_destroy();
#endif
}

module_init(redirfs_init);
module_exit(redirfs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frantisek Hrbata <franta@redirfs.org>");
MODULE_DESCRIPTION("RedirFS Framework allows to notify 3rd-party modules about events in the VFS layer");
