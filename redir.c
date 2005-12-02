#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/smp_lock.h>
#include <linux/stat.h>
#include "redirfs.h"
#include "operations.h"
#include "root.h"
#include "inode.h"

extern spinlock_t redirfs_ihash_lock;
extern spinlock_t inode_lock;
extern spinlock_t redirfs_flt_list_lock;
struct redirfs_operations_t redirfs_fw_ops;
struct redirfs_vfs_operations_t redirfs_vfs_ops;

static int redirfs_pre_call_filters(struct redirfs_root_t *root, 
		int type,
		int op,
		struct redirfs_context_t *context, 
		struct redirfs_args_t *args)
{
	struct redirfs_ptr_t *ptr;
	struct redirfs_flt_t *flt;
	int rv = REDIRFS_RETV_CONTINUE;
	enum redirfs_retv (*operation)(redirfs_context *, struct redirfs_args_t *);
	void ***pre_ops;


	spin_lock(&redirfs_flt_list_lock);

	list_for_each_entry(ptr, &root->attached_flts, ptr_list) {
		flt = ptr->ptr_val;
		pre_ops = redirfs_gettype(type, &flt->pre_ops);

		if (*pre_ops[op]) {
			operation = (enum redirfs_retv (*)(redirfs_context *, struct redirfs_args_t *))(*pre_ops[op]);
			rv = operation((void *)context, args);
			if (rv == REDIRFS_RETV_STOP)
				break;
		}
	}

	spin_unlock(&redirfs_flt_list_lock);

	return rv;
}

static void redirfs_d_iput(struct dentry *dentry, struct inode *inode)
{
	struct redirfs_inode_t *rinode;
	struct redirfs_root_t *root;
	
	
	spin_lock(&redirfs_ihash_lock);

	rinode = redirfs_iget(inode->i_sb, inode->i_ino);
	if (!rinode) {
		spin_unlock(&redirfs_ihash_lock);
		return;
	}

	root = rinode->root;
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

	if (root->orig_ops.dops && root->orig_ops.dops->d_iput)
		root->orig_ops.dops->d_iput(dentry, inode);
	else
		iput(inode);

	list_del(&rinode->inode_root);
	redirfs_free_inode(rinode);

	spin_unlock(&root->lock);
	spin_unlock(&redirfs_ihash_lock);
}

static int redirfs_dir_create(struct inode *inode, struct dentry *dentry, int mode, struct nameidata *nd)
{
	struct redirfs_inode_t *rinode;
	struct redirfs_root_t *root;
	struct inode *i_new;
	int rv = 0;


	spin_lock(&redirfs_ihash_lock);

	rinode = redirfs_iget(inode->i_sb, inode->i_ino);
	BUG_ON(!rinode);

	root = rinode->root;
	BUG_ON(!rinode->root);

	rv = root->orig_ops.dir_iops->create(inode, dentry, mode, nd);

	if (rv) 
		goto ret;

	i_new = dentry->d_inode;

	if (S_ISREG(i_new->i_mode)) {
		spin_lock(&root->lock);

		if (!root->orig_ops.reg_iops) {
			redirfs_set_reg_ops(root, dentry->d_inode);
			redirfs_set_root_ops(root, REDIRFS_I_REG);
			redirfs_set_root_ops(root, REDIRFS_F_REG);

			spin_lock(&dcache_lock);
			spin_lock(&inode_lock);

			redirfs_replace_files_ops(root->path, root->dentry, root->new_ops.reg_fops, S_IFREG);

			spin_unlock(&dcache_lock);
			spin_unlock(&inode_lock);
		}

		redirfs_add_inode(root, dentry);

		dentry->d_inode->i_op = root->new_ops.reg_iops;
		dentry->d_inode->i_fop = root->new_ops.reg_fops;
		dentry->d_op = root->new_ops.dops;
		
		spin_unlock(&root->lock);
	}


ret:
	spin_unlock(&redirfs_ihash_lock);
	return rv;
}

static struct dentry *redirfs_dir_lookup(struct inode *parent, struct dentry *dentry, struct nameidata *nd)
{
	struct dentry *res = NULL;
	struct inode *inode = NULL;
	struct redirfs_inode_t *rinode;
	struct redirfs_root_t *root;


	spin_lock(&redirfs_ihash_lock);

	rinode = redirfs_iget(parent->i_sb, parent->i_ino);
	BUG_ON(!rinode);

	root = rinode->root;
	BUG_ON(!rinode->root);

	res = root->orig_ops.dir_iops->lookup(parent, dentry, nd);
	if (res) 
		goto ret;

	inode = dentry->d_inode;

	if (!inode || !inode->i_op)
		goto ret;

	if (S_ISREG(inode->i_mode)) {
		spin_lock(&root->lock);

		if (!root->orig_ops.reg_iops) {
			redirfs_set_reg_ops(root, dentry->d_inode);
			redirfs_set_root_ops(root, REDIRFS_I_REG);
			redirfs_set_root_ops(root, REDIRFS_F_REG);

			spin_lock(&dcache_lock);
			spin_lock(&inode_lock);

			redirfs_replace_files_ops(root->path, root->dentry, root->new_ops.reg_fops, S_IFREG);

			spin_unlock(&dcache_lock);
			spin_unlock(&inode_lock);
		}

		redirfs_add_inode(root, dentry);

		dentry->d_inode->i_op = root->new_ops.reg_iops;
		dentry->d_inode->i_fop = root->new_ops.reg_fops;
		dentry->d_op = root->new_ops.dops;

		spin_unlock(&root->lock);

	} else if (S_ISDIR(inode->i_mode) && !dentry->d_mounted) {
		spin_lock(&root->lock);
		
		if (!root->orig_ops.dir_iops) {
			redirfs_set_dir_ops(root, dentry->d_inode);
			redirfs_set_root_ops(root, REDIRFS_I_DIR);
			redirfs_set_root_ops(root, REDIRFS_F_DIR);

			root->new_ops.dir_iops->lookup = root->fw_ops->dir_iops->lookup;
			root->new_ops.dir_iops->mkdir = root->fw_ops->dir_iops->mkdir;
			root->new_ops.dir_iops->create = root->fw_ops->dir_iops->create;

			spin_lock(&dcache_lock);
			spin_lock(&inode_lock);

			redirfs_replace_files_ops(root->path, root->dentry, root->new_ops.dir_fops, S_IFDIR);

			spin_unlock(&dcache_lock);
			spin_unlock(&inode_lock);
		}

		redirfs_add_inode(root, dentry);

		dentry->d_inode->i_op = root->new_ops.dir_iops;
		dentry->d_inode->i_fop = root->new_ops.dir_fops;
		dentry->d_op = root->new_ops.dops;

		spin_unlock(&root->lock);
	}

ret:
	spin_lock(&redirfs_ihash_lock);
	return res;
}

static int redirfs_dir_mkdir(struct inode *parent, struct dentry *dentry, int mode)
{
	struct inode *inode;
	struct redirfs_inode_t *rinode;
	struct redirfs_root_t *root;
	int rv;


	spin_lock(&redirfs_ihash_lock);

	rinode = redirfs_iget(parent->i_sb, parent->i_ino);
	BUG_ON(!rinode);

	root = rinode->root;
	BUG_ON(!rinode->root);

	rv = root->orig_ops.dir_iops->mkdir(parent, dentry, mode);

	if (rv)
		goto ret;

	inode = dentry->d_inode;

	if (!inode)
		goto ret;

	redirfs_add_inode(root, dentry);

	spin_lock(&root->lock);
	inode->i_op = root->new_ops.dir_iops;
	inode->i_fop = root->new_ops.dir_fops;
	dentry->d_op = root->new_ops.dops;
	spin_unlock(&root->lock);

ret:
	spin_lock(&redirfs_ihash_lock);
	return rv;
}

static int redirfs_reg_permission(struct inode *inode, int mode, struct nameidata *nd)
{
	struct redirfs_inode_t *rinode;
	struct redirfs_root_t *root;
	struct redirfs_args_t args;
	int rv;
	
	if (!nd)
		return generic_permission(inode, mode, NULL);

	spin_lock(&redirfs_ihash_lock);

	rinode = redirfs_iget(inode->i_sb, inode->i_ino);
	BUG_ON(!rinode);

	root = rinode->root;
	BUG_ON(!rinode->root);

	spin_lock(&root->lock);

	args.args.i_permission.inode = inode;
	args.args.i_permission.mode = mode;
	args.args.i_permission.nd = nd;

	rv = redirfs_pre_call_filters(root, REDIRFS_I_REG, REDIRFS_IOP_PERMISSION, NULL, &args);

	if (rv == REDIRFS_RETV_STOP)
		return args.retv.rv_int;

	if (root->orig_ops.reg_iops->permission)
		return root->orig_ops.reg_iops->permission(inode, mode, nd);

	spin_unlock(&root->lock);

	spin_unlock(&redirfs_ihash_lock);

	return generic_permission(inode, mode, NULL);
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
	rv = redirfs_init_ihash(2<<14);

	if (rv)
		return rv;

	redirfs_init_icache();

	return rv;
}

static void __exit redirfs_exit(void)
{
	redirfs_destroy_icache();
	redirfs_destroy_ihash();
}

module_init(redirfs_init);
module_exit(redirfs_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Frantisek Hrbata <franta@grisoft.cz>");
MODULE_VERSION("v0.001");
MODULE_DESCRIPTION("Provides framework allowing redirect native Filesystem calls in VFS objects");
