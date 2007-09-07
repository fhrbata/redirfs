#include "avflt.h"

struct file *avflt_get_file(struct file *file)
{
	struct file *f;
	struct file_operations *fops;
	
	fops = kmalloc(sizeof(struct file_operations), GFP_KERNEL);
	if (!fops)
		return ERR_PTR(-ENOMEM);

	f = get_empty_filp();

	if (!f) {
		kfree(fops);
		return ERR_PTR(-ENFILE);
	}

	memcpy(fops, file->f_op, sizeof(struct file_operations));
	fops->owner = THIS_MODULE;
	fops->release = NULL;

	f->f_path.mnt = mntget(file->f_vfsmnt);
	f->f_path.dentry = dget(file->f_dentry);
	f->f_mapping = file->f_path.dentry->d_inode->i_mapping;

	f->f_pos = 0;
	f->f_flags = O_RDONLY;
	f->f_op = fops_get(fops);
	f->f_mode = FMODE_READ;
	f->f_version = 0;

	return f;
}

void avflt_put_file(struct file *file)
{
	const struct file_operations *fops;

	fops = file->f_op;
	fput(file);
	kfree(fops);
}
