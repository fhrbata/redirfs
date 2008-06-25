#include "../redirfs/redirfs.h"

#define DUMMYFLT_VERSION "0.2"

static redirfs_filter dummyflt;

static struct redirfs_filter_info dummyflt_info = {
	.owner = THIS_MODULE,
	.name = "dummyflt",
	.priority = 1,
	.active = 1
};

enum redirfs_rv dummyflt_open(redirfs_context context,
		struct redirfs_args *args)
{
	char path[PAGE_SIZE];
	char *call;
	int rv;

	rv = redirfs_get_filename(args->args.f_open.file->f_vfsmnt,
			args->args.f_open.file->f_dentry, path, PAGE_SIZE);

	if (rv) {
		printk(KERN_ERR "dummyflt: rfs_get_filename failed(%d)\n", rv);
		return REDIRFS_CONTINUE;
	}

	call = args->type.call == REDIRFS_PRECALL ? "precall" : "postcall";

	printk(KERN_ALERT "dummyflt: open: %s, call: %s\n", path, call);

	return REDIRFS_CONTINUE;
}

enum redirfs_rv dummyflt_release(redirfs_context context,
		struct redirfs_args *args)
{
	char path[PAGE_SIZE];
	char *call;
	int rv;

	rv = redirfs_get_filename(args->args.f_release.file->f_vfsmnt,
			args->args.f_release.file->f_dentry, path, PAGE_SIZE);

	if (rv) {
		printk(KERN_ERR "dummyflt: rfs_get_filename failed(%d)\n", rv);
		return REDIRFS_CONTINUE;
	}

	call = args->type.call == REDIRFS_PRECALL ? "precall" : "postcall";

	printk(KERN_ALERT "dummyflt: release: %s, call: %s\n", path, call);

	return REDIRFS_CONTINUE;
}

enum redirfs_rv dummyflt_permission(redirfs_context context,
		struct redirfs_args *args)
{
	char path[PAGE_SIZE];
	char *call;
	int rv;

	if (!args->args.i_permission.nd)
		return REDIRFS_CONTINUE;

	rv = redirfs_get_filename(args->args.i_permission.nd->path.mnt,
			args->args.i_permission.nd->path.dentry, path, PAGE_SIZE);

	if (rv) {
		printk(KERN_ERR "dummyflt: rfs_get_filename failed(%d)\n", rv);
		return REDIRFS_CONTINUE;
	}

	call = args->type.call == REDIRFS_PRECALL ? "precall" : "postcall";

	printk(KERN_ALERT "dummyflt: permission: %s, call: %s\n", path, call);

	return REDIRFS_CONTINUE;
}

static struct redirfs_op_info dummyflt_op_info[] = {
	{REDIRFS_REG_FOP_OPEN, dummyflt_open, dummyflt_open},
	{REDIRFS_REG_FOP_RELEASE, dummyflt_release, dummyflt_release},
	{REDIRFS_DIR_FOP_OPEN, dummyflt_open, dummyflt_open},
	{REDIRFS_DIR_FOP_RELEASE, dummyflt_release, dummyflt_release},
	{REDIRFS_REG_IOP_PERMISSION, dummyflt_permission, dummyflt_permission},
	{REDIRFS_DIR_IOP_PERMISSION, dummyflt_permission, dummyflt_permission},
	{REDIRFS_OP_END, NULL, NULL}
};


static int __init dummyflt_init(void)
{
	int err;

	err = redirfs_register_filter(&dummyflt, &dummyflt_info);
	if (err) {
		printk(KERN_ERR "dummyflt: register filter failed(%d)\n", err);
		return err;
	}

	err = redirfs_set_operations(dummyflt, dummyflt_op_info);
	if (err) {
		redirfs_unregister_filter(dummyflt);
		printk(KERN_ERR "dummyflt: set operations failed(%d)\n", err);
		return err;
	}

	printk(KERN_INFO "Dummy Filter Version "
			DUMMYFLT_VERSION "<www.redirfs.org>\n");

	return 0;
}

static void __exit dummyflt_exit(void)
{
	redirfs_delete_filter(dummyflt);
}

module_init(dummyflt_init);
module_exit(dummyflt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frantisek Hrbata <frantisek.hrbata@redirfs.org>");
MODULE_DESCRIPTION("Dummy Filter Version " DUMMYFLT_VERSION "<www.redirfs.org>");

