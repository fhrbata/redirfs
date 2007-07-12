#include "../redirfs/redirfs.h"

enum rfs_retv dummyflt_permission(rfs_context context, struct rfs_args *args);
enum rfs_retv dummyflt_open(rfs_context context, struct rfs_args *args);
int dummyflt_ctl(struct rfs_ctl *ctl);

static rfs_filter dummyflt;
static struct rfs_path_info path_info;
static struct rfs_filter_info flt_info = {"dummyflt", 1000, 0, dummyflt_ctl};

static struct rfs_op_info op_info[] = {
	{RFS_REG_IOP_PERMISSION, dummyflt_permission, dummyflt_permission},
	{RFS_DIR_IOP_PERMISSION, dummyflt_permission, dummyflt_permission},
	{RFS_REG_FOP_OPEN, dummyflt_open, dummyflt_open},
	{RFS_DIR_FOP_OPEN, dummyflt_open, dummyflt_open},
	{RFS_OP_END, NULL, NULL}
};

int dummyflt_ctl(struct rfs_ctl *ctl)
{
	int err = 0;

	switch (ctl->id) {
		case RFS_CTL_ACTIVATE:
			err = rfs_activate_filter(dummyflt);
			printk(KERN_ALERT "dummyflt: ctl: RFS_CTL_ACTIVATE(%d)\n", err);
			break;

		case RFS_CTL_DEACTIVATE:
			err = rfs_deactivate_filter(dummyflt);
			printk(KERN_ALERT "dummyflt: ctl: RFS_CTL_DEACTIVATE(%d)\n", err);
			break;

		case RFS_CTL_SETPATH:
			err = rfs_set_path(dummyflt, &ctl->data.path_info); 
			printk(KERN_ALERT "dummyflt: ctl: RFS_CTL_SETPATH(%d)\n", err);
			break;
	}

	return err;
}

enum rfs_retv dummyflt_permission(rfs_context context, struct rfs_args *args)
{
	char path[PAGE_SIZE];
	char *call;
	int rv;

	if (!args->args.i_permission.nd)
		return RFS_CONTINUE;

	rv = rfs_get_filename(args->args.i_permission.nd->dentry, path, PAGE_SIZE);
	if (rv) {
		printk(KERN_ALERT "dummyflt: rfs_get_filename failed\n");
		return RFS_CONTINUE;
	}

	call = args->type.call == RFS_PRECALL ? "precall" : "postcall";

	printk(KERN_ALERT "dummyflt: permission: path: %s, call: %s\n", path, call);

	return RFS_CONTINUE;
}

enum rfs_retv dummyflt_open(rfs_context context, struct rfs_args *args)
{
	char path[PAGE_SIZE];
	char *call;
	int rv;

	if (!args->args.i_permission.nd)
		return RFS_CONTINUE;

	rv = rfs_get_filename(args->args.i_permission.nd->dentry, path, PAGE_SIZE);
	if (rv) {
		printk(KERN_ALERT "dummyflt: rfs_get_filename failed\n");
		return RFS_CONTINUE;
	}

	call = args->type.call == RFS_PRECALL ? "precall" : "postcall";

	printk(KERN_ALERT "dummyflt: open: path: %s, call: %s\n", path, call);

	return RFS_CONTINUE;

}

static int __init dummyflt_init(void)
{
	int err;

	err = rfs_register_filter(&dummyflt, &flt_info);
	if (err) {
		printk(KERN_ERR "dummyflt: register filter failed: error %d\n", err);
		goto error;
	}

	err = rfs_set_operations(dummyflt, op_info); 
	if (err) {
		printk(KERN_ERR "dummyflt: set operations failed: error %d\n", err);
		goto error;
	}

/* NOTE: 2007-07-06 Frantisek Hrbata
 * 
 * The sysfs interface(/sys/fs/redirfs/dummyflt/paths) can be used to include or exclude paths

#error "Please fill the path_info.path variable with the full pathname which you want to use and delete this line!!!"

	path_info.path = "";
	path_info.flags = RFS_PATH_INCLUDE | RFS_PATH_SUBTREE;

	err = rfs_set_path(dummyflt, &path_info); 
	if (err) {
		printk(KERN_ERR "dummyflt: set path failed: error %d\n", err);
		goto error;
	}
*/

	err = rfs_activate_filter(dummyflt);
	if (err) {
		printk(KERN_ERR "dummyflt: activate filter failed: error %d\n", err);
		goto error;
	}

	return 0;

error:
	if (rfs_unregister_filter(dummyflt))
		printk(KERN_ERR "dummyflt: unregister filter failed: error %d\n", err);

	return err;
}

static void __exit dummyflt_exit(void)
{
	int err;
	
	err = rfs_unregister_filter(dummyflt);
	if (err)
		printk(KERN_ERR "dummyflt: unregistration failed: error %d\n", err);
}

module_init(dummyflt_init);
module_exit(dummyflt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frantisek Hrbata <franta@redirfs.org>");
MODULE_DESCRIPTION("Dummy Filter for the RedirFS Framework");
