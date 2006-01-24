#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include "../redirfs/redirfs.h"

redirfs_filter dummyflt;

static enum redirfs_retv dymmyflt_pre_permission(redirfs_context context,
		struct redirfs_args_t *args)
{
	mode_t mode;
	struct dentry *dentry;
	const unsigned char *name = "unknown";

	
	mode = args->args.i_permission.mode;
	if (args->args.i_permission.nd) {
		dentry = args->args.i_permission.nd->dentry;
		name = dentry->d_name.name;
	}

	switch (mode) {
		case MAY_EXEC:
			printk(KERN_ALERT "dummyflt: %s - exec\n", name);
			break;
		case MAY_WRITE:
			printk(KERN_ALERT "dummyflt: %s - write\n", name);
			break;
		case MAY_READ:
			printk(KERN_ALERT "dummyflt: %s - read\n", name);
			break;
		case MAY_APPEND:
			printk(KERN_ALERT "dummyflt: %s - append\n", name);
			break;
		default:
			printk(KERN_ALERT "dummyflt: %s - unknown\n", name);
	}
	
	return REDIRFS_RETV_CONTINUE;
}

static enum redirfs_retv dymmyflt_pre_open(redirfs_context context,
		struct redirfs_args_t *args)
{
	const unsigned char *name;


	name = args->args.f_open.file->f_dentry->d_name.name;
	printk(KERN_ALERT "dummyflt: %s - open\n", name);

	return REDIRFS_RETV_CONTINUE;
}

static struct redirfs_op_t dummyflt_ops[] = {
	{REDIRFS_I_REG, REDIRFS_IOP_PERMISSION, dymmyflt_pre_permission, NULL},
	{REDIRFS_F_REG, REDIRFS_FOP_OPEN, dymmyflt_pre_open, NULL},
	REDIRFS_OP_END
};

static int __init dummyflt_init(void)
{
	char name[] = "dummyflt";
	int priority = 66;
	unsigned long flags = 0;
	int error = 0;

	
	dummyflt = redirfs_register_filter(name, priority, flags);
	if (IS_ERR(dummyflt)) return PTR_ERR(dummyflt);
	
	error = redirfs_set_operations(dummyflt, dummyflt_ops);
	if (error) goto unregister;
	
	error = redirfs_include_path(dummyflt, "/usr");
	if (error) goto unregister;
	
	error = redirfs_include_path(dummyflt, "/tmp");
	if (error) goto unregister;
	
	redirfs_activate_filter(dummyflt);

	return 0;

unregister:
	redirfs_unregister_filter(dummyflt);
	return error;
}

static void __exit dummyflt_exit(void)
{
	redirfs_unregister_filter(dummyflt);
}

module_init(dummyflt_init);
module_exit(dummyflt_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Frantisek Hrbata <franta@grisoft.cz>");
MODULE_VERSION("v0.001");
MODULE_DESCRIPTION("Dummy Filter for the RedirFS Framework");
