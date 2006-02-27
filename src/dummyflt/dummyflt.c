/*
 * Include the RedirFS interface and LKM headers. The redirfs.h header file is not a part
 * of standard system directories with header files so you will need to specify the full 
 * path to the redirfs.h header file or specify the -I option during compilation.
 */
#include <linux/module.h>		/* header files for the LKM */
#include <linux/kernel.h>
#include <linux/init.h>
#include "../redirfs/redirfs.h"		/* RedirFS interface header file */

/*
 * Each Filter is represented by its handler. The Filter's handler is initialized by the 
 * redirfs_register_filter() function and it is used in every further communication with
 * the RedirFS Framework.
 */
redirfs_filter dummyflt; /* Dummy Filter handler */


/*
 * Define the pre and post callback functions. All callback functions have same interface.
 * The context argument is reserved for future use and it will allow Filter e.g. to attach
 * its private data to VFS objects. The args argument contains all arguments which are 
 * passed from the RedirFS Framework to the callback function(e.g. native filesystem call 
 * arguments, native filesystem return value, some extended arguments filled by RedirFS).
 * The callback function has to return proper redirfs_retv value(REDIRFS_RETV_CONTINUE - call
 * next Filter in chain or REDIRFS_RETV_STOP - do not call next Filter in chain).
 */
static enum redirfs_retv dymmyflt_pre_open(redirfs_context context, struct redirfs_args_t *args)
{
	/* arguments for native filesystem open call. you can change them if you need to. */
	struct inode *inode = args->args.f_open.inode; 	/* inode for opened file */
	struct file *file = args->args.f_open.file; 	/* file object for opened file */
	
	
	/* arguments from RedirFS */
	const unsigned char *path = args->exts.full_path; /* full path of newly opened file */

	
	/* callback information. this is intended to be used to distinguish between callback
	 * functions in case that you register one callback function for several callback. */
	enum redirfs_op_type op_type = args->info.type; 	/* identifies operation type(in this case REDIRFS_F_REG) */
	int op = args->info.op; 				/* identifies operation(in this case REDIRFS_FOP_OPEN) */
	enum redirfs_call_type op_call = args->info.call; 	/* identifies pre or post callback function(in this case it will have REDIRFS_PRECALL value) */


	/* return value of native filesystem call. you can change it if you need to(e.g. in
	 * this case you can disallow to open this file - set rv_int to -EPERM and return REDIRFS_RETV_STOP).
	 * Note: If you are going to change return value you have to fill it properly. */
	 /* args->retv.rv_int = -EPERM; */


        /* print out some info */
	printk(KERN_ALERT "dummyflt: pre-open callback for file: %s, inode: %p, file: %p, op_type: %d, op: %d, op_call: %d\n", path, inode, file, op_type, op, op_call);

	
	/* call next Filter in chain */
	return REDIRFS_RETV_CONTINUE;
}

static enum redirfs_retv dymmyflt_post_flush(redirfs_context context, struct redirfs_args_t *args)
{
	/* print out some info */
	printk(KERN_ALERT "dummyflt: post-open callback for file: %s\n", args->exts.full_path);

	/* call next Filter in chain */
	return REDIRFS_RETV_CONTINUE;
}

/*
 * Array of redirfs_op_t structures is used to register callback functions to RedirFS.
 * Each function is identified by type and operation. Type specifies group of
 * operations(e.g. file operations of regular file - REDIRFS_F_REG, dentry operations - REDIRFS_DENTRY,
 * inode operations of directory REDIRFS_I_DIR). Operation specifies on function from selected
 * group(e.g. file open operation - REDIRFS_FOP_OPEN, inode lookup operation - REDIRFS_IOP_LOOKUP).
 */
static struct redirfs_op_t dummyflt_ops[] = {
	{REDIRFS_F_REG, REDIRFS_FOP_OPEN, dymmyflt_pre_open, NULL},	/* pre-open callback function for regular files*/
	{REDIRFS_F_REG, REDIRFS_FOP_FLUSH, NULL, dymmyflt_post_flush},	/* post-close callback for regular files */
	REDIRFS_OP_END							/* end mark */
};


/*
 * Module initialization
 */
static int __init dummyflt_init(void)
{
	char name[] = "dummyflt";	/* Filter's name */
	int priority = 66;		/* Filter's priority */
	unsigned long flags = 0;	/* Filter's flags */
	int error = 0;

	
	/* Registers Filter to the RedirFS Framework. Each Filter has to
	 * specify its name, priority and flags. Name is used only for debug
	 * and /proc info. Priority is a unique number determining Filter's
	 * position in the Filter chain. RedirFS Framework allows to register one or
	 * more Filters. The priority is used to determine order in which registered
	 * Filters will be called. Flags are reserved for future use. */
	dummyflt = redirfs_register_filter(name, priority, flags);
	if (IS_ERR(dummyflt)) {
		printk(KERN_ERR "dummyflt: registration failed: error %ld\n", PTR_ERR(dummyflt));
		return PTR_ERR(dummyflt);
	}
	
	/* Sets Filter's operations */
	error = redirfs_set_operations(dummyflt, dummyflt_ops);
	if (error) {
		printk(KERN_ERR "dummyflt: set operations failed: error %d\n", error);
		goto unregister;
	}
	
	/* Selects Filter's paths for which its pre and post
	 * callback functions will be called. */
	error = redirfs_include_path(dummyflt, "/usr");
	if (error) {
		printk(KERN_ERR "dummyflt: include path failed: error %d\n", error);
		goto unregister;
	}
	
	error = redirfs_include_path(dummyflt, "/tmp");
	if (error) {
		printk(KERN_ERR "dummyflt: include path failed: error %d\n", error);
		goto unregister;
	}
	
	/* Activates Filter. Filter is by default deactivate so this function has to
	 * be called otherwise Filter's callbacks will not be called */
	error = redirfs_activate_filter(dummyflt);
	if (error) {
		printk(KERN_ERR "dummyflt: active filter failed: error %d\n", error);
		goto unregister;
	}

	return 0;

unregister:
	/* Removes all paths included or excluded by Filter and completely removes
	 * Filter from the RedirFS Framework. */
	error = redirfs_unregister_filter(dummyflt);
	if (error) 
		printk(KERN_ERR "dummyflt: unregistration failed: error %d\n", error);

	return error;
}

/*
 * Module cleanup
 */
static void __exit dummyflt_exit(void)
{
	int error;

	/* Removes all paths included or excluded by Filter and completely removes
	 * Filter from the RedirFS Framework. */
	error = redirfs_unregister_filter(dummyflt);
	if (error) 
		printk(KERN_ERR "dummyflt: unregistration failed: error %d\n", error);
}

module_init(dummyflt_init);
module_exit(dummyflt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frantisek Hrbata <franta@redirfs.org>");
MODULE_DESCRIPTION("Dummy Filter for the RedirFS Framework");
