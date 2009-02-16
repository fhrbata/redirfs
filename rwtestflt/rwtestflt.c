/*
 * rwtestflt - redirfs read/write test filter
 */

#include <redirfs.h>
#include <linux/namei.h>

#define RWTESTFLT_VERSION "0.1"

static redirfs_filter rwtestflt;

static struct redirfs_filter_info rwtestflt_info = {
	.owner = THIS_MODULE,
	.name = "rwtestflt",
	.priority = 500000000,
	.active = 1
};

enum redirfs_rv rwtestflt_open(redirfs_context context,
		struct redirfs_args *args)
{
	printk(KERN_INFO "rwtestflt: open callback\n");
	return REDIRFS_CONTINUE;
}

enum redirfs_rv rwtestflt_read(redirfs_context context,
		struct redirfs_args *args)
{
	printk(KERN_INFO "rwtestflt: read callback\n");
	return REDIRFS_CONTINUE;
}

enum redirfs_rv rwtestflt_write(redirfs_context context,
		struct redirfs_args *args)
{
	printk(KERN_INFO "rwtestflt: write callback\n");
	return REDIRFS_CONTINUE;
}

static struct redirfs_op_info rwtestflt_op_info[] = {
	{REDIRFS_REG_FOP_OPEN, rwtestflt_open, rwtestflt_open},
	{REDIRFS_REG_FOP_READ, rwtestflt_read, rwtestflt_read},
	{REDIRFS_REG_FOP_WRITE, rwtestflt_write, rwtestflt_write},
	{REDIRFS_OP_END, NULL, NULL}
};

static int __init rwflt_init(void)
{
	struct redirfs_path_info rwflt_path_info;
	struct nameidata nd;
	redirfs_path path;
	int err;
	int rv;

	rwtestflt = redirfs_register_filter(&rwtestflt_info);
	if (IS_ERR(rwtestflt)) {
		rv = PTR_ERR(rwtestflt);
		printk(KERN_ERR "rwtestflt: register filter "
				"failed: %d\n", rv);
		return rv;
	}

	rv = redirfs_set_operations(rwtestflt, rwtestflt_op_info);
	if (rv) {
		printk(KERN_ERR "rwtestflt: set operations "
				"failed: %d\n", rv);
		goto error;
	}

	rv = path_lookup("/tmp/rwtest", LOOKUP_FOLLOW, &nd);
	if (rv) {
		printk(KERN_ERR "rwtestflt: path lookup failed: %d\n", rv);
		goto error;
	}

	rwflt_path_info.dentry = nd.path.dentry;
	rwflt_path_info.mnt = nd.path.mnt;
	rwflt_path_info.flags = REDIRFS_PATH_INCLUDE;

	path = redirfs_add_path(rwtestflt, &rwflt_path_info);
	if (IS_ERR(path)) {
		rv = PTR_ERR(path);
		printk(KERN_ERR "rwtestflt: add path failed: %d\n", rv);
		goto error;
	}
	path_put(&nd.path);
	redirfs_put_path(path);

	printk(KERN_INFO "RedirFS read/write test filter, "
			"version " RWTESTFLT_VERSION "\n");
	return 0;

error:
	err = redirfs_unregister_filter(rwtestflt);
	if (err) {
		printk(KERN_ERR "rwtestflt: unregister filter "
				"failed: %d\n", rv);
		return 0;
	}
	redirfs_delete_filter(rwtestflt);
	return rv;
}

static void __exit rwflt_exit(void)
{
	int rv;

	rv = redirfs_unregister_filter(rwtestflt);
	if (rv) {
		printk(KERN_ERR "rwtestflt: unregister filter "
				"failed: %d\n", rv);
	}
	redirfs_delete_filter(rwtestflt);
}

module_init(rwflt_init);
module_exit(rwflt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pavel Zuna <xzunap00@stud.fit.vutbr.cz>");
MODULE_DESCRIPTION("RedirFS read/write test filter, "
                   "version " RWTESTFLT_VERSION);

