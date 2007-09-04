#include "avflt.h"

extern int avflt_open;
extern int avflt_close;
extern rfs_filter avflt;
struct kobject *kobj;

static int __init avflt_init(void)
{
	int rv;

	rv = avflt_check_init();
	if (rv)
		return rv;

	rv = avflt_rfs_init();
	if (rv)
		goto err_check;

	rv = rfs_get_kobject(avflt, &kobj);
	if (rv)
		goto err_rfs;

	rv = avflt_sys_init(kobj);
	if (rv) 
		goto err_rfs;

	rv = avflt_dev_init();
	if (rv)
		goto err_sys;

	return 0;

err_sys:
	avflt_sys_exit();

err_rfs:
	avflt_rfs_exit();

err_check:
	avflt_check_exit();

	return rv;

}

static void __exit avflt_exit(void)
{
	avflt_dev_exit();
	avflt_sys_exit();
	avflt_rfs_exit();
	avflt_check_exit();
}

module_init(avflt_init);
module_exit(avflt_exit);

module_param(avflt_open, int, 0000);
module_param(avflt_close, int, 0000);

MODULE_PARM_DESC(avflt_open, "capture file open events (default 1)");
MODULE_PARM_DESC(avflt_close, "capture file close events (default 1)");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frantisek Hrbata <hrbata@redirfs.org>");
MODULE_DESCRIPTION("Anti-Virus Filter for the RedirFS Framework");

