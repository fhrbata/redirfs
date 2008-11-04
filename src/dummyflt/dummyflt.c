/*
 * DummyFlt: Dummy Filter for Redirecting File System
 * Written by Frantisek Hrbata <frantisek.hrbata@redirfs.org>
 *
 * Copyright (C) 2008 Frantisek Hrbata
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <redirfs.h>

#define DUMMYFLT_VERSION "0.2"

static redirfs_filter dummyflt;

static struct redirfs_filter_info dummyflt_info = {
	.owner = THIS_MODULE,
	.name = "dummyflt",
	.priority = 500000000,
	.active = 1
};

enum redirfs_rv dummyflt_open(redirfs_context context,
		struct redirfs_args *args)
{
	char *path;
	char *call;
	int rv;

	path = kzalloc(sizeof(char) * PAGE_SIZE, GFP_KERNEL);
	if (!path)
		return REDIRFS_CONTINUE;

	rv = redirfs_get_filename(args->args.f_open.file->f_vfsmnt,
			args->args.f_open.file->f_dentry, path, PAGE_SIZE);

	if (rv) {
		printk(KERN_ERR "dummyflt: rfs_get_filename failed(%d)\n", rv);
		goto exit;
	}

	call = args->type.call == REDIRFS_PRECALL ? "precall" : "postcall";

	printk(KERN_ALERT "dummyflt: open: %s, call: %s\n", path, call);

exit:
	kfree(path);
	return REDIRFS_CONTINUE;
}

enum redirfs_rv dummyflt_release(redirfs_context context,
		struct redirfs_args *args)
{
	char *path;
	char *call;
	int rv;

	path = kzalloc(sizeof(char) * PAGE_SIZE, GFP_KERNEL);
	if (!path)
		return REDIRFS_CONTINUE;

	rv = redirfs_get_filename(args->args.f_release.file->f_vfsmnt,
			args->args.f_release.file->f_dentry, path, PAGE_SIZE);

	if (rv) {
		printk(KERN_ERR "dummyflt: rfs_get_filename failed(%d)\n", rv);
		goto exit;
	}

	call = args->type.call == REDIRFS_PRECALL ? "precall" : "postcall";

	printk(KERN_ALERT "dummyflt: release: %s, call: %s\n", path, call);

exit:
	kfree(path);
	return REDIRFS_CONTINUE;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)

enum redirfs_rv dummyflt_permission(redirfs_context context,
		struct redirfs_args *args)
{
	char *path;
	char *call;
	int rv;

	if (!args->args.i_permission.nd)
		return REDIRFS_CONTINUE;

	path = kzalloc(sizeof(char) * PAGE_SIZE, GFP_KERNEL);
	if (!path)
		return REDIRFS_CONTINUE;

	rv = redirfs_get_filename(args->args.i_permission.nd->path.mnt,
			args->args.i_permission.nd->path.dentry, path, PAGE_SIZE);

	if (rv) {
		printk(KERN_ERR "dummyflt: rfs_get_filename failed(%d)\n", rv);
		goto exit;
	}

	call = args->type.call == REDIRFS_PRECALL ? "precall" : "postcall";

	printk(KERN_ALERT "dummyflt: permission: %s, call: %s\n", path, call);

exit:
	kfree(path);
	return REDIRFS_CONTINUE;
}

#endif

enum redirfs_rv dummyflt_lookup(redirfs_context context,
		struct redirfs_args *args)
{
	char *path;
	char *call;
	int rv;

	if (!args->args.i_lookup.nd)
		return REDIRFS_CONTINUE;

	path = kzalloc(sizeof(char) * PAGE_SIZE, GFP_KERNEL);
	if (!path)
		return REDIRFS_CONTINUE;

	rv = redirfs_get_filename(args->args.i_lookup.nd->path.mnt,
			args->args.i_lookup.nd->path.dentry, path, PAGE_SIZE);

	if (rv) {
		printk(KERN_ERR "dummyflt: rfs_get_filename failed(%d)\n", rv);
		goto exit;
	}

	call = args->type.call == REDIRFS_PRECALL ? "precall" : "postcall";

	printk(KERN_ALERT "dummyflt: lookup: %s, dentry: %s, call: %s\n", path,
			call, args->args.i_lookup.dentry->d_name.name);

exit:
	kfree(path);
	return REDIRFS_CONTINUE;
}

static struct redirfs_op_info dummyflt_op_info[] = {
	{REDIRFS_REG_FOP_OPEN, dummyflt_open, dummyflt_open},
	{REDIRFS_REG_FOP_RELEASE, dummyflt_release, dummyflt_release},
	{REDIRFS_DIR_FOP_OPEN, dummyflt_open, dummyflt_open},
	{REDIRFS_DIR_FOP_RELEASE, dummyflt_release, dummyflt_release},
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	{REDIRFS_REG_IOP_PERMISSION, dummyflt_permission, dummyflt_permission},
	{REDIRFS_DIR_IOP_PERMISSION, dummyflt_permission, dummyflt_permission},
#endif
	{REDIRFS_DIR_IOP_LOOKUP, dummyflt_lookup, dummyflt_lookup},
	{REDIRFS_OP_END, NULL, NULL}
};

static int __init dummyflt_init(void)
{
	/*
	struct redirfs_path_info dummyflt_path_info;
	struct nameidata nd;
	*/
	int err;
	int rv;

	dummyflt = redirfs_register_filter(&dummyflt_info);
	if (IS_ERR(dummyflt)) {
		rv = PTR_ERR(dummyflt);
		printk(KERN_ERR "dummyflt: register filter failed(%d)\n", rv);
		return rv;
	}

	rv = redirfs_set_operations(dummyflt, dummyflt_op_info);
	if (rv) {
		printk(KERN_ERR "dummyflt: set operations failed(%d)\n", rv);
		goto error;
	}

	/*
	rv = path_lookup("/tmp", LOOKUP_FOLLOW, &nd);
	if (rv) {
		printk(KERN_ERR "dummyflt: path lookup failed(%d)\n", rv);
		goto error;
	}

	dummyflt_path_info.dentry = nd.path.dentry;
	dummyflt_path_info.mnt  = nd.path.mnt;
	dummyflt_path_info.flags  = REDIRFS_PATH_ADD | REDIRFS_PATH_INCLUDE;

	rv = redirfs_set_path(dummyflt, &dummyflt_path_info);
	if (rv) {
		printk(KERN_ERR "dummyflt: redirfs_set_path failed(%d)\n", rv);
		path_put(&nd.path);
		goto error;
	}

	path_put(&nd.path);
	*/

	printk(KERN_INFO "Dummy Filter Version "
			DUMMYFLT_VERSION " <www.redirfs.org>\n");
	return 0;
error:
	err = redirfs_unregister_filter(dummyflt);
	if (err) {
		printk(KERN_ERR "dummyflt: unregister filter "
				"failed(%d)\n", err);
		return 0;
	}
	redirfs_delete_filter(dummyflt);
	return rv;
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

