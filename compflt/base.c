#include <linux/kernel.h>
#include <linux/module.h>
#include "../redirfs/redirfs.h"
#include "compflt.h"
#include "path.h"

char version[] = "pre6";

static enum rfs_retv f_pre_open(rfs_context context, struct rfs_args *args)
{
        struct file *f = args->args.f_open.file;
        struct inode *inode = args->args.f_open.inode;
        struct fheader *fh;

        debug_printk("compflt: [pre_open i=%li\n", inode->i_ino);

        if (f->f_flags & O_TRUNC) {
                fh = fheader_find(inode->i_ino);
                if (fh) {
                        fheader_clear_blks(fh);
                        fh->compressed = 0;
                        fh->size = 0;
                }

        }

        return RFS_CONTINUE;
}

static enum rfs_retv f_post_release(rfs_context context, struct rfs_args *args)
{
        struct inode *inode = args->args.f_release.inode;
        struct file *f = args->args.f_release.file;
        struct fheader *fh;

        debug_printk("compflt: [post_release] i=%li\n", inode->i_ino);

        fh = fheader_find(inode->i_ino);
        if (fh && fh->compressed)
                fheader_write(f, fh);

        return RFS_CONTINUE;
}

static enum rfs_retv f_pre_read(rfs_context context, struct rfs_args *args)
{
        struct file *f = args->args.f_read.file;
        size_t count = args->args.f_read.count;
        loff_t *pos = args->args.f_read.pos;
        char __user *dst = args->args.f_read.buf;
        size_t *rv = &args->retv.rv_ssize;
        struct fheader *fh;

        debug_printk("compflt: [pre_read] i=%li | pos=%i len=%i\n", f->f_dentry->d_inode->i_ino, (int)*pos, count);

        fh = fheader_get(f);
        if (!fh)
                return RFS_CONTINUE;

        if (!fh->compressed) {
                printk(KERN_INFO "compflt: file not compressed\n");
                return RFS_CONTINUE;
        }

        read_u(f, fh, *pos, &count, dst);

        *rv = count;
        *pos += *rv;

        debug_printk("compflt: [pre_read] returning: count=%i pos=%i\n", *rv, (int)*pos);

        return RFS_STOP;
}

static enum rfs_retv f_pre_write(rfs_context context, struct rfs_args *args)
{
        struct file *f = args->args.f_write.file;
        unsigned char *src = (unsigned char *) args->args.f_write.buf;
        size_t count = args->args.f_write.count;
        loff_t *pos = args->args.f_write.pos;
        size_t *rv = &args->retv.rv_ssize;
        struct fheader *fh;

        debug_printk("compflt: [pre_write] i=%li | pos=%i len=%i\n", f->f_dentry->d_inode->i_ino, (int) *pos, count);

        fh = fheader_get(f);
        if (!fh)
                return RFS_CONTINUE;

        if (!fh->compressed && fh->size != 0) {
                printk(KERN_INFO "compflt: file not compressed\n");
                return RFS_CONTINUE;
        }

        if (f->f_flags & O_APPEND)
                *pos = fh->size;

        write_u(f, fh, *pos, &count, src);

        *rv = count;
        *pos += *rv;

        debug_printk("compflt: [pre_write] returning: count=%i pos=%i\n", *rv, (int)*pos);

        return RFS_STOP;
}

// ====================================

rfs_filter compflt;
static struct rfs_path_info path_info = {COMPFLT_INC_DIR, RFS_PATH_INCLUDE|RFS_PATH_SUBTREE};
static struct rfs_filter_info flt_info = {"compflt", 999, 0};
static struct rfs_op_info ops_info[] = {
        {RFS_REG_FOP_OPEN, f_pre_open, NULL},
        {RFS_REG_FOP_RELEASE, NULL, f_post_release},
        {RFS_REG_FOP_READ, f_pre_read, NULL},
        {RFS_REG_FOP_WRITE, f_pre_write, NULL},
        {RFS_OP_END, NULL, NULL}
};

static int __init compflt_init(void)
{
        enum rfs_err err = 1;

        err = rfs_register_filter(&compflt, &flt_info);
        if (err != RFS_ERR_OK) {
                printk(KERN_ERR "compflt: registration failed: error %d\n", err);
                goto error;
        }

        err = rfs_set_operations(compflt, ops_info);
        if (err != RFS_ERR_OK) {
                printk(KERN_ERR "compflt: set operations failed: error %d\n", err);
                goto error;
        }

        err = rfs_set_path(compflt, &path_info);
        if (err != RFS_ERR_OK) {
                printk(KERN_ERR "compflt: include path failed: error %d\n", err);
                goto error;
        }

        err = rfs_activate_filter(compflt);
        if (err != RFS_ERR_OK) {
                printk(KERN_ERR "compflt: filter activation failed: error %d\n", err);
                goto error;
        }

        err = block_cache_init();
        if (err) {
                printk(KERN_ERR "compflt: block cache initialization failed: error %d\n", err);
                goto error;
        }

        err = fheader_cache_init();
        if (err) {
                printk(KERN_ERR "compflt: fheader cache initialization failed: error %d\n", err);
                goto error;
        }

        err = proc_init();
        if (err) {
                printk(KERN_ERR "compflt: /proc initialization failed: error %d\n", err);
                goto error;
        }

        printk(KERN_INFO "compflt: loaded version %s\n", version);

        return 0;

error:
        if (rfs_unregister_filter(compflt))
                printk(KERN_ERR "compflt: unregistration failed: error %d\n", err);

        return err;
}

static void __exit compflt_exit(void)
{
        enum rfs_err err;

        proc_deinit();
        fheader_cache_deinit();
        block_cache_deinit();

	err = rfs_unregister_filter(compflt);
	if (err != RFS_ERR_OK)
                printk(KERN_ERR "compflt: unregistration failed: error %d\n", err);
}

module_init(compflt_init);
module_exit(compflt_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Jan Podrouzek <xpodro01@stud.fit.vutbr.cz>");
MODULE_DESCRIPTION("Compression filter for the RedirFS Framework");
