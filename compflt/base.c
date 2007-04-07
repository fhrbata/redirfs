#include <linux/kernel.h>
#include <linux/module.h>
#include "../redirfs/redirfs.h"
#include "compflt.h"
#include "path.h"

char version[] = "pre2";

redirfs_filter compflt;

static enum redirfs_retv compflt_post_release(redirfs_context context,
                struct redirfs_args_t *args)
{
        struct inode *inode = args->args.f_release.inode;
        struct file *f = args->args.f_release.file;

        struct header *fh;

        printk("compflt: [post_release] i=%li\n", inode->i_ino);

        fh = header_find(inode->i_ino);
        if (fh)
                header_write(f, fh);

        return REDIRFS_RETV_CONTINUE;
}

static enum redirfs_retv compflt_pre_read(redirfs_context context,
                struct redirfs_args_t *args)
{
        struct file *f = args->args.f_read.file;
        size_t count = args->args.f_read.count;
        loff_t *pos = args->args.f_read.pos;
        char __user *ubuffer = args->args.f_read.buffer;
        unsigned long ino = f->f_dentry->d_inode->i_ino;

        struct header *fh;

        printk("compflt: [pre_read] i=%li | pos=%i len=%i\n", ino, (int)*pos, count);

        fh = header_get(f);
        if (!fh)
                return REDIRFS_RETV_CONTINUE;

        // TODO: we dont support already existing non-compressed files, yet ;)
        if (!fh->compressed) {
                printk(KERN_INFO "compflt: [pre_read] file not compressed\n");
                return REDIRFS_RETV_CONTINUE;
        }

        read_u(f, fh, *pos, &count, ubuffer);

        args->retv.rv_ssize = count;
        *args->args.f_read.pos += args->retv.rv_ssize;

        printk("compflt: [pre_read] returning: count=%i pos=%i\n", count, (int)*args->args.f_read.pos);

        return REDIRFS_RETV_STOP;
}

static enum redirfs_retv compflt_pre_write(redirfs_context context,
                struct redirfs_args_t *args)
{
        struct file *f = args->args.f_write.file;
        unsigned char *src = (unsigned char *) args->args.f_write.buffer;
        size_t count = args->args.f_write.count;
        loff_t *pos = args->args.f_write.pos;
        unsigned long ino = f->f_dentry->d_inode->i_ino;

        struct header *fh;

        printk ("compflt: [pre_write] i=%li | pos=%i len=%i\n", ino, (int) *pos, count);

        fh = header_get(f);
        if (!fh)
                return REDIRFS_RETV_CONTINUE;

        write_u(f, fh, *pos, count, src);

        return REDIRFS_RETV_STOP;
}

static struct redirfs_op_t compflt_ops[] = {
        {REDIRFS_F_REG, REDIRFS_FOP_RELEASE, NULL, compflt_post_release},
        {REDIRFS_F_REG, REDIRFS_FOP_READ, compflt_pre_read, NULL},
        {REDIRFS_F_REG, REDIRFS_FOP_WRITE, compflt_pre_write, NULL},
        REDIRFS_OP_END
};

static int __init compflt_init(void)
{
        char name[] = "compflt";
        int priority = 99;
        int error = 0;

        compflt = redirfs_register_filter(name, priority, 0);
        if (IS_ERR(compflt)) {
                printk(KERN_ERR "compflt: registration failed: error %ld\n", PTR_ERR(compflt));
                return PTR_ERR(compflt);
        }

        error = redirfs_set_operations(compflt, compflt_ops);
        if (error) {
                printk(KERN_ERR "compflt: set operations failed: error %d\n", error);
                goto unregister;
        }

        error = redirfs_include_path(compflt, COMPFLT_INC_DIR);
        if (error) {
                printk(KERN_ERR "compflt: include path failed: error %d\n", error);
                goto unregister;
        }

        error = redirfs_activate_filter(compflt);
        if (error) {
                printk(KERN_ERR "compflt: filter activation failed: error %d\n", error);
                goto unregister;
        }

        if (dmap_cache_init()) {
                printk(KERN_ERR "compflt: dmap cache initialization failed\n");
                goto unregister;
        }

        if (header_cache_init()) {
                printk(KERN_ERR "compflt: header cache initialization failed\n");
                goto unregister;
        }

        printk(KERN_ALERT "compflt: loaded version %s\n", version);

        return 0;

unregister:
        error = redirfs_unregister_filter(compflt);
        if (error)
                printk(KERN_ERR "compflt: unregistration failed: error %d\n", error);

        return error;
}

static void __exit compflt_exit(void)
{
        int error;

        header_cache_deinit();
        // NOTE: shouldnt be needed, every dm is in some header
        dmap_cache_deinit();

        error = redirfs_unregister_filter(compflt);
        if (error)
                printk(KERN_ERR "compflt: unregistration failed: error %d\n", error);
}

module_init(compflt_init);
module_exit(compflt_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Jan Podrouzek <xpodro01@stud.fit.vutbr.cz>");
MODULE_DESCRIPTION("Compression filter for the RedirFS Framework");
