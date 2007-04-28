#include <linux/module.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h> // copy_from_user
#include "compflt.h"

#define cflt_proc_root proc_root_fs
#define dirname "compflt"

static struct proc_dir_entry *pf_dir;
static struct proc_dir_entry *pf_stat;
static struct proc_dir_entry *pf_method;
static struct proc_dir_entry *pf_blksize;

static int cflt_proc_stat_read(char *buf, char **start, off_t off, int count, int
                *eof, void *data)
{
        int len = 0;

        len = cflt_comp_proc_stat(buf, PAGE_SIZE);

        if (len <= off+count)
                *eof = 1;

        *start = buf+off;
        len -= off;

        if (len > count)
                len = count;
        if (len < 0)
                len = 0;

        return len;
}

static int cflt_proc_method_read(char *buf, char **start, off_t off, int count, int
                *eof, void *data)
{
        int len = 0;

        len = cflt_comp_proc_method(buf, PAGE_SIZE);

        if (len <= off+count)
                *eof = 1;

        *start = buf+off;
        len -= off;

        if (len > count)
                len = count;
        if (len < 0)
                len = 0;

        return len;
}

static int cflt_proc_method_write(struct file *f, const char *buf, unsigned long
                count, void *data)
{
        char local[1024];
        memset(local, 0, sizeof(local));

        if (count > sizeof(local))
                count = sizeof(local);

        if (copy_from_user(local, buf, count))
                return -EFAULT;

        cflt_comp_method_set(local);

        return count;
}

static int cflt_proc_blksize_read(char *buf, char **start, off_t off, int count, int
                *eof, void *data)
{
        int len = 0;

        len = cflt_file_proc_blksize(buf, PAGE_SIZE);

        if (len <= off+count)
                *eof = 1;

        *start = buf+off;
        len -= off;

        if (len > count)
                len = count;
        if (len < 0)
                len = 0;

        return len;
}

static int cflt_proc_blksize_write(struct file *f, const char *buf, unsigned long
                count, void *data)
{
        char local[1024];
        memset(local, 0, sizeof(local));

        if (count > sizeof(local))
                count = sizeof(local);

        if (copy_from_user(local, buf, count))
                return -EFAULT;
 
        cflt_file_blksize_set(simple_strtol(local, (char **)NULL, 10));

        return count;
}


int cflt_proc_init(void)
{
        cflt_debug_printk("compflt: [f:cflt_proc_init]\n");
        pf_dir = proc_mkdir(dirname, cflt_proc_root);
        if (!pf_dir)
                return -1;
        pf_dir->owner = THIS_MODULE;

        pf_stat = create_proc_read_entry("stat", 0444, pf_dir, cflt_proc_stat_read, NULL);
        if (!pf_stat)
                return -1;
        pf_stat->owner = THIS_MODULE;

        pf_method = create_proc_entry("method", 0644, pf_dir);
        if (!pf_method)
                return -1;
        pf_method->owner = THIS_MODULE;
        pf_method->read_proc = cflt_proc_method_read;
        pf_method->write_proc = cflt_proc_method_write;

        pf_blksize = create_proc_entry("blksize", 0644, pf_dir);
        if (!pf_blksize)
                return -1;
        pf_blksize->owner = THIS_MODULE;
        pf_blksize->read_proc = cflt_proc_blksize_read;
        pf_blksize->write_proc = cflt_proc_blksize_write;

        return 0;
}

void cflt_proc_deinit(void)
{
        cflt_debug_printk("compflt: [f:cflt_proc_deinit]\n");
        remove_proc_entry("stat", pf_dir);
        remove_proc_entry("method", pf_dir);
        remove_proc_entry("blksize", pf_dir);
        remove_proc_entry(dirname, cflt_proc_root);
}
