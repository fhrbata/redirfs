#include <linux/module.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h> // copy_from_user
#include "compflt.h"

#define compflt_root proc_root_fs
#define dirname "compflt"

static struct proc_dir_entry *pf_dir;
static struct proc_dir_entry *pf_stat;
static struct proc_dir_entry *pf_method;

static int proc_stat_read(char *buf, char **start, off_t off, int count, int
                *eof, void *data)
{
        int len = 0;

        len = comp_stat(buf, PAGE_SIZE);

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

static int proc_method_read(char *buf, char **start, off_t off, int count, int
                *eof, void *data)
{
        int len = 0;

        len = comp_proc_get(buf, PAGE_SIZE);

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

static int proc_method_write(struct file *f, const char *buf, unsigned long
                count, void *data)
{
        char local[1024];
        memset(local, 0, sizeof(local));

        if (count > sizeof(local))
                count = sizeof(local);

        if (copy_from_user(local, buf, count))
                return -EFAULT;

        comp_proc_set(local);

        return count;
}

int proc_init(void)
{
        pf_dir = proc_mkdir(dirname, compflt_root);
        if (!pf_dir)
                goto dir_fail;
        pf_dir->owner = THIS_MODULE;

        pf_stat = create_proc_read_entry("stat", 0444, pf_dir, proc_stat_read, NULL);
        if (!pf_stat)
                goto stat_fail;
        pf_stat->owner = THIS_MODULE;

        pf_method = create_proc_entry("method", 0644, pf_dir);
        if (!pf_method)
                goto method_fail;
        pf_method->owner = THIS_MODULE;
        pf_method->read_proc = proc_method_read;
        pf_method->write_proc = proc_method_write;

        return 0;

method_fail:
        remove_proc_entry("stat", pf_dir);
stat_fail:
        remove_proc_entry(dirname, compflt_root);
dir_fail:
        return -1;
}

void proc_deinit(void)
{
        remove_proc_entry("stat", pf_dir);
        remove_proc_entry("method", pf_dir);
        remove_proc_entry(dirname, compflt_root);
}
