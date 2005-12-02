#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include "root.h"
#include "filter.h"

static struct proc_dir_entry *redirfs_proc_dir; 
static struct proc_dir_entry *redirfs_proc_filters; 
static struct proc_dir_entry *redirfs_proc_roots;

static int redirfs_read_filters(char *page, char **start, off_t off, int count,
		int *eof, void *data)
{
	int len = 0;

	
	len = redirfs_filters_info(page, PAGE_SIZE);

	if (len <= off+count) *eof = 1;
	*start = page + off;
	len -= off;
	if (len>count) len = count;
	if (len<0) len = 0;
	
	return len;
}

static int redirfs_read_roots(char *page, char **start, off_t off, int count,
		int *eof, void *data)
{
	int len = 0;

	
	len = redirfs_roots_info(page, PAGE_SIZE);

	if (len <= off+count) *eof = 1;
	*start = page + off;
	len -= off;
	if (len>count) len = count;
	if (len<0) len = 0;
	
	return len;
}

int redirfs_proc_init(void)
{
	int rv = -1;

	
	redirfs_proc_dir = proc_mkdir("redirfs", proc_root_fs);
	if (!redirfs_proc_dir)
		goto out;
	redirfs_proc_dir->owner = THIS_MODULE;

	redirfs_proc_filters = create_proc_read_entry("filters",
			0444,
			redirfs_proc_dir,
			redirfs_read_filters,
			NULL);
	if (!redirfs_proc_filters)
		goto no_filters;
	redirfs_proc_filters->owner = THIS_MODULE;
	
	redirfs_proc_roots = create_proc_read_entry("roots",
			0444,
			redirfs_proc_dir,
			redirfs_read_roots,
			NULL);
	if (!redirfs_proc_roots)
		goto no_roots;
	redirfs_proc_roots->owner = THIS_MODULE;
	return 0;

no_roots:
	remove_proc_entry("filters", redirfs_proc_dir);
no_filters:
	remove_proc_entry("redirfs", proc_root_fs);
out:
	return rv;
}

void redirfs_proc_destroy(void)
{
	remove_proc_entry("filters", redirfs_proc_dir);
	remove_proc_entry("roots", redirfs_proc_dir);
	remove_proc_entry("redirfs", proc_root_fs);
}
