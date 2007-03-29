#include <linux/proc_fs.h>
#include "redir.h"

static struct proc_dir_entry *rfs_proc_dir; 
static struct proc_dir_entry *rfs_proc_filters; 
static struct proc_dir_entry *rfs_proc_paths;

static int rfs_read_filters(char *page, char **start, off_t off, int count,
		int *eof, void *data)
{
	int len = 0;

	
	len = flt_proc_info(page, PAGE_SIZE);

	if (len <= off + count)
		*eof = 1;
	
	*start = page + off;
	len -= off;

	if (len > count)
		len = count;

	if (len < 0)
		len = 0;
	
	return len;
}

static int rfs_read_paths(char *page, char **start, off_t off, int count,
		int *eof, void *data)
{
	int len = 0;

	
	len = path_proc_info(page, PAGE_SIZE);

	if (len <= off + count)
		*eof = 1;

	*start = page + off;
	len -= off;

	if (len > count)
		len = count;

	if (len < 0)
		len = 0;
	
	return len;
}

int rfs_proc_init(void)
{
	int rv = -1;

	
	rfs_proc_dir = proc_mkdir("redirfs", proc_root_fs);
	if (!rfs_proc_dir)
		goto out;
	rfs_proc_dir->owner = THIS_MODULE;

	rfs_proc_filters = create_proc_read_entry("filters",
			0444,
			rfs_proc_dir,
			rfs_read_filters,
			NULL);
	if (!rfs_proc_filters)
		goto no_filters;
	rfs_proc_filters->owner = THIS_MODULE;
	
	rfs_proc_paths = create_proc_read_entry("paths",
			0444,
			rfs_proc_dir,
			rfs_read_paths,
			NULL);
	if (!rfs_proc_paths)
		goto no_paths;
	rfs_proc_paths->owner = THIS_MODULE;
	return 0;

no_paths:
	remove_proc_entry("filters", rfs_proc_dir);
no_filters:
	remove_proc_entry("redirfs", proc_root_fs);
out:
	return rv;
}

void rfs_proc_destroy(void)
{
	remove_proc_entry("filters", rfs_proc_dir);
	remove_proc_entry("paths", rfs_proc_dir);
	remove_proc_entry("redirfs", proc_root_fs);
}
