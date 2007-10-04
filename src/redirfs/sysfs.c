#include "redir.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22) 
extern struct subsystem fs_subsys;
static struct subsystem rfs_subsys;
#else
extern struct kset fs_subsys;
static struct kset rfs_subsys;
#endif

struct kset rfs_flt_kset;
static struct kobj_type rfs_flt_type;
static struct sysfs_ops rfs_flt_ops;

static ssize_t rfs_control_show(rfs_filter filter, struct rfs_flt_attribute *attr, char *buf)
{
	struct filter *flt = (struct filter *)filter;

	return snprintf(buf, PAGE_SIZE, "%d", flt->f_ctl_cb ? 1 : 0);
}

static ssize_t rfs_priority_show(rfs_filter filter, struct rfs_flt_attribute *attr, char *buf)
{
	struct filter *flt = (struct filter *)filter;

	return snprintf(buf, PAGE_SIZE, "%d", flt->f_priority);
}

static ssize_t rfs_active_show(rfs_filter filter, struct rfs_flt_attribute *attr, char *buf)
{
	struct filter *flt = (struct filter *)filter;

	return snprintf(buf, PAGE_SIZE, "%d", atomic_read(&flt->f_active));
}

static ssize_t rfs_active_store(rfs_filter filter, struct rfs_flt_attribute *attr, const char *buf, size_t size)
{
	struct filter *flt = (struct filter *)filter;
	struct rfs_ctl ctl;
	int act;
	int rv;

	if (!flt->f_ctl_cb) {
		printk(KERN_INFO "redirfs: filter '%s' does not support configuration via sysfs interface\n", flt->f_name);
		return size;
	}

	if (sscanf(buf, "%d", &act) != 1) {
		printk(KERN_ERR "redirfs: %s of filter '%s' failed(malformed input)\n", act ? "activation" : "deactivation", flt->f_name);
		return size;
	}

	ctl.id = act ? RFS_CTL_ACTIVATE : RFS_CTL_DEACTIVATE;

	if ((rv = flt->f_ctl_cb(&ctl)))
		printk(KERN_ERR "redirfs: %s of filter '%s' failed(%d)\n", act ? "activation" : "deactivation", flt->f_name, rv);

	return size;
}

static ssize_t rfs_paths_show(rfs_filter filter, struct rfs_flt_attribute *attr, char *buf)
{
	struct filter *flt = (struct filter *)filter;

	return path_flt_info(flt, buf, PAGE_SIZE);
}

static ssize_t rfs_paths_store(rfs_filter filter, struct rfs_flt_attribute *attr, const char *buf, size_t size)
{
	struct filter *flt = (struct filter *)filter;
	char path[PAGE_SIZE];
	int incl;
	int subtree;
	struct rfs_ctl ctl;
	int rv;

	if (!flt->f_ctl_cb) {
		printk(KERN_INFO "redirfs: filter '%s' does not support configuration via sysfs interface\n", flt->f_name);
		return size;
	}

	if (sscanf(buf, "%d:%d:%s", &subtree, &incl, path) != 3) {
		printk(KERN_ERR "redirfs: setting path for filter '%s' failed(malformed input)\n", flt->f_name);
		return size;
	}

	ctl.id = RFS_CTL_SETPATH;
	ctl.data.path_info.path = path;
	ctl.data.path_info.flags = incl ? RFS_PATH_INCLUDE : RFS_PATH_EXCLUDE;
	ctl.data.path_info.flags |= subtree ? RFS_PATH_SUBTREE : RFS_PATH_SINGLE;

	if ((rv = flt->f_ctl_cb(&ctl)))
		printk(KERN_ERR "redirfs: setting path for filter '%s' failed(%d)\n", flt->f_name, rv);

	return size;
}

static rfs_flt_attr(control, 0444, rfs_control_show, NULL, NULL);
static rfs_flt_attr(priority, 0444, rfs_priority_show, NULL, NULL);
static rfs_flt_attr(active, 0644, rfs_active_show, rfs_active_store, NULL);
static rfs_flt_attr(paths, 0644, rfs_paths_show, rfs_paths_store, NULL);

static struct attribute *rfs_flt_attrs[] = {
	&rfs_flt_attr_control.attr,
	&rfs_flt_attr_priority.attr,
	&rfs_flt_attr_active.attr,
	&rfs_flt_attr_paths.attr,
	NULL
};

#define attr_to_rfsattr(__attr) container_of(__attr, struct rfs_flt_attribute, attr)
#define kobj_to_flt(__kobj) container_of(__kobj, struct filter, f_kobj)

static ssize_t rfs_flt_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct rfs_flt_attribute *rfs_attr = attr_to_rfsattr(attr);
	struct filter *flt = kobj_to_flt(kobj);

	return rfs_attr->show(flt, rfs_attr, buf);
}

static ssize_t rfs_flt_store(struct kobject *kobj, struct attribute *attr, const char *buf, size_t size)
{
	struct rfs_flt_attribute *rfs_attr = attr_to_rfsattr(attr);
	struct filter *flt = kobj_to_flt(kobj);

	return rfs_attr->store(flt, rfs_attr, buf, size);
}

int rfs_sysfs_init(void)
{
	int rv;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22) 
	memset(&rfs_subsys, 0, sizeof(struct subsystem));
#else
	memset(&rfs_subsys, 0, sizeof(struct kset));
#endif
	memset(&rfs_flt_type, 0, sizeof(struct kobj_type));
	memset(&rfs_flt_kset, 0, sizeof(struct kset));
	memset(&rfs_flt_ops, 0, sizeof(struct sysfs_ops));

	rfs_flt_ops.show = rfs_flt_show;
	rfs_flt_ops.store = rfs_flt_store;

	rfs_flt_type.release = NULL;
	rfs_flt_type.default_attrs = rfs_flt_attrs;
	rfs_flt_type.sysfs_ops = &rfs_flt_ops;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22) 
	rfs_subsys.kset.kobj.parent = &fs_subsys.kset.kobj;
	rfs_subsys.kset.ktype = NULL;
	kobject_set_name(&rfs_subsys.kset.kobj, "%s", "redirfs");
#else
	rfs_subsys.kobj.parent = &fs_subsys.kobj;
	rfs_subsys.ktype = NULL;
	kobject_set_name(&rfs_subsys.kobj, "%s", "redirfs");
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22) 
	rfs_flt_kset.subsys = &rfs_subsys;
#else
	rfs_flt_kset.kobj.parent = &rfs_subsys.kobj;
#endif
	rfs_flt_kset.ktype = &rfs_flt_type;
	kobject_set_name(&rfs_flt_kset.kobj, "%s", "filters");

	if ((rv = subsystem_register(&rfs_subsys)))
		return rv;

	if ((rv = kset_register(&rfs_flt_kset))) {
		subsystem_unregister(&rfs_subsys);
		return rv;
	}

	return 0;
}

void rfs_sysfs_destroy(void)
{
	kset_unregister(&rfs_flt_kset);
	subsystem_unregister(&rfs_subsys);
}

int rfs_register_attribute(rfs_filter filter, struct rfs_flt_attribute *attr)
{
	struct filter *flt = (struct filter *)filter;
	int rv;

	if (!filter || !attr)
		return -EINVAL;
	
	if ((rv = sysfs_create_file(&flt->f_kobj, &attr->attr))) 
		return rv;

	return 0;
}

int rfs_unregister_attribute(rfs_filter filter, struct rfs_flt_attribute *attr)
{
	struct filter *flt = (struct filter *)filter;

	if (!filter || !attr)
		return -EINVAL;
	
	sysfs_remove_file(&flt->f_kobj, &attr->attr);

	return 0;
}

int rfs_get_kobject(rfs_filter filter, struct kobject **kobj)
{
	struct filter *flt = (struct filter *)filter;

	if (!filter || !kobj)
		return -EINVAL;

	*kobj = &flt->f_kobj;

	return 0;
}

EXPORT_SYMBOL(rfs_register_attribute);
EXPORT_SYMBOL(rfs_unregister_attribute);
EXPORT_SYMBOL(rfs_get_kobject);

