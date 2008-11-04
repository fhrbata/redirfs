/*
 * RedirFS: Redirecting File System
 * Written by Frantisek Hrbata <frantisek.hrbata@redirfs.org>
 *
 * Copyright (C) 2008 Frantisek Hrbata
 * All rights reserved.
 *
 * This file is part of RedirFS.
 *
 * RedirFS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * RedirFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with RedirFS. If not, see <http://www.gnu.org/licenses/>.
 */

#include "rfs.h"

#define rfs_kattr_to_rattr(__kattr) \
	container_of(__kattr, struct redirfs_filter_attribute, attr)

static struct rfs_flt *rfs_sysfs_flt_get(struct rfs_flt *rflt)
{
	spin_lock(&rflt->lock);

	if (atomic_read(&rflt->kobj.kref.refcount) < 2) {
		spin_unlock(&rflt->lock);
		return ERR_PTR(-ENOENT);
	}

	rfs_flt_get(rflt);

	spin_unlock(&rflt->lock);

	return rflt;
}

static ssize_t rfs_flt_show(struct kobject *kobj, struct attribute *attr,
		char *buf)
{
	struct rfs_flt *rflt = rfs_kobj_to_rflt(kobj);
	struct redirfs_filter_attribute *rattr = rfs_kattr_to_rattr(attr);
	ssize_t rv;

	rflt = rfs_sysfs_flt_get(rflt);
	if (IS_ERR(rflt))
		return PTR_ERR(rflt);

	rv = rattr->show((redirfs_filter)rflt, rattr, buf);

	rfs_flt_put(rflt);

	return rv;
}

static ssize_t rfs_flt_store(struct kobject *kobj, struct attribute *attr,
		const char *buf, size_t count)
{
	struct rfs_flt *rflt = rfs_kobj_to_rflt(kobj);
	struct redirfs_filter_attribute *rattr = rfs_kattr_to_rattr(attr);
	ssize_t rv;

	if (strcmp(attr->name, "unregister") == 0)
		return rattr->store((redirfs_filter)rflt, rattr, buf, count);

	rflt = rfs_sysfs_flt_get(rflt);
	if (IS_ERR(rflt))
		return PTR_ERR(rflt);

	rv = rattr->store((redirfs_filter)rflt, rattr, buf, count);

	rfs_flt_put(rflt);

	return rv;
}

static ssize_t rfs_flt_priority_show(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, char *buf)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;

	return snprintf(buf, PAGE_SIZE, "%d", rflt->priority);
}

static ssize_t rfs_flt_active_show(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, char *buf)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;

	return snprintf(buf, PAGE_SIZE, "%d",
			atomic_read(&rflt->active));
}

static ssize_t rfs_flt_active_store(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, const char *buf,
		size_t count)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;
	struct redirfs_ctl rctl;
	int act;
	int rv;

	if (sscanf(buf, "%d", &act) != 1)
		return -EINVAL;

	if (act) {
		if (rflt->ctl_cb && (rflt->ctl_id & REDIRFS_CTL_ACTIVATE)) {
			rctl.id = REDIRFS_CTL_ACTIVATE;
			rv = rflt->ctl_cb(&rctl);

		} else
			rv = redirfs_activate_filter(filter);

	} else {
		if (rflt->ctl_cb && (rflt->ctl_id & REDIRFS_CTL_DEACTIVATE)) {
			rctl.id = REDIRFS_CTL_DEACTIVATE;
			rv = rflt->ctl_cb(&rctl);
		} else
			rv = redirfs_deactivate_filter(filter);
	}

	if (rv)
		return rv;

	return count;
}

static ssize_t rfs_flt_paths_show(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, char *buf)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;
	
	return rfs_path_get_info(rflt, buf, PAGE_SIZE);
}

static int rfs_flt_paths_add(redirfs_filter filter, const char *buf,
		size_t count)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;
	struct redirfs_ctl rctl;
	struct redirfs_path_info info;
	struct nameidata nd;
	char *path;
	char type;
	int rv;

	path = kzalloc(sizeof(char) * PAGE_SIZE, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	if (sscanf(buf, "a:%c:%s", &type, path) != 2) {
		kfree(path);
		return -EINVAL;
	}

	rctl.data.path_info = &info;
	rctl.id = REDIRFS_CTL_SET_PATH;
	info.flags = REDIRFS_PATH_ADD;

	if (type == 'i')
		info.flags |= REDIRFS_PATH_INCLUDE;

	else if (type == 'e')
		info.flags |= REDIRFS_PATH_EXCLUDE;

	else {
		kfree(path);
		return -EINVAL;
	}

	rv = path_lookup(path, LOOKUP_FOLLOW, &nd);
	if (rv) {
		kfree(path);
		return rv;
	}

	info.dentry = nd.path.dentry;
	info.mnt = nd.path.mnt;

	if (rflt->ctl_cb && (rflt->ctl_id & REDIRFS_CTL_SET_PATH))
		rv = rflt->ctl_cb(&rctl);
	else
		rv = redirfs_set_path(filter, &info);

	path_put(&nd.path);
	kfree(path);

	return rv;
}

static int rfs_flt_paths_rem(redirfs_filter filter, const char *buf,
		size_t count)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;
	struct redirfs_ctl rctl;
	struct rfs_path *rpath;
	struct redirfs_path_info *info;
	int id;
	int rv;

	if (sscanf(buf, "r:%d", &id) != 1)
		return -EINVAL;

	rctl.id = REDIRFS_CTL_SET_PATH;

	mutex_lock(&rfs_path_mutex);
	rpath = rfs_path_find_id(id);
	if (!rpath) {
		mutex_unlock(&rfs_path_mutex);
		return -ENOENT;
	}
	mutex_unlock(&rfs_path_mutex);
	
	info = redirfs_get_path_info(filter, (redirfs_path)rpath);
	rctl.data.path_info = info;

	if (IS_ERR(info)) {
		rfs_path_put(rpath);
		return PTR_ERR(info);
	}

	rctl.data.path_info->flags |= REDIRFS_PATH_REM;

	if (rflt->ctl_cb && (rflt->ctl_id & REDIRFS_CTL_SET_PATH))
		rv = rflt->ctl_cb(&rctl);
	else
		rv = redirfs_set_path(filter, info);

	redirfs_put_path_info(info);
	rfs_path_put(rpath);

	return rv;
}

static int rfs_flt_paths_clean(redirfs_filter filter, const char *buf,
		size_t count)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;
	struct redirfs_ctl rctl;
	char clean;
	int rv;

	if (sscanf(buf, "%c", &clean) != 1)
		return -EINVAL;

	if (clean != 'c')
		return -EINVAL;

	rctl.id = REDIRFS_CTL_REMOVE_PATHS;
	
	if (rflt->ctl_cb && (rflt->ctl_id & REDIRFS_CTL_REMOVE_PATHS))
		rv = rflt->ctl_cb(&rctl);
	else
		rv = redirfs_rem_paths(filter);

	return rv;
}

static ssize_t rfs_flt_paths_store(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, const char *buf,
		size_t count)
{
	int rv;

	if (count < 2)
		return -EINVAL;

	if (*buf == 'a')
		rv = rfs_flt_paths_add(filter, buf, count);

	else if (*buf == 'r')
		rv = rfs_flt_paths_rem(filter, buf, count);

	else if (*buf == 'c')
		rv = rfs_flt_paths_clean(filter, buf, count);

	else
		rv = -EINVAL;

	if (rv)
		return rv;

	return count;
}

static ssize_t rfs_flt_unregister_store(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, const char *buf,
		size_t count)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;
	struct redirfs_ctl rctl;
	int unreg;
	int rv;

	if (sscanf(buf, "%d", &unreg) != 1)
		return -EINVAL;

	if (unreg != 1)
		return -EINVAL;

	rctl.id = REDIRFS_CTL_UNREGISTER;

	if (rflt->ctl_cb && (rflt->ctl_id & REDIRFS_CTL_UNREGISTER))
		rv = rflt->ctl_cb(&rctl);
	else
		rv = redirfs_unregister_filter(filter);

	if (rv)
		return rv;

	return count;
}

static struct redirfs_filter_attribute rfs_flt_priority_attr =
	REDIRFS_FILTER_ATTRIBUTE(priority, 0444, rfs_flt_priority_show, NULL);

static struct redirfs_filter_attribute rfs_flt_active_attr = 
	REDIRFS_FILTER_ATTRIBUTE(active, 0644, rfs_flt_active_show,
			rfs_flt_active_store);

static struct redirfs_filter_attribute rfs_flt_paths_attr = 
	REDIRFS_FILTER_ATTRIBUTE(paths, 0644, rfs_flt_paths_show,
			rfs_flt_paths_store);

static struct redirfs_filter_attribute rfs_flt_unregister_attr = 
	REDIRFS_FILTER_ATTRIBUTE(unregister, 0200, NULL,
			rfs_flt_unregister_store);

static struct attribute *rfs_flt_attrs[] = {
	&rfs_flt_priority_attr.attr,
	&rfs_flt_active_attr.attr,
	&rfs_flt_paths_attr.attr,
	&rfs_flt_unregister_attr.attr,
	NULL
};

static struct kobject *rfs_kobj;
static struct kset *rfs_flt_kset;

static struct sysfs_ops rfs_sysfs_ops = {
	.show = rfs_flt_show,
	.store = rfs_flt_store
};

struct kobj_type rfs_flt_ktype = {
	.sysfs_ops = &rfs_sysfs_ops,
	.release = rfs_flt_release,
	.default_attrs = rfs_flt_attrs
};

int rfs_sysfs_create(void)
{
	rfs_kobj = kobject_create_and_add("redirfs", fs_kobj);
	if (!rfs_kobj)
		return -ENOMEM;

	rfs_flt_kset = kset_create_and_add("filters", NULL, rfs_kobj);
	if (!rfs_flt_kset) {
		kobject_put(rfs_kobj);
		return -ENOMEM;
	}

	return 0;
}

void rfs_sysfs_destroy(void)
{
	kset_unregister(rfs_flt_kset);
	kobject_put(rfs_kobj);
}

int redirfs_create_attribute(redirfs_filter filter,
		struct redirfs_filter_attribute *attr)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;

	if (!rflt || !attr)
		return -EINVAL;

	return sysfs_create_file(&rflt->kobj, &attr->attr);
}

int redirfs_remove_attribute(redirfs_filter filter,
		struct redirfs_filter_attribute *attr)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;

	if (!rflt || !attr)
		return -EINVAL;

	sysfs_remove_file(&rflt->kobj, &attr->attr);

	return 0;
}

struct kobject *redirfs_filter_kobject(redirfs_filter filter)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;

	if (!rflt || IS_ERR(rflt))
		return ERR_PTR(-EINVAL);

	return &rflt->kobj;
}

int rfs_flt_sysfs_init(struct rfs_flt *rflt)
{
	int rv;

	rflt->kobj.kset = rfs_flt_kset;
	rv = kobject_add(&rflt->kobj, NULL, "%s", rflt->name);
	if (rv)
		return rv;

	kobject_uevent(&rflt->kobj, KOBJ_ADD);

	return 0;
}

void rfs_flt_sysfs_exit(struct rfs_flt *rflt)
{
	kobject_del(&rflt->kobj);
}

EXPORT_SYMBOL(redirfs_create_attribute);
EXPORT_SYMBOL(redirfs_remove_attribute);
EXPORT_SYMBOL(redirfs_filter_kobject);

