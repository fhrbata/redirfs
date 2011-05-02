/*
 * UnionFlt: Union Mount Filter
 * Written by Petr Holasek <holasekp@gmail.com>
 *
 * Copyright (C) 2011 Petr Holasek
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

#include <redirfs.h>
#include <rfs.h>
#include <linux/slab.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/security.h>
#include <linux/kobject.h>
#include <linux/list_sort.h>

#define UNIONFLT_VERSION "0.1"
#define SYMLINK_BUFFER 1024

#define rfs_kattr_to_rattr(__kattr) \
	container_of(__kattr, struct redirfs_filter_attribute, attr)

#define rfs_kobj_to_rflt_sp(__kobj) container_of(__kobj, struct rfs_flt_subpath, kobj)

#define rfs_data_to_rfs_branch(data) container_of(data, struct rfs_branch_data, data);

struct rfs_flt_subpath {
	const char * name;
	struct kobject kobj;
	struct rfs_path *rpath;
	atomic_t count;
	spinlock_t lock;
};

/* List of subbranches in root object private data */
struct rfs_branch_data {
	struct list_head branches;
	struct redirfs_data data;
};

struct rfs_branch {
	struct list_head list;
	struct rfs_path *rpath;
	int priority;
};


struct rfs_branch *alloc_branch(int priority, struct rfs_path *rpath);
struct rfs_flt_subpath *rfs_flt_sp_get(struct rfs_flt_subpath *rsubpath);
void rfs_flt_sp_put(struct rfs_flt_subpath *rsubpath);
void rfs_flt_sp_release(struct kobject *kobj);
static struct rfs_flt_subpath *rfs_sysfs_flt_sp_get(struct rfs_flt_subpath *spath);
static ssize_t rfs_flt_sp_show(struct kobject *kobj, struct attribute *attr, char *buf);
static ssize_t rfs_flt_sp_store(struct kobject *kobj, struct attribute *attr,
		const char *buf, size_t count);
static ssize_t rfs_flt_sp_paths_show(struct rfs_flt_subpath * spath,
		struct redirfs_filter_attribute *attr, char *buf);
static int rfs_flt_subpaths_add(struct rfs_flt_subpath * spath, const char *buf,
		size_t count);
static ssize_t rfs_flt_sp_paths_show(struct rfs_flt_subpath * spath,
		struct redirfs_filter_attribute *attr, char *buf);
static int rfs_flt_subpaths_add(struct rfs_flt_subpath * spath, const char *buf,
		size_t count);
static int rfs_flt_subpaths_rem(struct rfs_flt_subpath * spath, const char *buf,
		size_t count);
static int rfs_flt_subpaths_clean(struct rfs_flt_subpath * spath, const char *buf,
		size_t count);
static ssize_t rfs_flt_sp_paths_store(struct rfs_flt_subpath * spath,
		struct redirfs_filter_attribute *attr, const char *buf,
		size_t count);
static int unionflt_add_branch(const char * name, struct rfs_path *rpath);
static int unionflt_add_path(struct redirfs_path_info *info);
struct rfs_branch *rfs_subpath_find_id(struct rfs_branch_data *bdata, int id);
static int rfs_branch_get_id(struct rfs_branch_data *bdata);
redirfs_path redirfs_add_path2spath(struct rfs_flt_subpath *spath,
		struct redirfs_path_info *info);
int rfs_path_get_info_sp(struct rfs_flt_subpath *spath, char *buf, int size);

static redirfs_filter unionflt;
static struct kset *rfs_flt_subpath_kset;

struct rfs_branch *alloc_branch(int priority, struct rfs_path *rpath)
{
	struct rfs_branch *branch;

	branch = kzalloc(sizeof(*branch), GFP_KERNEL);
	if (!branch)
		return branch;
	branch->rpath = rpath;
	branch->priority = priority;
	return branch;
}

struct rfs_flt_subpath *rfs_flt_sp_get(struct rfs_flt_subpath *rsubpath)
{
	if (!rsubpath || IS_ERR(rsubpath))
		return NULL;

	BUG_ON(!atomic_read(&rsubpath->count));
	atomic_inc(&rsubpath->count);

	return rsubpath;
}

void rfs_flt_sp_put(struct rfs_flt_subpath *rsubpath)
{
	if (!rsubpath || IS_ERR(rsubpath))
		return;

	BUG_ON(!atomic_read(&rsubpath->count));
	if (!atomic_dec_and_test(&rsubpath->count))
		return;

	kfree(rsubpath);
}

void rfs_flt_sp_release(struct kobject *kobj)
{
	struct rfs_flt_subpath *spath = rfs_kobj_to_rflt_sp(kobj);

	rfs_flt_sp_put(spath);
}

static struct rfs_flt_subpath *rfs_sysfs_flt_sp_get(struct rfs_flt_subpath *spath)
{
	spin_lock(&spath->lock);

	rfs_flt_sp_get(spath);

	spin_unlock(&spath->lock);

	return spath;
}

static ssize_t rfs_flt_sp_show(struct kobject *kobj, struct attribute *attr,
		char *buf)
{
	struct rfs_flt_subpath *spath = rfs_kobj_to_rflt_sp(kobj);
	struct redirfs_filter_attribute *rattr = rfs_kattr_to_rattr(attr);
	ssize_t rv;

	spath = rfs_sysfs_flt_sp_get(spath);
	if (IS_ERR(spath))
		return PTR_ERR(spath);

	rv = rattr->show(spath, rattr, buf);

	rfs_flt_sp_put(spath);

	return rv;
}

static ssize_t rfs_flt_sp_store(struct kobject *kobj, struct attribute *attr,
		const char *buf, size_t count)
{
	struct rfs_flt_subpath *spath = rfs_kobj_to_rflt_sp(kobj);
	struct redirfs_filter_attribute *rattr = rfs_kattr_to_rattr(attr);
	ssize_t rv;

	spath = rfs_sysfs_flt_sp_get(spath);
	if (IS_ERR(spath))
		return PTR_ERR(spath);

	rv = rattr->store(spath, rattr, buf, count);

	rfs_flt_sp_put(spath);

	return rv;
}

static ssize_t rfs_flt_sp_paths_show(struct rfs_flt_subpath * spath,
		struct redirfs_filter_attribute *attr, char *buf)
{
	return rfs_path_get_info_sp(spath, buf, PAGE_SIZE);
}

static int rfs_flt_subpaths_add(struct rfs_flt_subpath * spath, const char *buf,
		size_t count)
{
	struct rfs_path *rpath;
	struct redirfs_path_info info;
	struct nameidata nd;
	char *path;
	int rv;

	path = kzalloc(sizeof(char) * PAGE_SIZE, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	if (sscanf(buf, "a:%d:%s", &info.flags, path) != 2) {
		kfree(path);
		return -EINVAL;
	}

	rv = path_lookup(path, LOOKUP_FOLLOW, &nd);
	if (rv) {
		kfree(path);
		return rv;
	}

	info.dentry = rfs_nameidata_dentry(&nd);
	info.mnt = rfs_nameidata_mnt(&nd);

	rpath = redirfs_add_path2spath(spath, &info);

	if (IS_ERR(rpath))
		rv = PTR_ERR(rpath);

	rfs_nameidata_put(&nd);
	kfree(path);

	return rv;
}

static int rfs_flt_subpaths_rem(struct rfs_flt_subpath * spath, const char *buf,
		size_t count)
{
	int id;
	int rv;
	struct rfs_root *root;
	struct redirfs_data *data;
	struct rfs_branch_data *bdata;
	struct rfs_branch *branch;

	if (sscanf(buf, "r:%d", &id) != 1)
		return -EINVAL;

	root = redirfs_get_root_path(spath->rpath);
	if (!root)
		return -ENOENT;
	data = redirfs_get_data_root(unionflt, root);
	if (!data) {
		redirfs_put_root(root);
		return -ENOENT;
	}
	bdata = rfs_data_to_rfs_branch(data);

	branch = rfs_subpath_find_id(bdata,id);
	if (!branch) {
		redirfs_put_data(data);
		redirfs_put_root(root);
		return -ENOENT;
	}
	list_del(&branch->list);
	redirfs_put_path(branch->rpath);
	kfree(branch);
	redirfs_put_data(data);
	redirfs_put_root(root);
	return rv;
}

static int unionflt_destroy_all_branches(struct rfs_flt_subpath * spath)
{
	struct rfs_root *root;
	struct redirfs_data *data;
	struct rfs_branch_data *bdata;
	struct rfs_branch *branch;
	struct list_head *pos, *q;

	root = redirfs_get_root_path(spath->rpath);
	if (!root)
		return -ENOENT;

	data = redirfs_get_data_root(unionflt, root);
	if (!data) {
		redirfs_put_root(root);
		return -ENOENT;
	}
	bdata = rfs_data_to_rfs_branch(data);

	list_for_each_safe(pos, q, &bdata->branches) {
		branch = list_entry(pos, struct rfs_branch, list);
		redirfs_put_path(branch->rpath);
		list_del(pos);
		kfree(branch);
	}

	redirfs_put_data(data);
	redirfs_put_root(root);

	return 0;
}

static int rfs_flt_subpaths_clean(struct rfs_flt_subpath * spath, const char *buf,
		size_t count)
{
	char clean;
	int rv;

	if (sscanf(buf, "%c", &clean) != 1)
		return -EINVAL;

	if (clean != 'c')
		return -EINVAL;

	rv = unionflt_destroy_all_branches(spath);

	return rv;
}

static ssize_t rfs_flt_sp_paths_store(struct rfs_flt_subpath * spath,
		struct redirfs_filter_attribute *attr, const char *buf,
		size_t count)
{
	int rv;

	if (count < 2)
		return -EINVAL;

	if (*buf == 'a')
		rv = rfs_flt_subpaths_add(spath, buf, count);

	else if (*buf == 'r')
		rv = rfs_flt_subpaths_rem(spath, buf, count);

	else if (*buf == 'c')
		rv = rfs_flt_subpaths_clean(spath, buf, count);

	else
		rv = -EINVAL;

	if (rv)
		return rv;

	return count;
}


struct redirfs_subpath_attribute {
	struct attribute attr;
	ssize_t (*show)(struct rfs_flt_subpath *spath,
			struct redirfs_filter_attribute *attr, char *buf);
	ssize_t (*store)(struct rfs_flt_subpath *spath,
			struct redirfs_filter_attribute *attr, const char *buf,
			size_t count);
};

static struct redirfs_subpath_attribute rfs_fltsp_paths_attr =
	REDIRFS_FILTER_ATTRIBUTE(branches , 0644, rfs_flt_sp_paths_show,
			rfs_flt_sp_paths_store);

static struct attribute *rfs_flt_sp_attrs[] = {
	&rfs_fltsp_paths_attr.attr,
	NULL
};

static struct sysfs_ops rfs_sysfs_sp_ops = {
	.show = rfs_flt_sp_show,
	.store = rfs_flt_sp_store
};

struct kobj_type rfs_flt_sp_ktype = {
	.sysfs_ops = &rfs_sysfs_sp_ops,
	.release = rfs_flt_sp_release,
	.default_attrs = rfs_flt_sp_attrs
};

void unionflt_free_data(struct redirfs_data *data)
{
	kfree(data);
}

static int unionflt_add_branch(const char * name, struct rfs_path *rpath)
{
	struct rfs_flt_subpath *spath;
	struct rfs_branch_data *bdata;
	struct rfs_root *root;

	int rv;

	spath = kzalloc(sizeof(struct rfs_flt_subpath), GFP_KERNEL);
	if (!spath)
		return -EINVAL;
	spath->name = name; //FIXME - valid forever??
	spath->kobj.kset = rfs_flt_subpath_kset;
	kobject_init(&spath->kobj, &rfs_flt_sp_ktype);
	rv = kobject_add(&spath->kobj, NULL, "%s", spath->name);
	if (rv)
		return -EINVAL;
	atomic_set(&spath->count, 1);

	kobject_uevent(&spath->kobj, KOBJ_ADD);
	spath->rpath = rpath;
	bdata = kzalloc(sizeof(struct rfs_branch_data), GFP_KERNEL);
	INIT_LIST_HEAD(&bdata->branches);
	redirfs_init_data(&bdata->data, unionflt, &unionflt_free_data, NULL);
	root = redirfs_get_root_path(rpath);
	if (!root)
		return -EINVAL;
	redirfs_attach_data_root(unionflt, root, &bdata->data);
	redirfs_put_root(root);

	return 0;
}

static int unionflt_add_path(struct redirfs_path_info *info)
{
	struct rfs_path *rpath;
	int rv;

	rpath = redirfs_add_path(unionflt, info);

	rv = unionflt_add_branch(info->dentry->d_name.name, rpath);
	if (rv) {
		redirfs_put_path(rpath);
		rpath = ERR_PTR(rv);
		return rv;
	}
	return 0;
}

static int unionflt_destroy_subpath(struct rfs_path *rpath)
{
	struct rfs_root *root;
	struct rfs_flt_subpath *spath;
	struct kobject *kobj;
	struct list_head *pos, *q;
	struct redirfs_data *data;

	root = rpath->rroot;
	data = redirfs_detach_data_root(unionflt, root);

	list_for_each_safe(pos, q, &rfs_flt_subpath_kset->list) {
		kobj = list_entry(pos, struct kobject, entry);
		spath = rfs_kobj_to_rflt_sp(kobj);
		if (spath->rpath != rpath)
			continue;
		unionflt_destroy_all_branches(spath);
		redirfs_put_data(data);
		redirfs_put_data(data);
		redirfs_put_data(data);
		kobject_del(&spath->kobj);
		//kobject_put(&spath->kobj);
		kfree(spath);
		return 0;
	}

	return 1;
}

static int unionflt_destroy_subpaths(void)
{
	struct kobject *kobj;
	struct rfs_flt_subpath *spath;
	struct list_head *pos, *q;
	struct redirfs_data *data;

	list_for_each_safe(pos, q, &rfs_flt_subpath_kset->list) {
		kobj = list_entry(pos, struct kobject, entry);
		spath = rfs_kobj_to_rflt_sp(kobj);
		unionflt_destroy_all_branches(spath);
		data = redirfs_detach_data_root(unionflt, spath->rpath->rroot);
		redirfs_put_data(data);
		redirfs_put_data(data);
		redirfs_put_data(data);
		kobject_del(&spath->kobj);
		//kobject_put(&spath->kobj);
		kfree(spath);
	}

	return 0;
}

static int unionflt_rem_path(redirfs_path rrpath)
{
	int rv;
	struct rfs_path *rpath = (struct rfs_path *) rrpath;
	
	rv = unionflt_destroy_subpath(rpath);
	if (rv)
		return rv;

	rv = redirfs_rem_path(unionflt, rpath);
		return rv;
}

static int unionflt_rem_paths(void)
{
	int rv;

	rv = unionflt_destroy_subpaths();

	rv = redirfs_rem_paths(unionflt);
	return rv;
}

static struct redirfs_filter_operations unionflt_ops = {
	.add_path = &unionflt_add_path,
	.rem_path = &unionflt_rem_path,
	.rem_paths = &unionflt_rem_paths
};

static struct redirfs_filter_info unionflt_info = {
	.owner = THIS_MODULE,
	.name = "unionflt",
	.priority = 400000000,
	.active = 1,
	.ops = &unionflt_ops
};

struct rfs_branch *rfs_subpath_find_id(struct rfs_branch_data *bdata, int id)
{
	struct rfs_branch *found = NULL;
	struct rfs_branch *branch;

	list_for_each_entry(branch, &bdata->branches, list) {
		if (branch->rpath->id != id)
			continue;

		redirfs_get_path(branch->rpath);
		found = branch;
		break;
	}

	return found;
}

static int rfs_branch_get_id(struct rfs_branch_data *bdata)
{
	struct rfs_branch *branch = NULL;
	int i = 0;

	while (i < INT_MAX) {
		list_for_each_entry(branch, &bdata->branches, list) {
			if (branch->rpath->id == i) {
				i++;
				continue;
			}
		}
		return i;
	}

	return -1;
}

static int rfs_path_check_fs(struct file_system_type *type)
{
	if (!strcmp("cifs", type->name))
		goto notsup;

	return 0;
notsup:
	printk(KERN_ERR "redirfs does not support '%s' file system\n",
			type->name);
	return -1;
}

static struct rfs_path *rfs_path_alloc(struct vfsmount *mnt,
		struct dentry *dentry)
{
	struct rfs_path *rpath;

	rpath = kzalloc(sizeof(struct rfs_path), GFP_KERNEL);
	if (!rpath)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&rpath->list);
	INIT_LIST_HEAD(&rpath->rroot_list);
	rpath->mnt = mntget(mnt);
	rpath->dentry = dget(dentry);
	atomic_set(&rpath->count, 1);

	return rpath;
}

static int search_for_prio(struct rfs_branch_data *bdata, int prio) {
	struct rfs_branch *branch;

	list_for_each_entry(branch, &bdata->branches, list) {
		if (branch->priority == prio)
			return 1;
	}
	return 0;
}

static int unionflt_cmp_prio(void *priv, struct list_head *a, struct list_head *b)
{
	struct rfs_branch *from_a, *from_b;

	from_a = list_entry(a, struct rfs_branch, list);
	from_b = list_entry(b, struct rfs_branch, list);
	if (from_a->priority < from_b->priority)
		return -1;
	else if (from_a->priority > from_b->priority)
		return 1;
	else
		return 0;
}

redirfs_path redirfs_add_path2spath(struct rfs_flt_subpath *spath,
		struct redirfs_path_info *info)
{
	struct rfs_path *rpath = NULL;
	struct rfs_root *root;
	struct redirfs_data *data;
	struct rfs_branch_data *bdata;
	struct rfs_branch *branch;
	int id;

	might_sleep();

	if (!spath || IS_ERR(spath) || !info)
		return ERR_PTR(-EINVAL);

	if (!info->mnt || !info->dentry || !info->flags)
		return ERR_PTR(-EINVAL);

	if (rfs_path_check_fs(info->dentry->d_inode->i_sb->s_type))
		return ERR_PTR(-EPERM);

	rfs_rename_lock(info->dentry->d_inode->i_sb);

	root = redirfs_get_root_path(spath->rpath);
	if (!root) {
		rfs_rename_unlock(info->dentry->d_inode->i_sb);
		return root;
	}

	data = redirfs_get_data_root(unionflt, root);
	if (!data)
		goto exit;
	bdata = rfs_data_to_rfs_branch(data);

	if (search_for_prio(bdata, info->flags))
		goto exit;

	id = rfs_branch_get_id(bdata);
	if (id < 0)
		goto exit;

	rpath = rfs_path_alloc(info->mnt, info->dentry);
	if (IS_ERR(rpath))
		goto exit;
	rpath->id = id;

	branch = alloc_branch(info->flags, rpath);
	if (!branch)
		goto exit;

	INIT_LIST_HEAD(&branch->list);
	list_add(&branch->list, &bdata->branches);
	list_sort(NULL, &bdata->branches, &unionflt_cmp_prio);
	if (IS_ERR(rpath))
		goto exit;

exit:
	redirfs_put_data(data);
	redirfs_put_root(root);
	rfs_rename_unlock(info->dentry->d_inode->i_sb);
	return rpath;
}

int rfs_path_get_info_sp(struct rfs_flt_subpath *spath, char *buf, int size)
{
	struct rfs_root *root;
	struct redirfs_data *data;
	struct rfs_branch_data *bdata;
	struct rfs_branch *branch;
	char *path;
	int len = 0;
	int rv = 0;

	path = kzalloc(sizeof(char) * PAGE_SIZE, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	root = redirfs_get_root_path(spath->rpath);
	if (!root)
		return -ENOENT;
	data = redirfs_get_data_root(unionflt, root);
	if (!data)
		return -ENOENT;
	bdata = rfs_data_to_rfs_branch(data);

	list_for_each_entry(branch, &bdata->branches, list) {
		rv = redirfs_get_filename(branch->rpath->mnt, branch->rpath->dentry, path,
				PAGE_SIZE);
		if (rv) {
			redirfs_put_data(data);
			redirfs_put_root(root);
			kfree(path);
			return rv;
		}

		len += snprintf(buf + len, size - len,"%d:%d:%s",
				branch->priority, branch->rpath->id, path) + 1;

		if (len >= size) {
			len = size;
			break;
		}
	}

	redirfs_put_data(data);
	redirfs_put_root(root);
	kfree(path);

	return len;
}



struct getdents_callback {
       struct linux_dirent __user *current_dir;
       struct linux_dirent __user *previous;
       int count;
       int error;
};

struct union_cache_callback {
       struct getdents_callback *buf;  /* original getdents_callback */
       //struct list_head list;          /* list of union cache entries */
       filldir_t filler;               /* the filldir() we should call */
       loff_t offset;                  /* base offset of our dirents */
       loff_t count;                   /* maximum number of bytes to "read" */
};

static int filldir_union(void *buf, const char *name, int namlen,
	                     loff_t offset, u64 ino, unsigned int d_type)
{
       struct union_cache_callback *cb = buf;

       switch (namlen) {
	        case 2:
			if (name[1] != '.')
		                break;
	        case 1:
		        if (name[0] != '.')
		                break;
		return 0;
       }

       return cb->filler(cb->buf, name, namlen, cb->offset + offset, ino, d_type);
}

static void *unionflt_alloc(size_t size)
{
	void *p;

	p = kmalloc(size, GFP_KERNEL);
	if (!p)
		return NULL;

	memset(p, 0, size);

	return p;
}

struct rfs_branch_data *unionflt_get_root_data(struct vfsmount *mnt, struct dentry *dentry)
{
	struct rfs_path *rpath = NULL;
	struct rfs_root *root;
	struct rfs_branch_data *bdata;
	struct redirfs_data *data;
	struct kobject *kobj;
	struct rfs_flt_subpath *spath;

	list_for_each_entry(kobj, &rfs_flt_subpath_kset->list, entry) {
		spath = rfs_kobj_to_rflt_sp(kobj);
		rpath = spath->rpath;
		break;
	}
	if (!rpath)
		return (void *) rpath;
	redirfs_get_path(rpath);
	root = redirfs_get_root_path(rpath);
	redirfs_put_path(rpath);
	if (!root)
		return (void *) root;
	data = redirfs_get_data_root(unionflt, root);
	if (!data)
		return (void *) data;
	bdata = rfs_data_to_rfs_branch(data);
	redirfs_put_root(root);
	
	return bdata;
}

/* FIXME - revert into array or change location */
static struct inode *inode_old;
static struct inode *inode_new;

static char symlink_buffer[SYMLINK_BUFFER];

/*
 * Private callback for follow_link inode operation
 */
static void *unionflt_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	nd_set_link(nd, symlink_buffer);
	return NULL;
}

static struct inode_operations unionflt_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= unionflt_follow_link
};

/*
 * Allocate new inode with symlink address
 */
static struct inode *unionflt_symlink_alloc(struct super_block *sb)
{
	struct inode *inode;

	inode = new_inode(sb);
	if (IS_ERR(inode))
		goto out_alloc;

	inode->i_flags |= S_PRIVATE;
	inode->i_op = &unionflt_symlink_inode_operations;

out_alloc:
	return inode;
}

/*
 * Detach inode from dentry
 */
static void unionflt_d_deinstantiate(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;

	spin_lock(&dentry->d_lock);
	spin_lock(&dcache_lock);
	if (inode) {
		dentry->d_inode = NULL;
		list_del_init(&dentry->d_alias);
	}
	spin_unlock(&dentry->d_lock);
	spin_unlock(&dcache_lock);
};

/*
 * Set new symlink address to inode
 */
void unionflt_symlink_set(char *address)
{
	memset(symlink_buffer, '\0', SYMLINK_BUFFER);
	strcpy(symlink_buffer, address);
}

/*
 * Drop symlink inode
 */
static void unionflt_symlink_drop(struct dentry *dentry) 
{
	struct inode *inode = dentry->d_inode;

	iput(inode);
	return;
}

enum redirfs_rv unionflt_lookup(redirfs_context context,
		struct redirfs_args *args)
{
	char *path, *mntpath, *cut, *ch_rev, *cpath;
	int rv;
	struct nameidata nd;
	struct path branch_path;
	struct rfs_branch_data *bdata;
	struct rfs_branch *branch;

	if (!args->args.i_lookup.nd)
		return REDIRFS_CONTINUE;

	path = unionflt_alloc(sizeof(char) * PAGE_SIZE);
	if (!path)
		return REDIRFS_CONTINUE;
	mntpath = unionflt_alloc(sizeof(char) * PAGE_SIZE);
	if (!mntpath)
		return REDIRFS_CONTINUE;

        bdata = unionflt_get_root_data(args->args.i_lookup.nd->path.mnt,
			args->args.i_lookup.nd->path.dentry);
	if (!bdata) {
		printk(KERN_ALERT "NO DATA!\n");
		goto exit2;
	}

	/* WORKAROUND1 -FIXME */
	/* backup of inode of mount point */
	path_lookup("/mnt/union", LOOKUP_FOLLOW, &nd);
	inode_old = nd.path.dentry->d_inode;
	/* allocating of fake inode for redirecting */
	inode_new = unionflt_symlink_alloc(nd.path.mnt->mnt_sb);
	
	/* reconstruction of lookup path */
	ch_rev = d_path(&args->args.i_lookup.nd->path, path, PAGE_SIZE);
	if (IS_ERR(ch_rev)) {
		goto exit2;
	}
	strcpy(path,ch_rev);
	printk(KERN_ALERT "init path %s\n", path);
	/* WORKAROUND1 - FIXME*/
	strcpy(mntpath, "/mnt/union/");
	printk(KERN_ALERT "init mntpath %s\n", mntpath);
	/* cut the root of union path from begin */
	cpath = path;
	cut = mntpath;
	while (*cut && *cpath && *cut == *cpath) {
		cut++;
		cpath++;
	}
	printk(KERN_ALERT "cutted path %s\n", cpath);

	list_for_each_entry(branch, &bdata->branches, list) {
		memset(mntpath, '\0', PAGE_SIZE);
		/* Recreate path of branch root into ch_rev*/
		branch_path.mnt = branch->rpath->mnt;
		branch_path.dentry = branch->rpath->dentry;
		ch_rev = d_path(&branch_path, mntpath, PAGE_SIZE);
		if (IS_ERR(ch_rev)) {
			continue;
		}
		strcpy(mntpath, ch_rev);
		printk(KERN_ALERT "base %s\n", mntpath);

		strcat(mntpath,"/");
		/* Here is complete path to search in subbranch */
		strcat(mntpath,cpath);
		strcat(mntpath,args->args.i_lookup.dentry->d_name.name);
		printk(KERN_ALERT "full %s\n", mntpath);
		/* Is there the dentry we searched for? */
		rv = path_lookup(mntpath, LOOKUP_FOLLOW, &nd);
		if (rv) {
			/* No, continue to another branch */
			printk(KERN_ALERT "No success in this branch..continue");
			continue;
		}
		printk(KERN_ALERT "Dentry were found!");
		/* Searched dentry exists in this branch */
		/* => Remove former inode */
		unionflt_d_deinstantiate(args->args.i_lookup.nd->path.dentry);
		/* Get symlink address - root path of branch */
		unionflt_symlink_set(ch_rev);
		/* Attach fake inode to mount point dentry */
		d_instantiate(args->args.i_lookup.nd->path.dentry, inode_new);
		args->args.i_lookup.dir = inode_new;
		/* Break and give new inode into lower FS layer */
		break;
	}

	/* If no dentry in subpaths were found, there are no changes */

exit2:
	redirfs_put_data(&bdata->data);
	kfree(path);
	kfree(mntpath);
	return REDIRFS_CONTINUE;
}

enum redirfs_rv unionflt_lookup_post(redirfs_context context,
		struct redirfs_args *args)
{
	/* detach new redirect inode */
	unionflt_d_deinstantiate(args->args.i_lookup.nd->path.dentry);
	unionflt_symlink_drop(args->args.i_lookup.nd->path.dentry);

	/* re-attach old inode */
	d_instantiate(args->args.i_lookup.nd->path.dentry, inode_old);
	args->args.i_lookup.dir = inode_old;
drop_out:
	return REDIRFS_CONTINUE;
}

/*
enum redirfs_rv unionflt_readdir(redirfs_context context,
		struct redirfs_args *args)
{
	int rv;
	struct file *ftmp;
	struct rfs_path *rpath;
	struct file *file = args->args.f_readdir.file;
	struct nameidata nd;
	struct inode *inode = args->args.f_readdir.file->f_path.dentry->d_inode;
	struct union_cache_callback cb;
	const struct cred *cred = current_cred();
	char *path;
	loff_t offset = 0;
	struct rfs_branch_data *bdata;
	struct rfs_branch *branch;

	if (!args->args.f_readdir.file)
		return REDIRFS_CONTINUE;

	path = unionflt_alloc(sizeof(char) * PAGE_SIZE);
	if (!path)
		return REDIRFS_CONTINUE;

	cb.buf = args->args.f_readdir.dirent;
	cb.filler = args->args.f_readdir.filldir;
	cb.offset = 0;
	cb.count = args->args.f_readdir.file->f_pos;

        bdata = unionflt_get_root_data(args->args.f_readdir.file->f_path.mnt,
			args->args.f_readdir.file->f_path.dentry);

	if (!bdata)
		goto out;



	*//* Priority layer *//*
	list_for_each_entry(branch, &bdata->branches, list) {

		memset(path,0,PAGE_SIZE);
		rv = redirfs_get_filename(branch->rpath->mnt, branch->rpath->dentry, path, PAGE_SIZE);
		if (rv)
			continue;
		rv = path_lookup(path, LOOKUP_FOLLOW, &nd);
		if (rv)
			continue;
		ftmp = dentry_open(nd.path.dentry, nd.path.mnt,
				O_RDONLY | O_DIRECTORY | O_NOATIME, cred);

		if (IS_ERR(ftmp)) {
			continue;
		}

		path_get(&nd.path);
		inode = nd.path.dentry->d_inode;
		mutex_lock(&inode->i_mutex);
		cb.offset += offset;
		offset = i_size_read(inode);
		ftmp->f_pos = file->f_pos - cb.offset;
		cb.count = ftmp->f_pos;
		if (ftmp->f_pos < 0) {
			mutex_unlock(&inode->i_mutex);
			fput(ftmp);
			path_put(&nd.path);
			continue;
		}

		if (ftmp->f_pos < offset) {
			  rv = ftmp->f_op->readdir(ftmp, &cb, filldir_union);
			  file_accessed(ftmp);
			  if (rv)
				   file->f_pos += ftmp->f_pos;
			  else
			       *//*
				* We read until EOF of this directory, so lets
				* advance the f_pos by the maximum offset
				* (i_size) of this directory
				*//*
				    file->f_pos += offset;
		}

		file_accessed(ftmp);
		mutex_unlock(&inode->i_mutex);
		path_put(&nd.path);
		fput(ftmp);
	}

out:
	redirfs_put_data(&bdata->data);
	kfree(path);
	return REDIRFS_CONTINUE;
}
*/

static struct redirfs_op_info unionflt_op_info[] = {
	{REDIRFS_DIR_IOP_LOOKUP, unionflt_lookup, unionflt_lookup_post},
	//{REDIRFS_DIR_FOP_READDIR, unionflt_readdir, NULL},
	{REDIRFS_OP_END, NULL, NULL}
};

static int __init unionflt_init(void)
{
	int err;
	int rv;

	unionflt = redirfs_register_filter(&unionflt_info);
	if (IS_ERR(unionflt)) {
		rv = PTR_ERR(unionflt);
		printk(KERN_ERR "unionflt: register filter failed(%d)\n", rv);
		return rv;
	}

	rv = redirfs_set_operations(unionflt, unionflt_op_info);
	if (rv) {
		printk(KERN_ERR "unionflt: set operations failed(%d)\n", rv);
		goto error;
	}

	rfs_flt_subpath_kset = kset_create_and_add("umounts", NULL, 
			redirfs_filter_kobject(unionflt));
	if (!rfs_flt_subpath_kset) {
		goto error;
	}

	printk(KERN_INFO "Union Filter Version "
			UNIONFLT_VERSION " <www.redirfs.org>\n");
	return 0;
error:
	err = redirfs_unregister_filter(unionflt);
	if (err) {
		printk(KERN_ERR "unionflt: unregister filter "
				"failed(%d)\n", err);
		return 0;
	}
	redirfs_delete_filter(unionflt);
	return rv;
}

static void __exit unionflt_exit(void)
{
	unionflt_destroy_subpaths();
	kset_unregister(rfs_flt_subpath_kset);
	redirfs_delete_filter(unionflt);
}

module_init(unionflt_init);
module_exit(unionflt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Petr Holasek <holasekp@gmail.com>");
MODULE_DESCRIPTION("Union Filter Version " UNIONFLT_VERSION "<www.redirfs.org>");

