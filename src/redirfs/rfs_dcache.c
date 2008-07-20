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

struct rfs_dcache_data *rfs_dcache_data_alloc(struct dentry *dentry,
		struct rfs_info *rinfo, struct rfs_flt *rflt)
{
	struct rfs_dcache_data *rdata;

	rdata = kmalloc(sizeof(struct rfs_dcache_data), GFP_KERNEL);
	if (!rdata)
		return ERR_PTR(-ENOMEM);

	rdata->rinfo = rinfo;
	rdata->rflt = rflt;
	rdata->droot = dentry;

	return rdata;
}

void rfs_dcache_data_free(struct rfs_dcache_data *rdata)
{
	if (!rdata || IS_ERR(rdata))
		return;

	kfree(rdata);
}

static struct rfs_dcache_entry *rfs_dcache_entry_alloc(struct dentry *dentry,
		struct list_head *list, int type)
{
	struct rfs_dcache_entry *entry;

	entry = kmalloc(sizeof(struct rfs_dcache_entry), type);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&entry->list);
	spin_lock(&dentry->d_lock);
	atomic_inc(&dentry->d_count);
	entry->dentry = dentry;
	spin_unlock(&dentry->d_lock);
	list_add_tail(&entry->list, list);

	return entry;
}

static void rfs_dcache_entry_free(struct rfs_dcache_entry *entry)
{
	if (!entry)
		return;

	list_del_init(&entry->list);
	dput(entry->dentry);
	kfree(entry);
}

int rfs_dcache_get_subs(struct dentry *dir, struct list_head *sibs)
{
	struct rfs_dcache_entry *sib;
	struct dentry *dentry;
	int rv = 0;

	spin_lock(&dcache_lock);

	list_for_each_entry(dentry, &dir->d_subdirs, d_u.d_child) {

		sib = rfs_dcache_entry_alloc(dentry, sibs, GFP_ATOMIC);
		if (IS_ERR(sib)) {
			rv = PTR_ERR(sib);
			break;
		}
	}

	spin_unlock(&dcache_lock);

	return rv;
}

void rfs_dcache_entry_free_list(struct list_head *head)
{
	struct rfs_dcache_entry *entry;
	struct rfs_dcache_entry *tmp;

	list_for_each_entry_safe(entry, tmp, head, list) {
		rfs_dcache_entry_free(entry);
	}
}

static int rfs_dcache_get_subs_mutex(struct dentry *dir, struct list_head *sibs)
{
	int rv = 0;

	if (!dir || !dir->d_inode)
		return 0;

	mutex_lock(&dir->d_inode->i_mutex);
	rv = rfs_dcache_get_subs(dir, sibs);
	mutex_unlock(&dir->d_inode->i_mutex);

	return rv;
}

static int rfs_dcache_get_dirs(struct list_head *dirs, struct list_head *sibs)
{
	struct rfs_dcache_entry *entry;
	struct rfs_dcache_entry *dir;
	struct rfs_dcache_entry *tmp;

	list_for_each_entry_safe(entry, tmp, sibs, list) {
		if (!entry->dentry->d_inode)
			continue;

		if (!S_ISDIR(entry->dentry->d_inode->i_mode))
			continue;

		dir = rfs_dcache_entry_alloc(entry->dentry, dirs, GFP_KERNEL);
		if (IS_ERR(dir))
			return PTR_ERR(dir);

		rfs_dcache_entry_free(entry);
	}

	return 0;
}

int rfs_dcache_walk(struct dentry *root, int (*cb)(struct dentry *, void *),
		void *data)
{
	LIST_HEAD(dirs);
	LIST_HEAD(sibs);
	struct rfs_dcache_entry *dir;
	struct rfs_dcache_entry *sib;
	int rv = 0;

	dir = rfs_dcache_entry_alloc(root, &dirs, GFP_KERNEL);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	while (!list_empty(&dirs)) {
		dir = list_entry(dirs.next, struct rfs_dcache_entry, list);

		rv = cb(dir->dentry, data);
		if (rv < 0)
			goto exit;

		if (rv > 0 || !dir->dentry->d_inode) {
			rfs_dcache_entry_free(dir);
			rv = 0;
			continue;
		}

		rv = rfs_dcache_get_subs_mutex(dir->dentry, &sibs);
		if (rv)
			goto exit;

		rv = rfs_dcache_get_dirs(&dirs, &sibs);
		if (rv)
			goto exit;

		list_for_each_entry(sib, &sibs, list) {
			rv = cb(sib->dentry, data);
			if (rv < 0)
				goto exit;
		}
		rfs_dcache_entry_free_list(&sibs);
		rfs_dcache_entry_free(dir);
	}
exit:
	list_splice(&sibs, &dirs);
	rfs_dcache_entry_free_list(&dirs);

	return rv;
}

static int rfs_dcache_skip(struct dentry *dentry, struct rfs_dcache_data *rdata)
{
	struct rfs_dentry *rdentry = NULL;
	int rv = 0;

	if (dentry == rdata->droot)
		return 0;

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry)
		return 0;

	if (!rdentry->rinfo)
		goto exit;

	if (!rdentry->rinfo->rroot)
		goto exit;

	if (rdentry->rinfo->rroot->dentry != dentry)
		goto exit;

	rv = 1;
exit:
	rfs_dentry_put(rdentry);
	return rv;
}

int rfs_dcache_rdentry_add(struct dentry *dentry, struct rfs_info *rinfo)
{
	struct rfs_dentry *rdentry = NULL;
	struct rfs_inode *rinode = NULL;
	int rv = 0;

	rdentry = rfs_dentry_add(dentry);
	if (IS_ERR(rdentry))
		return PTR_ERR(rdentry);

	rfs_dentry_set_rinfo(rdentry, rinfo);

	rv = rfs_dentry_add_rinode(rdentry);
	if (rv)
		goto exit;

	spin_lock(&rdentry->lock);
	rinode = rfs_inode_get(rdentry->rinode);
	spin_unlock(&rdentry->lock);
	rv = rfs_inode_set_rinfo(rinode);
	if (rv)
		goto exit;

	rfs_dentry_set_ops(rdentry);
exit:
	rfs_dentry_put(rdentry);
	rfs_inode_put(rinode);
	return rv;
}

int rfs_dcache_rinode_del(struct rfs_dentry *rdentry, struct inode *inode)
{
	struct rfs_inode *rinode = NULL;
	int rv = 0;

	if (!inode)
		return 0;

	rfs_dentry_rem_rinode(rdentry, inode);

	rinode = rfs_inode_find(inode);
	if (!rinode)
		return 0;

	rv = rfs_inode_set_rinfo(rinode);
	if (rv) {
		rfs_inode_put(rinode);
		return rv;
	}

	rfs_inode_set_ops(rinode);
	rfs_inode_put(rinode);

	return 0;
}

static int rfs_dcache_rdentry_del(struct dentry *dentry, struct rfs_info *rinfo)
{
	struct rfs_dentry *rdentry = NULL;
	struct rfs_inode *rinode = NULL;
	int rv = 0;

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry)
		return 0;

	rfs_dentry_set_rinfo(rdentry, rinfo);
	spin_lock(&rdentry->lock);
	rinode = rfs_inode_get(rdentry->rinode);
	spin_unlock(&rdentry->lock);
	rv = rfs_inode_set_rinfo(rinode);
	if (rv)
		goto exit;

	rfs_dentry_set_ops(rdentry);
exit:
	rfs_dentry_put(rdentry);
	rfs_inode_put(rinode);
	return rv;
}

int rfs_dcache_add(struct dentry *dentry, void *data)
{
	struct rfs_dcache_data *rdata = (struct rfs_dcache_data *)data;

	if (rfs_dcache_skip(dentry, rdata)) {
		rfs_root_add_walk(dentry);
		return 1;
	}

	return rfs_dcache_rdentry_add(dentry, rdata->rinfo);
}

int rfs_dcache_rem(struct dentry *dentry, void *data)
{
	struct rfs_dcache_data *rdata = (struct rfs_dcache_data *)data;

	if (rfs_dcache_skip(dentry, rdata)) {
		rfs_root_add_walk(dentry);
		return 1;
	}

	if (!rdata->rinfo->rchain)
		return rfs_dcache_rdentry_del(dentry, rfs_info_deleted);

	return rfs_dcache_rdentry_add(dentry, rdata->rinfo);
}

int rfs_dcache_set(struct dentry *dentry, void *data)
{
	struct rfs_dcache_data *rdata = (struct rfs_dcache_data *)data;

	if (rfs_dcache_skip(dentry, rdata))
		return 1;

	if (!rdata->rinfo->rchain)
		return rfs_dcache_rdentry_del(dentry, rfs_info_deleted);

	return rfs_dcache_rdentry_add(dentry, rdata->rinfo);
}

