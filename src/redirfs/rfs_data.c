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

int redirfs_init_data(struct redirfs_data *data, redirfs_filter filter,
		void (*cb)(struct redirfs_data *))
{
	if (!data || filter || cb)
		return -EINVAL;

	INIT_LIST_HEAD(&data->list);
	atomic_set(&data->cnt, 1);
	data->cb = cb;
	data->filter = (redirfs_filter)rfs_flt_get((struct rfs_flt *)filter);

	return 0;
}

struct redirfs_data *redirfs_get_data(struct redirfs_data *data)
{
	if (!data || IS_ERR(data))
		return NULL;
	
	BUG_ON(!atomic_read(&data->cnt));

	atomic_inc(&data->cnt);

	return data;
}

void redirfs_put_data(struct redirfs_data *data)
{
	if (!data || IS_ERR(data))
		return;

	BUG_ON(!atomic_read(&data->cnt));
	
	if (!atomic_dec_and_test(&data->cnt))
		return;

	data->cb(data);
	rfs_flt_put((struct rfs_flt *)data->filter);
}

static struct redirfs_data *rfs_find_data(struct list_head *head,
		redirfs_filter filter)
{
	struct redirfs_data *found = NULL;
	struct redirfs_data *loop = NULL;

	list_for_each_entry(loop, head, list) {
		if (loop->filter == filter) {
			found = redirfs_get_data(loop);
			break;
		}
	}

	return found;
}

int redirfs_attach_data_file(redirfs_filter filter, struct file *file,
		struct redirfs_data *data, struct redirfs_data **exist)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;
	struct rfs_file *rfile = NULL;
	int rv = 0;

	if (!filter || !file || !data || !exist)
		return -EINVAL;

	rfile = rfs_file_find(file);
	if (!rfile)
		return -ENODATA;

	spin_lock(&rfile->rdentry->lock);
	spin_lock(&rfile->lock);

	if (rfs_chain_find(rfile->rdentry->rinfo->rchain, rflt) == -1) {
		rv = -ENODATA;
		goto exit;
	}

	*exist = rfs_find_data(&rfile->data, filter);
	if (*exist) {
		rv = -EEXIST;
		goto exit;
	}

	list_add_tail(&data->list, &rfile->data); 
	redirfs_get_data(data);
	*exist = NULL;
exit:
	spin_unlock(&rfile->lock);
	spin_unlock(&rfile->rdentry->lock);
	rfs_file_put(rfile);
	return rv;
}

struct redirfs_data *redirfs_detach_data_file(redirfs_filter filter,
		struct file *file)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;
	struct rfs_file *rfile = NULL;
	struct redirfs_data *data;

	if (!filter || !file)
		return ERR_PTR(-EINVAL);

	rfile = rfs_file_find(file);
	if (!rfile)
		return ERR_PTR(-ENODATA);

	spin_lock(&rfile->lock);

	data = rfs_find_data(&rfile->data, rflt);
	if (!data) {
		spin_unlock(&rfile->lock);
		rfs_file_put(rfile);
		return ERR_PTR(-ENODATA);
	}

	list_del(&data->list);
	spin_unlock(&rfile->lock);
	rfs_file_put(rfile);
	return data;
}

struct redirfs_data *redirfs_get_data_file(redirfs_filter filter,
		struct file *file)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;
	struct rfs_file *rfile = NULL;
	struct redirfs_data *data;

	if (!filter || !file)
		return ERR_PTR(-EINVAL);

	rfile = rfs_file_find(file);
	if (!rfile)
		return ERR_PTR(-EINVAL);

	spin_lock(&rfile->lock);

	data = rfs_find_data(&rfile->data, rflt);
	if (!data) {
		spin_unlock(&rfile->lock);
		rfs_file_put(rfile);
		return ERR_PTR(-ENODATA);
	}

	redirfs_get_data(data);
	spin_unlock(&rfile->lock);
	rfs_file_put(rfile);
	return data;
}

int redirfs_attach_data_dentry(redirfs_filter filter, struct dentry *dentry,
		struct redirfs_data *data, struct redirfs_data **exist)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;
	struct rfs_dentry *rdentry = NULL;
	int rv = 0;

	if (!filter || !dentry || !data || !exist)
		return -EINVAL;

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry)
		return -ENODATA;

	spin_lock(&rdentry->lock);

	if (rfs_chain_find(rdentry->rinfo->rchain, rflt) == -1) {
		rv = -ENODATA;
		goto exit;
	}

	*exist = rfs_find_data(&rdentry->data, filter);
	if (*exist) {
		rv = -EEXIST;
		goto exit;
	}

	list_add_tail(&data->list, &rdentry->data); 
	redirfs_get_data(data);
	*exist = NULL;
exit:
	spin_unlock(&rdentry->lock);
	rfs_dentry_put(rdentry);
	return rv;
}

struct redirfs_data *redirfs_detach_data_dentry(redirfs_filter filter,
		struct dentry *dentry)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;
	struct rfs_dentry *rdentry = NULL;
	struct redirfs_data *data;

	if (!filter || !dentry)
		return ERR_PTR(-EINVAL);

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry)
		return ERR_PTR(-ENODATA);

	spin_lock(&rdentry->lock);

	data = rfs_find_data(&rdentry->data, rflt);
	if (!data) {
		spin_unlock(&rdentry->lock);
		rfs_dentry_put(rdentry);
		return ERR_PTR(-ENODATA);
	}

	list_del(&data->list);
	spin_unlock(&rdentry->lock);
	rfs_dentry_put(rdentry);
	return data;
}

struct redirfs_data *redirfs_get_data_dentry(redirfs_filter filter,
		struct dentry *dentry)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;
	struct rfs_dentry *rdentry = NULL;
	struct redirfs_data *data;

	if (!filter || !dentry)
		return ERR_PTR(-EINVAL);

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry)
		return ERR_PTR(-EINVAL);

	spin_lock(&rdentry->lock);

	data = rfs_find_data(&rdentry->data, rflt);
	if (!data) {
		spin_unlock(&rdentry->lock);
		rfs_dentry_put(rdentry);
		return ERR_PTR(-ENODATA);
	}

	redirfs_get_data(data);
	spin_unlock(&rdentry->lock);
	rfs_dentry_put(rdentry);
	return data;
}

int redirfs_attach_data_inode(redirfs_filter filter, struct inode *inode,
		struct redirfs_data *data, struct redirfs_data **exist)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;
	struct rfs_inode *rinode = NULL;
	int rv = 0;

	if (!filter || !inode || !data || !exist)
		return -EINVAL;

	rinode = rfs_inode_find(inode);
	if (!rinode)
		return -ENODATA;

	spin_lock(&rinode->lock);

	if (rfs_chain_find(rinode->rinfo->rchain, rflt) == -1) {
		rv = -ENODATA;
		goto exit;
	}

	*exist = rfs_find_data(&rinode->data, filter);
	if (*exist) {
		rv = -EEXIST;
		goto exit;
	}

	list_add_tail(&data->list, &rinode->data); 
	redirfs_get_data(data);
	*exist = NULL;
exit:
	spin_unlock(&rinode->lock);
	rfs_inode_put(rinode);
	return rv;
}

struct redirfs_data *redirfs_detach_data_inode(redirfs_filter filter,
		struct inode *inode)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;
	struct rfs_inode *rinode = NULL;
	struct redirfs_data *data;

	if (!filter || !inode)
		return ERR_PTR(-EINVAL);

	rinode = rfs_inode_find(inode);
	if (!rinode)
		return ERR_PTR(-ENODATA);

	spin_lock(&rinode->lock);

	data = rfs_find_data(&rinode->data, rflt);
	if (!data) {
		spin_unlock(&rinode->lock);
		rfs_inode_put(rinode);
		return ERR_PTR(-ENODATA);
	}

	list_del(&data->list);
	spin_unlock(&rinode->lock);
	rfs_inode_put(rinode);
	return data;
}

struct redirfs_data *redirfs_get_data_inode(redirfs_filter filter,
		struct inode *inode)
{
	struct rfs_flt *rflt = (struct rfs_flt *)filter;
	struct rfs_inode *rinode = NULL;
	struct redirfs_data *data;

	if (!filter || !inode)
		return ERR_PTR(-EINVAL);

	rinode = rfs_inode_find(inode);
	if (!rinode)
		return ERR_PTR(-EINVAL);

	spin_lock(&rinode->lock);

	data = rfs_find_data(&rinode->data, rflt);
	if (!data) {
		spin_unlock(&rinode->lock);
		rfs_inode_put(rinode);
		return ERR_PTR(-ENODATA);
	}

	redirfs_get_data(data);
	spin_unlock(&rinode->lock);
	rfs_inode_put(rinode);
	return data;
}

EXPORT_SYMBOL(redirfs_init_data);
EXPORT_SYMBOL(redirfs_get_data);
EXPORT_SYMBOL(redirfs_put_data);
EXPORT_SYMBOL(redirfs_attach_data_file);
EXPORT_SYMBOL(redirfs_detach_data_file);
EXPORT_SYMBOL(redirfs_get_data_file);
EXPORT_SYMBOL(redirfs_attach_data_dentry);
EXPORT_SYMBOL(redirfs_detach_data_dentry);
EXPORT_SYMBOL(redirfs_get_data_dentry);
EXPORT_SYMBOL(redirfs_attach_data_inode);
EXPORT_SYMBOL(redirfs_detach_data_inode);
EXPORT_SYMBOL(redirfs_get_data_inode);

