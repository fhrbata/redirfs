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

static LIST_HEAD(rfs_fst_list);
static spinlock_t rfs_fst_list_lock = SPIN_LOCK_UNLOCKED;

static struct rfs_fst *rfs_fst_alloc(struct file_system_type *fst)
{
	struct rfs_fst *rfst;

	rfst = kmalloc(sizeof(struct rfs_fst), GFP_KERNEL);
	if (!rfst)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&rfst->list);
	INIT_LIST_HEAD(&rfst->rpaths);
	rfst->fst = fst;
	rfst->iops = NULL;
	rfst->rename = NULL;
	atomic_set(&rfst->count, 1);

	return rfst;
}

struct rfs_fst *rfs_fst_get(struct rfs_fst *rfst)
{
	if (!rfst || IS_ERR(rfst))
		return NULL;

	BUG_ON(!atomic_read(&rfst->count));
	atomic_inc(&rfst->count);

	return rfst;
}

void rfs_fst_put(struct rfs_fst *rfst)
{
	if (!rfst || IS_ERR(rfst))
		return;

	BUG_ON(!atomic_read(&rfst->count));
	if (!atomic_dec_and_test(&rfst->count))
		return;

	kfree(rfst);
}

static void rfs_fst_hook_rename(struct rfs_fst *rfst, struct inode *inode)
{
	if (!inode->i_op->rename)
		return;

	if (rfst->rename)
		return;

	rfst->iops = (struct inode_operations*)inode->i_op;
	rfst->rename = rfst->iops->rename;
	rfst->iops->rename = rfs_fsrename;
}

static void rfs_fst_unhook_rename(struct rfs_fst *rfst)
{
	if (!rfst->rename)
		return;

	rfst->iops->rename = rfst->rename;
}

struct rfs_fst *rfs_fst_find(struct file_system_type *fst)
{
	struct rfs_fst *rfst = NULL;
	struct rfs_fst *found = NULL;

	spin_lock(&rfs_fst_list_lock);

	list_for_each_entry(rfst, &rfs_fst_list, list) {
		if (rfst->fst == fst) {
			found = rfs_fst_get(rfst);
			break;
		}
	}

	spin_unlock(&rfs_fst_list_lock);

	return found;
}

static void rfs_fst_list_add(struct rfs_fst *rfst)
{
	spin_lock(&rfs_fst_list_lock);
	list_add_tail(&rfst->list, &rfs_fst_list);
	spin_unlock(&rfs_fst_list_lock);
	rfs_fst_get(rfst);
}

static void rfs_fst_list_rem(struct rfs_fst *rfst)
{
	spin_lock(&rfs_fst_list_lock);
	list_del_init(&rfst->list);
	spin_unlock(&rfs_fst_list_lock);
	rfs_fst_put(rfst);
}

void rfs_fst_add_rpath(struct rfs_fst *rfst, struct rfs_path *rpath)
{
	list_add_tail(&rpath->rfst_list, &rfst->rpaths);
	rfs_path_get(rpath);
}

void rfs_fst_rem_rpath(struct rfs_fst *rfst, struct rfs_path *rpath)
{
	list_del_init(&rpath->rfst_list);
	rfs_path_put(rpath);

	if (!list_empty(&rfst->rpaths))
		return;

	rfs_fst_unhook_rename(rfst);
	rfs_fst_list_rem(rfst);
}

struct rfs_fst *rfs_fst_add(struct super_block *sb)
{
	struct rfs_fst *rfst;

	rfst = rfs_fst_find(sb->s_type);
	if (rfst)
		return rfst;

	rfst = rfs_fst_alloc(sb->s_type);
	if (IS_ERR(rfst))
		return rfst;

	rfs_fst_hook_rename(rfst, sb->s_root->d_inode);
	rfs_fst_list_add(rfst);

	return rfst;
}

