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

static struct kmem_cache *rfs_dentry_cache = NULL;
atomic_t rfs_dentry_cnt = ATOMIC_INIT(0);
DECLARE_WAIT_QUEUE_HEAD(rfs_dentry_wait);

void rfs_d_iput(struct dentry *dentry, struct inode *inode);
void rfs_d_release(struct dentry *dentry);

static struct rfs_dentry *rfs_dentry_alloc(struct dentry *dentry)
{
	struct rfs_dentry *rdentry;

	rdentry = kmem_cache_alloc(rfs_dentry_cache, GFP_KERNEL);
	if (!rdentry)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&rdentry->rinode_list);
	INIT_LIST_HEAD(&rdentry->rfiles);
	INIT_LIST_HEAD(&rdentry->priv);
	INIT_RCU_HEAD(&rdentry->rcu);
	rdentry->dentry = dentry;
	rdentry->op_old = dentry->d_op;
	rdentry->rinode = NULL;
	rdentry->rinfo = NULL;
	spin_lock_init(&rdentry->lock);
	atomic_set(&rdentry->count, 1);

	if (dentry->d_op)
		memcpy(&rdentry->op_new, dentry->d_op,
				sizeof(struct dentry_operations));
	else
		memset(&rdentry->op_new, 0,
				sizeof(struct dentry_operations));

	rdentry->op_new.d_iput = rfs_d_iput;
	rdentry->op_new.d_release = rfs_d_release;

	atomic_inc(&rfs_dentry_cnt);

	return rdentry;
}

struct rfs_dentry *rfs_dentry_get(struct rfs_dentry *rdentry)
{
	if (!rdentry || IS_ERR(rdentry))
		return NULL;

	BUG_ON(!atomic_read(&rdentry->count));
	atomic_inc(&rdentry->count);

	return rdentry;
}

void rfs_dentry_put(struct rfs_dentry *rdentry)
{
	if (!rdentry || IS_ERR(rdentry))
		return;

	BUG_ON(!atomic_read(&rdentry->count));
	if (!atomic_dec_and_test(&rdentry->count))
		return;

	rfs_inode_put(rdentry->rinode);
	rfs_info_put(rdentry->rinfo);

	kmem_cache_free(rfs_dentry_cache, rdentry);

	if (atomic_dec_and_test(&rfs_dentry_cnt))
		wake_up_interruptible(&rfs_dentry_wait);
}

struct rfs_dentry *rfs_dentry_find(struct dentry *dentry)
{
	struct rfs_dentry *rdentry = NULL;
	struct dentry_operations *d_op = NULL;

	rcu_read_lock();
	d_op = rcu_dereference(dentry->d_op);
	if (!d_op)
		goto exit;

	if (d_op->d_iput != rfs_d_iput)
		goto exit;

	rdentry = container_of(d_op, struct rfs_dentry, op_new);
	rdentry = rfs_dentry_get(rdentry);
exit:
	rcu_read_unlock();
	return rdentry;
}

struct rfs_dentry *rfs_dentry_add(struct dentry *dentry)
{
	struct rfs_dentry *rd_new;
	struct rfs_dentry *rd;

	if (!dentry)
		return NULL;

	rd_new = rfs_dentry_alloc(dentry);
	if (IS_ERR(rd_new))
		return rd_new;

	spin_lock(&dentry->d_lock);

	rd = rfs_dentry_find(dentry);

	/*
	 * Workaround for the isofs_lookup function. It assigns
	 * dentry operations for the new dentry from the root dentry.
	 * This leads to the situation when one rdentry object can be
	 * found for more dentry objects.
	 *
	 * isofs_lookup: dentry->d_op = dir->i_sb->s_root->d_op;
	 */
	if (rd && rd->dentry != dentry) {
		rd_new->op_old = rd->op_old;
		rfs_dentry_put(rd);
		rd = NULL;
	}

	if (!rd) {
		rcu_assign_pointer(dentry->d_op, &rd_new->op_new);
		rfs_dentry_get(rd_new);
		rd = rfs_dentry_get(rd_new);
	}

	spin_unlock(&dentry->d_lock);

	rfs_dentry_put(rd_new);

	return rd;
}

static void rfs_dentry_del_rcu(struct rcu_head *head)
{
	struct rfs_dentry *rdentry;

	rdentry = container_of(head, struct rfs_dentry, rcu);
	rfs_dentry_put(rdentry);
}

void rfs_dentry_del(struct dentry *dentry)
{
	struct rfs_dentry *rdentry;
	
	spin_lock(&dentry->d_lock);

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry) {
		spin_unlock(&dentry->d_lock);
		return;
	}

	rcu_assign_pointer(dentry->d_op, rdentry->op_old);

	spin_unlock(&dentry->d_lock);

	call_rcu(&rdentry->rcu, rfs_dentry_del_rcu);

	rfs_dentry_put(rdentry);
}

int rfs_dentry_add_rinode(struct rfs_dentry *rdentry)
{
	struct rfs_inode *rinode;

	if (!rdentry->dentry->d_inode)
		return 0;

	spin_lock(&rdentry->lock);
	if (rdentry->rinode) {
		spin_unlock(&rdentry->lock);
		return 0;
	}
	spin_unlock(&rdentry->lock);

	rinode = rfs_inode_add(rdentry->dentry->d_inode);
	if (IS_ERR(rinode))
		return PTR_ERR(rinode);

	spin_lock(&rdentry->lock);
	if (rdentry->rinode) {
		spin_unlock(&rdentry->lock);
		rfs_inode_del(rdentry->dentry->d_inode);
		rfs_inode_put(rinode);
		return 0;
	}

	rdentry->rinode = rfs_inode_get(rinode);
	spin_unlock(&rdentry->lock);

	rfs_inode_add_rdentry(rinode, rdentry);
	rfs_inode_put(rinode);
	return 0;
}

void rfs_dentry_rem_rinode(struct rfs_dentry *rdentry, struct inode *inode)
{
	struct rfs_inode *rinode;

	spin_lock(&rdentry->lock);
	rinode = rdentry->rinode;
	if (!rinode) {
		spin_unlock(&rdentry->lock);
		return;
	}
	rdentry->rinode = NULL;
	spin_unlock(&rdentry->lock);

	rfs_inode_del(inode);
	rfs_inode_rem_rdentry(rinode, rdentry);
	rfs_inode_put(rinode);
}

struct rfs_info *rfs_dentry_get_rinfo(struct rfs_dentry *rdentry)
{
	struct rfs_info *rinfo;

	spin_lock(&rdentry->lock);
	rinfo = rfs_info_get(rdentry->rinfo);
	spin_unlock(&rdentry->lock);

	return rinfo;
}

void rfs_dentry_set_rinfo(struct rfs_dentry *rdentry, struct rfs_info *rinfo)
{
	spin_lock(&rdentry->lock);
	rfs_info_put(rdentry->rinfo);
	rdentry->rinfo = rfs_info_get(rinfo);
	spin_unlock(&rdentry->lock);
}

void rfs_dentry_add_rfile(struct rfs_dentry *rdentry, struct rfs_file *rfile)
{
	list_add_tail(&rdentry->rfiles, &rfile->rdentry_list);
	rfs_file_get(rfile);
}

void rfs_dentry_rem_rfile(struct rfs_file *rfile)
{
	list_del_init(&rfile->rdentry_list);
	rfs_file_put(rfile);
}

void rfs_dentry_rem_rfiles(struct rfs_dentry *rdentry)
{
	struct rfs_file *rfile;
	struct rfs_file *tmp;

	spin_lock(&rdentry->lock);

	list_for_each_entry_safe(rfile, tmp, &rdentry->rfiles, rdentry_list) {
		rfs_file_del(rfile->file);
	}

	spin_unlock(&rdentry->lock);
}

int rfs_dentry_cache_create(void)
{
	rfs_dentry_cache = kmem_cache_create("rfs_dentry_cache",
			sizeof(struct rfs_dentry), 0,
			SLAB_RECLAIM_ACCOUNT, NULL);

	if (!rfs_dentry_cache)
		return -ENOMEM;

	return 0;
}

void rfs_dentry_cache_destory(void)
{
	kmem_cache_destroy(rfs_dentry_cache);
}

void rfs_d_iput(struct dentry *dentry, struct inode *inode)
{
	struct rfs_dentry *rdentry;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_iput)
			dentry->d_op->d_iput(dentry, inode);
		return;
	}

	rinfo = rfs_dentry_get_rinfo(rdentry);
	rfs_context_init(&rcont, 0);

	if (S_ISREG(inode->i_mode))
		rargs.type.id = REDIRFS_REG_DOP_D_IPUT;
	else if (S_ISDIR(inode->i_mode))
		rargs.type.id = REDIRFS_DIR_DOP_D_IPUT;
	else if (S_ISLNK(inode->i_mode))
		rargs.type.id = REDIRFS_LNK_DOP_D_IPUT;
	else if (S_ISCHR(inode->i_mode))
		rargs.type.id = REDIRFS_CHR_DOP_D_IPUT;
	else if (S_ISBLK(inode->i_mode))
		rargs.type.id = REDIRFS_BLK_DOP_D_IPUT;
	else if (S_ISFIFO(inode->i_mode))
		rargs.type.id = REDIRFS_FIFO_DOP_D_IPUT;
	else
		rargs.type.id = REDIRFS_SOCK_DOP_D_IPUT;

	rargs.args.d_iput.dentry = dentry;
	rargs.args.d_iput.inode = inode;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rdentry->op_old && rdentry->op_old->d_iput)
			rdentry->op_old->d_iput(rargs.args.d_iput.dentry,
					rargs.args.d_iput.inode);
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	BUG_ON(rfs_dcache_rdentry_del(dentry, inode));

	rfs_dentry_put(rdentry);
	rfs_info_put(rinfo);
}

void rfs_d_release(struct dentry *dentry)
{
	struct rfs_dentry *rdentry;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;

	rdentry = rfs_dentry_find(dentry);
	if (!rdentry) {
		if (dentry->d_op && dentry->d_op->d_release)
			dentry->d_op->d_release(dentry);
		return;
	}

	rinfo = rfs_dentry_get_rinfo(rdentry);
	rfs_context_init(&rcont, 0);
	rargs.type.id = REDIRFS_NONE_DOP_D_RELEASE;
	rargs.args.d_release.dentry = dentry;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rdentry->op_old && rdentry->op_old->d_release)
			rdentry->op_old->d_release(rargs.args.d_release.dentry);
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_dentry_del(dentry);
	rfs_dentry_put(rdentry);
	rfs_info_put(rinfo);
}

static void rfs_dentry_set_ops_none(struct rfs_dentry *rdentry)
{
}

static void rfs_dentry_set_ops_reg(struct rfs_dentry *rdentry)
{
}

static void rfs_dentry_set_ops_dir(struct rfs_dentry *rdentry)
{
}

static void rfs_dentry_set_ops_lnk(struct rfs_dentry *rdentry)
{
}

static void rfs_dentry_set_ops_chr(struct rfs_dentry *rdentry)
{
}

static void rfs_dentry_set_ops_blk(struct rfs_dentry *rdentry)
{
}

static void rfs_dentry_set_ops_fifo(struct rfs_dentry *rdentry)
{
}

static void rfs_dentry_set_ops_sock(struct rfs_dentry *rdentry)
{
}

void rfs_dentry_set_ops(struct rfs_dentry *rdentry)
{
	struct rfs_file *rfile;
	struct rfs_inode *rinode;
	umode_t mode;

	spin_lock(&rdentry->lock);

	if (!rdentry->rinode) {
		rfs_dentry_set_ops_none(rdentry);
		spin_unlock(&rdentry->lock);
		return;
	}

	list_for_each_entry(rfile, &rdentry->rfiles, rdentry_list) {
		rfs_file_set_ops(rfile);
	}

	mode = rdentry->rinode->inode->i_mode;

	if (S_ISREG(mode))
		rfs_dentry_set_ops_reg(rdentry);

	else if (S_ISDIR(mode))
		rfs_dentry_set_ops_dir(rdentry);

	else if (S_ISLNK(mode))
		rfs_dentry_set_ops_lnk(rdentry);

	else if (S_ISCHR(mode))
		rfs_dentry_set_ops_chr(rdentry);

	else if (S_ISBLK(mode))
		rfs_dentry_set_ops_blk(rdentry);

	else if (S_ISFIFO(mode))
		rfs_dentry_set_ops_fifo(rdentry);

	else if (S_ISSOCK(mode))
		rfs_dentry_set_ops_sock(rdentry);

	rinode = rfs_inode_get(rdentry->rinode);
	spin_unlock(&rdentry->lock);
	rfs_inode_set_ops(rinode);
	rfs_inode_put(rinode);
}

