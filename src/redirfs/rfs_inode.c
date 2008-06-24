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

static struct kmem_cache *rfs_inode_cache = NULL;
atomic_t rfs_inode_cnt = ATOMIC_INIT(0);
DECLARE_WAIT_QUEUE_HEAD(rfs_inode_wait);

struct dentry *rfs_lookup(struct inode *dir,struct dentry *dentry,
		struct nameidata *nd);

static struct rfs_inode *rfs_inode_alloc(struct inode *inode)
{
	struct rfs_inode *rinode;

	rinode = kmem_cache_alloc(rfs_inode_cache, GFP_KERNEL);
	if (IS_ERR(rinode))
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&rinode->rdentries);
	INIT_RCU_HEAD(&rinode->rcu);
	rinode->inode = inode;
	rinode->op_old = inode->i_op;
	rinode->fop_old = inode->i_fop;
	rinode->aop_old = inode->i_mapping->a_ops;
	rinode->rinfo = NULL;
	spin_lock_init(&rinode->lock);
	atomic_set(&rinode->count, 1);
	rinode->nlink = 1;
	rinode->rdentries_nr = 0;

	if (inode->i_op)
		memcpy(&rinode->op_new, inode->i_op,
				sizeof(struct inode_operations));
	else
		memset(&rinode->op_new, 0,
				sizeof(struct inode_operations));

	if (inode->i_mapping->a_ops)
		memcpy(&rinode->aop_new, inode->i_mapping->a_ops,
				sizeof(struct address_space_operations));
	else
		memset(&rinode->aop_new, 0,
				sizeof(struct address_space_operations));

	rinode->op_new.lookup = rfs_lookup;
	atomic_inc(&rfs_inode_cnt);

	return rinode;
}

struct rfs_inode *rfs_inode_get(struct rfs_inode *rinode)
{
	if (!rinode || IS_ERR(rinode))
		return NULL;

	BUG_ON(!atomic_read(&rinode->count));
	atomic_inc(&rinode->count);

	return rinode;
}

void rfs_inode_put(struct rfs_inode *rinode)
{
	if (!rinode || IS_ERR(rinode))
		return;

	BUG_ON(!atomic_read(&rinode->count));
	if (!atomic_dec_and_test(&rinode->count))
		return;

	rfs_info_put(rinode->rinfo);

	kmem_cache_free(rfs_inode_cache, rinode);

	if (atomic_dec_and_test(&rfs_inode_cnt))
		wake_up_interruptible(&rfs_inode_wait);
}

struct rfs_inode *rfs_inode_find(struct inode *inode)
{
	struct rfs_inode *rinode = NULL;
	const struct inode_operations *i_op;

	rcu_read_lock();
	i_op = rcu_dereference(inode->i_op);
	if (!i_op)
		goto exit;

	if (i_op->lookup != rfs_lookup)
		goto exit;

	rinode = container_of(i_op, struct rfs_inode, op_new);
	rinode = rfs_inode_get(rinode);
exit:
	rcu_read_unlock();
	return rinode;
}

struct rfs_inode *rfs_inode_add(struct inode *inode)
{
	struct rfs_inode *ri_new;
	struct rfs_inode *ri;

	if (!inode)
		return NULL;

	ri_new = rfs_inode_alloc(inode);
	if (IS_ERR(ri_new))
		return ri_new;

	spin_lock(&inode->i_lock);

	ri = rfs_inode_find(inode);
	if (!ri) {
		if (!S_ISSOCK(inode->i_mode))
			inode->i_fop = &rfs_file_ops;

		if (S_ISREG(inode->i_mode))
			inode->i_mapping->a_ops = &ri_new->aop_new;

		rcu_assign_pointer(inode->i_op, &ri_new->op_new);
		rfs_inode_get(ri_new);
		ri = rfs_inode_get(ri_new);
	} else
		ri->nlink++;

	spin_unlock(&inode->i_lock);

	rfs_inode_put(ri_new);

	return ri;
}

static void rfs_inode_del_rcu(struct rcu_head *head)
{
	struct rfs_inode *rinode;

	rinode = container_of(head, struct rfs_inode, rcu);
	rfs_inode_put(rinode);
}

void rfs_inode_del(struct inode *inode)
{
	struct rfs_inode *rinode;

	if (!inode)
		return;

	spin_lock(&inode->i_lock);

	rinode = rfs_inode_find(inode);
	if (!rinode) {
		spin_unlock(&inode->i_lock);
		return;
	}

	if (--rinode->nlink) {
		spin_unlock(&inode->i_lock);
		rfs_inode_put(rinode);
		return;
	}

	if (!S_ISSOCK(inode->i_mode))
		inode->i_fop = rinode->fop_old;

	if (S_ISREG(inode->i_mode))
		inode->i_mapping->a_ops = rinode->aop_old;

	rcu_assign_pointer(inode->i_op, rinode->op_old);
	spin_unlock(&inode->i_lock);
	call_rcu(&rinode->rcu, rfs_inode_del_rcu);
	rfs_inode_put(rinode);
}

void rfs_inode_add_rdentry(struct rfs_inode *rinode, struct rfs_dentry *rdentry)
{
	spin_lock(&rinode->lock);
	rinode->rdentries_nr++;
	list_add_tail(&rdentry->rinode_list, &rinode->rdentries);
	spin_unlock(&rinode->lock);
	rfs_dentry_get(rdentry);
}

void rfs_inode_rem_rdentry(struct rfs_inode *rinode, struct rfs_dentry *rdentry)
{
	spin_lock(&rinode->lock);
	rinode->rdentries_nr--;
	list_del_init(&rdentry->rinode_list);
	spin_unlock(&rinode->lock);
	rfs_dentry_put(rdentry);
}

static struct rfs_chain *rfs_inode_join_rchains(struct rfs_inode *rinode)
{
	struct rfs_dentry *rdentry = NULL;
	struct rfs_info *rinfo = NULL;
	struct rfs_chain *rchain = NULL;
	struct rfs_chain *rchain_old = NULL;

	list_for_each_entry(rdentry, &rinode->rdentries, rinode_list) {
		spin_lock(&rdentry->lock);
		rinfo = rfs_info_get(rdentry->rinfo);
		spin_unlock(&rdentry->lock);

		rchain = rfs_chain_join(rinfo->rchain, rchain_old);

		rfs_info_put(rinfo);
		rfs_chain_put(rchain_old);

		if (IS_ERR(rchain))
			return rchain;

		rchain_old = rchain;
	}

	return rchain;
}

static int rfs_inode_set_rinfo_fast(struct rfs_inode *rinode)
{
	struct rfs_dentry *rdentry;

	if (!rinode->rdentries_nr)
		return 0;

	if (rinode->rdentries_nr > 1)
		return -1;

	rdentry = list_entry(rinode->rdentries.next, struct rfs_dentry, rinode_list);

	spin_lock(&rdentry->lock);
	rfs_info_put(rinode->rinfo);
	rinode->rinfo = rfs_info_get(rdentry->rinfo);
	spin_unlock(&rdentry->lock);

	return 0;
}

struct rfs_info *rfs_inode_get_rinfo(struct rfs_inode *rinode)
{
	struct rfs_info *rinfo;

	spin_lock(&rinode->lock);
	rinfo = rfs_info_get(rinode->rinfo);
	spin_unlock(&rinode->lock);

	return rinfo;
}

int rfs_inode_set_rinfo(struct rfs_inode *rinode)
{
	struct rfs_chain *rchain;
	struct rfs_info *rinfo;
	struct rfs_ops *rops;
	int rv;

	if (!rinode)
		return 0;

	spin_lock(&rinode->lock);
	rv = rfs_inode_set_rinfo_fast(rinode);
	spin_unlock(&rinode->lock);
	if (!rv)
		return 0;

	rinfo = rfs_info_alloc(NULL, NULL);
	if (IS_ERR(rinfo))
		return PTR_ERR(rinfo);

	rops = rfs_ops_alloc();
	if (IS_ERR(rops)) {
		rfs_info_put(rinfo);
		return PTR_ERR(rops);
	}

	rinfo->rops = rops;

	spin_lock(&rinode->lock);
	rv = rfs_inode_set_rinfo_fast(rinode);
	if (!rv) {
		spin_unlock(&rinode->lock);
		rfs_info_put(rinfo);
		return 0;
	}

	rchain = rfs_inode_join_rchains(rinode);
	if (IS_ERR(rchain)) {
		spin_unlock(&rinode->lock);
		rfs_info_put(rinfo);
		return PTR_ERR(rchain);
	}

	rinfo->rchain = rchain;
	rfs_chain_ops(rinfo->rchain, rinfo->rops);
	rfs_info_put(rinode->rinfo);
	rinode->rinfo = rinfo;
	spin_unlock(&rinode->lock);

	return 0;
}

int rfs_inode_cache_create(void)
{
	rfs_inode_cache = kmem_cache_create("rfs_inode_cache",
			sizeof(struct rfs_inode), 0,
			SLAB_RECLAIM_ACCOUNT, NULL);

	if (!rfs_inode_cache)
		return -ENOMEM;

	return 0;
}

void rfs_inode_cache_destroy(void)
{
	kmem_cache_destroy(rfs_inode_cache);
}

struct dentry *rfs_lookup(struct inode *dir, struct dentry *dentry,
		struct nameidata *nd)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;
	struct dentry *dadd = dentry;

	rinode = rfs_inode_find(dir);
	if (!rinode) {
		if (dir->i_op && dir->i_op->lookup)
			return dir->i_op->lookup(dir, dentry, nd);

		return ERR_PTR(-ENOSYS);
	}

	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	if (S_ISDIR(dir->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_LOOKUP;
	else
		BUG();

	rargs.args.i_lookup.dir = dir;
	rargs.args.i_lookup.dentry = dentry;
	rargs.args.i_lookup.nd = nd;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->lookup)
			rargs.rv.rv_dentry = rinode->op_old->lookup(
					rargs.args.i_lookup.dir,
					rargs.args.i_lookup.dentry,
					rargs.args.i_lookup.nd);
		else
			rargs.rv.rv_dentry = ERR_PTR(-ENOSYS);
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	if (IS_ERR(rargs.rv.rv_dentry))
		goto exit;

	if (rargs.rv.rv_dentry)
		dadd = rargs.rv.rv_dentry;

	if (rfs_dcache_rdentry_add(dadd, rinfo))
		BUG();
exit:
	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_dentry;
}


int rfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;

	rinode = rfs_inode_find(dir);
	if (!rinode) {
		if (dir->i_op && dir->i_op->mkdir)
			return dir->i_op->mkdir(dir, dentry, mode);

		return -ENOSYS;
	}

	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	if (S_ISDIR(dir->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_MKDIR;
	else
		BUG();

	rargs.args.i_mkdir.dir = dir;
	rargs.args.i_mkdir.dentry = dentry;
	rargs.args.i_mkdir.mode = mode;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->mkdir)
			rargs.rv.rv_int = rinode->op_old->mkdir(
					rargs.args.i_mkdir.dir,
					rargs.args.i_mkdir.dentry,
					rargs.args.i_mkdir.mode);
		else
			rargs.rv.rv_int = -ENOSYS;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	if (!rargs.rv.rv_int) {
		if (rfs_dcache_rdentry_add(dentry, rinfo))
			BUG();
	}

	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

int rfs_create(struct inode *dir, struct dentry *dentry, int mode,
		struct nameidata *nd)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;

	rinode = rfs_inode_find(dir);
	if (!rinode) {
		if (dir->i_op && dir->i_op->create)
			return dir->i_op->create(dir, dentry, mode, nd);

		return -ENOSYS;
	}

	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	if (S_ISDIR(dir->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_CREATE;
	else
		BUG();

	rargs.args.i_create.dir = dir;
	rargs.args.i_create.dentry = dentry;
	rargs.args.i_create.mode = mode;
	rargs.args.i_create.nd = nd;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->create)
			rargs.rv.rv_int = rinode->op_old->create(
					rargs.args.i_create.dir,
					rargs.args.i_create.dentry,
					rargs.args.i_create.mode,
					rargs.args.i_create.nd);
		else
			rargs.rv.rv_int = -ENOSYS;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	if (!rargs.rv.rv_int) {
		if (rfs_dcache_rdentry_add(dentry, rinfo))
			BUG();
	}

	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

int rfs_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *dentry)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;

	rinode = rfs_inode_find(dir);
	if (!rinode) {
		if (dir->i_op && dir->i_op->link)
			return dir->i_op->link(old_dentry, dir, dentry);

		return -ENOSYS;
	}

	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	if (S_ISDIR(dir->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_LINK;
	else
		BUG();

	rargs.args.i_link.old_dentry = old_dentry;
	rargs.args.i_link.dir = dir;
	rargs.args.i_link.dentry = dentry;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->link)
			rargs.rv.rv_int = rinode->op_old->link(
					rargs.args.i_link.old_dentry,
					rargs.args.i_link.dir,
					rargs.args.i_link.dentry);
		else
			rargs.rv.rv_int = -ENOSYS;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	if (!rargs.rv.rv_int) {
		if (rfs_dcache_rdentry_add(dentry, rinfo))
			BUG();
	}

	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

int rfs_symlink(struct inode *dir, struct dentry *dentry, const char *oldname)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;

	rinode = rfs_inode_find(dir);
	if (!rinode) {
		if (dir->i_op && dir->i_op->symlink)
			return dir->i_op->symlink(dir, dentry, oldname);

		return -ENOSYS;
	}

	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	if (S_ISDIR(dir->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_LINK;
	else
		BUG();

	rargs.args.i_symlink.dir = dir;
	rargs.args.i_symlink.dentry = dentry;
	rargs.args.i_symlink.oldname = oldname;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->symlink)
			rargs.rv.rv_int = rinode->op_old->symlink(
					rargs.args.i_symlink.dir,
					rargs.args.i_symlink.dentry,
					rargs.args.i_symlink.oldname);
		else
			rargs.rv.rv_int = -ENOSYS;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	if (!rargs.rv.rv_int) {
		if (rfs_dcache_rdentry_add(dentry, rinfo))
			BUG();
	}

	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

int rfs_mknod(struct inode * dir, struct dentry *dentry, int mode, dev_t rdev)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;

	rinode = rfs_inode_find(dir);
	if (!rinode) {
		if (dir->i_op && dir->i_op->mknod)
			return dir->i_op->mknod(dir, dentry, mode, rdev);

		return -ENOSYS;
	}

	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	if (S_ISDIR(dir->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_LINK;
	else
		BUG();

	rargs.args.i_mknod.dir = dir;
	rargs.args.i_mknod.dentry = dentry;
	rargs.args.i_mknod.mode = mode;
	rargs.args.i_mknod.rdev = rdev;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->mknod)
			rargs.rv.rv_int = rinode->op_old->mknod(
					rargs.args.i_mknod.dir,
					rargs.args.i_mknod.dentry,
					rargs.args.i_mknod.mode,
					rargs.args.i_mknod.rdev);
		else
			rargs.rv.rv_int = -ENOSYS;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	if (!rargs.rv.rv_int) {
		if (rfs_dcache_rdentry_add(dentry, rinfo))
			BUG();
	}

	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

static void rfs_inode_set_ops_reg(struct rfs_inode *rinode)
{
}

static void rfs_inode_set_ops_dir(struct rfs_inode *rinode)
{
	rinode->op_new.mkdir = rfs_mkdir;
	rinode->op_new.create = rfs_create;
	rinode->op_new.link = rfs_link;
	rinode->op_new.mknod = rfs_mknod;
	rinode->op_new.symlink = rfs_symlink;
}

static void rfs_inode_set_ops_lnk(struct rfs_inode *rinode)
{
}

static void rfs_inode_set_ops_chr(struct rfs_inode *rinode)
{
}

static void rfs_inode_set_ops_blk(struct rfs_inode *rinode)
{
}

static void rfs_inode_set_ops_fifo(struct rfs_inode *rinode)
{
}

static void rfs_inode_set_ops_sock(struct rfs_inode *rinode)
{
}

static void rfs_inode_set_aops_reg(struct rfs_inode *rinode)
{
}

void rfs_inode_set_ops(struct rfs_inode *rinode)
{
	umode_t mode = rinode->inode->i_mode;

	spin_lock(&rinode->lock);

	if (S_ISREG(mode)) {
		rfs_inode_set_ops_reg(rinode);
		rfs_inode_set_aops_reg(rinode);

	} else if (S_ISDIR(mode))
		rfs_inode_set_ops_dir(rinode);

	else if (S_ISLNK(mode))
		rfs_inode_set_ops_lnk(rinode);

	else if (S_ISCHR(mode))
		rfs_inode_set_ops_chr(rinode);

	else if (S_ISBLK(mode))
		rfs_inode_set_ops_blk(rinode);

	else if (S_ISFIFO(mode))
		rfs_inode_set_ops_fifo(rinode);

	else if (S_ISSOCK(mode))
		rfs_inode_set_ops_sock(rinode);

	spin_unlock(&rinode->lock);
}

