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

int rfs_precall_flts(struct rfs_chain *rchain, struct rfs_context *rcont,
		struct redirfs_args *rargs)
{
	enum redirfs_rv (*rop)(redirfs_context, struct redirfs_args *);
	enum redirfs_rv rv;

	if (!rchain)
		return 0;

	rargs->type.call = REDIRFS_PRECALL;

	rcont->idx = rcont->idx_start;

	for (; rcont->idx < rchain->rflts_nr; rcont->idx++) {
		if (!atomic_read(&rchain->rflts[rcont->idx]->active))
			continue;

		rop = rchain->rflts[rcont->idx]->cbs[rargs->type.id].pre_cb;
		if (!rop)
			continue;

		rv = rop(rcont, rargs);
		if (rv == REDIRFS_STOP)
			return -1;
	}

	rcont->idx--;

	return 0;
}

void rfs_postcall_flts(struct rfs_chain *rchain, struct rfs_context *rcont,
		struct redirfs_args *rargs)
{
	enum redirfs_rv (*rop)(redirfs_context, struct redirfs_args *);

	if (!rchain)
		return;

	rargs->type.call = REDIRFS_POSTCALL;

	for (; rcont->idx >= rcont->idx_start; rcont->idx--) {

		rop = rchain->rflts[rcont->idx]->cbs[rargs->type.id].post_cb;
		if (rop) 
			rop(rcont, rargs);
	}

	rcont->idx++;
}

static int __init rfs_init(void)
{
	int rv;

	rv = rfs_dentry_cache_create();
	if (rv)
		return rv;

	rv = rfs_inode_cache_create();
	if (rv)
		goto err_inode_cache;

	rv = rfs_file_cache_create();
	if (rv)
		goto err_file_cache;

	rv = rfs_sysfs_create();
	if (rv)
		goto err_sysfs;

	printk(KERN_INFO "Redirecting File System Framework Version "
			REDIRFS_VERSION " <www.redirfs.org>\n");


	return 0;

err_sysfs:
	rfs_file_cache_destory();
err_file_cache:
	rfs_inode_cache_destroy();
err_inode_cache:
	rfs_dentry_cache_destory();
	return rv;
}

static void __exit rfs_exit(void)
{
	wait_event_interruptible(rfs_file_wait, !atomic_read(&rfs_file_cnt));
	rfs_file_cache_destory();
	wait_event_interruptible(rfs_inode_wait, !atomic_read(&rfs_inode_cnt));
	rfs_inode_cache_destroy();
	wait_event_interruptible(rfs_dentry_wait, !atomic_read(&rfs_dentry_cnt));
	rfs_dentry_cache_destory();

	rfs_sysfs_destroy();
}

module_init(rfs_init);
module_exit(rfs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frantisek Hrbata <frantisek.hrbata@redirfs.org>");
MODULE_DESCRIPTION("Redirecting File System Framework Version "
		REDIRFS_VERSION " <www.redirfs.org>");

