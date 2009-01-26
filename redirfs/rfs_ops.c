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

struct rfs_ops *rfs_ops_alloc(void)
{
	struct rfs_ops *rops;
	char *arr;

	rops = kzalloc(sizeof(struct rfs_ops), GFP_KERNEL);
	arr = kzalloc(sizeof(char) * REDIRFS_OP_END, GFP_KERNEL);

	if (!rops || !arr) {
		kfree(rops);
		kfree(arr);
		return ERR_PTR(-ENOMEM);
	}

	rops->arr = arr;
	atomic_set(&rops->count, 1);

	return rops;
}

struct rfs_ops *rfs_ops_get(struct rfs_ops *rops)
{
	if (!rops || IS_ERR(rops))
		return NULL;

	BUG_ON(!atomic_read(&rops->count));
	atomic_inc(&rops->count);
	return rops;
}

void rfs_ops_put(struct rfs_ops *rops)
{
	if (!rops || IS_ERR(rops))
		return;

	BUG_ON(!atomic_read(&rops->count));
	if (!atomic_dec_and_test(&rops->count))
		return;

	kfree(rops->arr);
	kfree(rops);
}

static int rfs_ops_is_none(struct rfs_ops *rops)
{
	if (rops->arr[REDIRFS_NONE_DOP_D_COMPARE])
		return 1;

	if (rops->arr[REDIRFS_NONE_DOP_D_RELEASE])
		return 1;

	if (rops->arr[REDIRFS_NONE_DOP_D_IPUT])
		return 1;

	return 0;
}

static int rfs_ops_is_reg(struct rfs_ops *rops)
{
	if (rops->arr[REDIRFS_REG_DOP_D_COMPARE])
		return 1;

	if (rops->arr[REDIRFS_REG_DOP_D_RELEASE])
		return 1;

	if (rops->arr[REDIRFS_REG_DOP_D_IPUT])
		return 1;

	if (rops->arr[REDIRFS_REG_IOP_PERMISSION])
		return 1;

	if (rops->arr[REDIRFS_REG_FOP_OPEN])
		return 1;

	if (rops->arr[REDIRFS_REG_FOP_RELEASE])
		return 1;

	return 0;
}

static int rfs_ops_is_chr(struct rfs_ops *rops)
{
	if (rops->arr[REDIRFS_CHR_DOP_D_COMPARE])
		return 1;

	if (rops->arr[REDIRFS_CHR_DOP_D_RELEASE])
		return 1;

	if (rops->arr[REDIRFS_CHR_DOP_D_IPUT])
		return 1;

	if (rops->arr[REDIRFS_CHR_IOP_PERMISSION])
		return 1;

	if (rops->arr[REDIRFS_CHR_FOP_OPEN])
		return 1;

	if (rops->arr[REDIRFS_CHR_FOP_RELEASE])
		return 1;

	return 0;
}

static int rfs_ops_is_blk(struct rfs_ops *rops)
{
	if (rops->arr[REDIRFS_BLK_DOP_D_COMPARE])
		return 1;

	if (rops->arr[REDIRFS_BLK_DOP_D_RELEASE])
		return 1;

	if (rops->arr[REDIRFS_BLK_DOP_D_IPUT])
		return 1;

	if (rops->arr[REDIRFS_BLK_IOP_PERMISSION])
		return 1;

	if (rops->arr[REDIRFS_BLK_FOP_OPEN])
		return 1;

	if (rops->arr[REDIRFS_BLK_FOP_RELEASE])
		return 1;

	return 0;
}

static int rfs_ops_is_fifo(struct rfs_ops *rops)
{
	if (rops->arr[REDIRFS_FIFO_DOP_D_COMPARE])
		return 1;

	if (rops->arr[REDIRFS_FIFO_DOP_D_RELEASE])
		return 1;

	if (rops->arr[REDIRFS_FIFO_DOP_D_IPUT])
		return 1;

	if (rops->arr[REDIRFS_FIFO_IOP_PERMISSION])
		return 1;

	if (rops->arr[REDIRFS_FIFO_FOP_OPEN])
		return 1;

	if (rops->arr[REDIRFS_FIFO_FOP_RELEASE])
		return 1;

	return 0;
}

static int rfs_ops_is_lnk(struct rfs_ops *rops)
{
	if (rops->arr[REDIRFS_LNK_DOP_D_COMPARE])
		return 1;

	if (rops->arr[REDIRFS_LNK_DOP_D_RELEASE])
		return 1;

	if (rops->arr[REDIRFS_LNK_DOP_D_IPUT])
		return 1;

	if (rops->arr[REDIRFS_LNK_IOP_PERMISSION])
		return 1;

	if (rops->arr[REDIRFS_LNK_FOP_OPEN])
		return 1;

	if (rops->arr[REDIRFS_LNK_FOP_RELEASE])
		return 1;

	return 0;
}

static int rfs_ops_is_sock(struct rfs_ops *rops)
{
	if (rops->arr[REDIRFS_LNK_DOP_D_COMPARE])
		return 1;

	if (rops->arr[REDIRFS_LNK_DOP_D_RELEASE])
		return 1;

	if (rops->arr[REDIRFS_LNK_DOP_D_IPUT])
		return 1;

	if (rops->arr[REDIRFS_LNK_IOP_PERMISSION])
		return 1;

	return 0;
}

void rfs_ops_set_types(struct rfs_ops *rops)
{
	rops->flags = 0;

	if (rfs_ops_is_none(rops))
		rops->flags |= RFS_NONE_OPS;

	if (rfs_ops_is_reg(rops))
		rops->flags |= RFS_REG_OPS;

	if (rfs_ops_is_chr(rops))
		rops->flags |= RFS_CHR_OPS;

	if (rfs_ops_is_blk(rops))
		rops->flags |= RFS_BLK_OPS;

	if (rfs_ops_is_fifo(rops))
		rops->flags |= RFS_FIFO_OPS;

	if (rfs_ops_is_lnk(rops))
		rops->flags |= RFS_LNK_OPS;

	if (rfs_ops_is_sock(rops))
		rops->flags |= RFS_SOCK_OPS;
}

