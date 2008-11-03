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

#include "avflt.h"

static struct kmem_cache *avflt_data_cache = NULL;

static void avflt_data_free(struct redirfs_data *rfs_data)
{
	struct avflt_data *data = rfs_to_avflt_data(rfs_data);

	kmem_cache_free(avflt_data_cache, data);
}

static struct avflt_data *avflt_data_alloc(void)
{
	struct avflt_data *data;
	int err;

	data = kmem_cache_zalloc(avflt_data_cache, GFP_KERNEL);
	if (!data)
		return ERR_PTR(-ENOMEM);

	err = redirfs_init_data(&data->rfs_data, avflt, avflt_data_free);
	if (err) {
		 kmem_cache_free(avflt_data_cache, data);
		 return ERR_PTR(err);
	}

	atomic_set(&data->state, 0);

	return data;
}

struct avflt_data *avflt_get_data(struct inode *inode)
{
	struct redirfs_data *rfs_data;

	rfs_data = redirfs_get_data_inode(avflt, inode);
	if (!rfs_data)
		return NULL;

	if (IS_ERR(rfs_data))
		return ERR_PTR(PTR_ERR(rfs_data));

	return rfs_to_avflt_data(rfs_data);
}

void avflt_put_data(struct avflt_data *data)
{
	redirfs_put_data(&data->rfs_data);
}

struct avflt_data *avflt_attach_data(struct inode *inode)
{
	struct avflt_data *data;
	struct redirfs_data *data_exist;
	int err;

	data = avflt_get_data(inode);
	if (!IS_ERR(data))
		return data;

	if (data)
		return data;

	data = avflt_data_alloc();
	if (IS_ERR(data)) 
		return data;

	err = redirfs_attach_data_inode(avflt, inode, &data->rfs_data,
			&data_exist);
	if (!err)
		return data;

	if (err == -EEXIST) {
		avflt_put_data(data);
		return rfs_to_avflt_data(data_exist);
	}

	avflt_put_data(data);
	return ERR_PTR(err);
}

int avflt_data_cache_init(void)
{
	avflt_data_cache = kmem_cache_create("avflt_data_cache",
			sizeof(struct avflt_data),
			0, SLAB_RECLAIM_ACCOUNT, NULL);

	if (!avflt_data_cache)
		return -ENOMEM;

	return 0;
}

void avflt_data_cache_exit(void)
{
	kmem_cache_destroy(avflt_data_cache);
}


