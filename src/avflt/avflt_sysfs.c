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

atomic_t avflt_reply_timeout = ATOMIC_INIT(0);
atomic_t avflt_cache_enabled = ATOMIC_INIT(1);

static ssize_t avflt_timeout_show(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d",
			atomic_read(&avflt_reply_timeout));
}

static ssize_t avflt_timeout_store(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, const char *buf,
		size_t count)
{
	int timeout;

	if (sscanf(buf, "%d", &timeout) != 1)
		return -EINVAL;

	if (timeout < 0)
		return -EINVAL;

	atomic_set(&avflt_reply_timeout, timeout);

	return count;
}

static ssize_t avflt_cache_show(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d",
			atomic_read(&avflt_cache_enabled));
}

static ssize_t avflt_cache_store(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, const char *buf,
		size_t count)
{
	int cache;

	if (sscanf(buf, "%d", &cache) != 1)
		return -EINVAL;

	if (cache) {
		atomic_set(&avflt_cache_enabled, 1);
		return count;
	}

	atomic_set(&avflt_cache_enabled, 0);
	avflt_invalidate_cache();

	return count;
}

static ssize_t avflt_pathcache_show(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, char *buf)
{
	return 0;
}

static ssize_t avflt_pathcache_store(redirfs_filter filter,
		struct redirfs_filter_attribute *attr, const char *buf,
		size_t count)
{
	return count;
}

static struct redirfs_filter_attribute avflt_timeout_attr = 
	REDIRFS_FILTER_ATTRIBUTE(timeout, 0644, avflt_timeout_show,
			avflt_timeout_store);

static struct redirfs_filter_attribute avflt_cache_attr = 
	REDIRFS_FILTER_ATTRIBUTE(cache, 0644, avflt_cache_show,
			avflt_cache_store);

static struct redirfs_filter_attribute avflt_pathcache_attr = 
	REDIRFS_FILTER_ATTRIBUTE(pathcache, 0644, avflt_pathcache_show,
			avflt_pathcache_store);

int avflt_sys_init(void)
{
	int rv;

	rv = redirfs_create_attribute(avflt, &avflt_timeout_attr);
	if (rv)
		return rv;

	rv = redirfs_create_attribute(avflt, &avflt_cache_attr);
	if (rv) {
		redirfs_remove_attribute(avflt, &avflt_timeout_attr);
		return rv;
	}

	rv = redirfs_create_attribute(avflt, &avflt_pathcache_attr);
	if (rv) {
		redirfs_remove_attribute(avflt, &avflt_timeout_attr);
		redirfs_remove_attribute(avflt, &avflt_cache_attr);
		return rv;
	}

	return 0;
}

void avflt_sys_exit(void)
{
	redirfs_remove_attribute(avflt, &avflt_timeout_attr);
	redirfs_remove_attribute(avflt, &avflt_cache_attr);
	redirfs_remove_attribute(avflt, &avflt_pathcache_attr);
}

