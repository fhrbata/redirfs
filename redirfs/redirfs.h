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

#ifndef _REDIRFS_H
#define _REDIRFS_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/types.h>
#include <linux/aio.h>
#include <linux/version.h>

#define REDIRFS_VERSION "0.6"

#define REDIRFS_PATH_INCLUDE		1
#define REDIRFS_PATH_EXCLUDE		2

#define REDIRFS_FILTER_ATTRIBUTE(__name, __mode, __show, __store) \
	__ATTR(__name, __mode, __show, __store)

/**
 * enum redirfs_op_id - VFS operation identifier
 *
 * Values:
 *     Each value represents an operation from a VFS object operation set.
 *     They are defined using the pattern
 *     REDIRFS_<file type>_<operation set>_<operation>
 *
 *     <file type> can be either "REG", "DIR", "CHR", "BLK", "FIFO", "LNK" or
 *     "SOCK" for regular file, directory, character device, block device,
 *     symbolic link or unix socket respectively.
 *
 *     <operation set> can be either "DOP", "IOP", "FOP" or "AOP" for
 *     dentry, inode, file or address space object operation sets.
 *
 *     <operation> can by any operation from the appropriate operation set
 *     as defined by VFS.
 *
 *     For example the file object's open operation on regular files is
 *     defined as REDIRFS_REG_FOP_OPEN.
 **/
enum redirfs_op_id {
	/* REDIRFS_NONE_DOP_D_REVALIDATE, */
	/* REDIRFS_NONE_DOP_D_HASH, */
	REDIRFS_NONE_DOP_D_COMPARE,
	/* REDIRFS_NONE_DOP_D_DELETE, */
	REDIRFS_NONE_DOP_D_RELEASE,
	REDIRFS_NONE_DOP_D_IPUT,
	/* REDIRFS_NODE_DOP_D_NAME, */

	/* REDIRFS_REG_DOP_D_REVALIDATE, */
	/* REDIRFS_REG_DOP_D_HASH, */
	REDIRFS_REG_DOP_D_COMPARE,
	/* REDIRFS_REG_DOP_D_DELETE, */
	REDIRFS_REG_DOP_D_RELEASE,
	REDIRFS_REG_DOP_D_IPUT,
	/* REDIRFS_REG_DOP_D_NAME, */

	/* REDIRFS_DIR_DOP_D_REVALIDATE, */
	/* REDIRFS_DIR_DOP_D_HASH, */
	REDIRFS_DIR_DOP_D_COMPARE,
	/* REDIRFS_DIR_DOP_D_DELETE, */
	REDIRFS_DIR_DOP_D_RELEASE,
	REDIRFS_DIR_DOP_D_IPUT,
	/* REDIRFS_DIR_DOP_D_NAME, */

	/* REDIRFS_CHR_DOP_D_REVALIDATE, */
	/* REDIRFS_CHR_DOP_D_HASH, */
	REDIRFS_CHR_DOP_D_COMPARE,
	/* REDIRFS_CHR_DOP_D_DELETE, */
	REDIRFS_CHR_DOP_D_RELEASE,
	REDIRFS_CHR_DOP_D_IPUT,
	/* REDIRFS_CHR_DOP_D_NAME, */

	/* REDIRFS_BLK_DOP_D_REVALIDATE, */
	/* REDIRFS_BLK_DOP_D_HASH, */
	REDIRFS_BLK_DOP_D_COMPARE,
	/* REDIRFS_BLK_DOP_D_DELETE, */
	REDIRFS_BLK_DOP_D_RELEASE,
	REDIRFS_BLK_DOP_D_IPUT,
	/* REDIRFS_BLK_DOP_D_NAME, */

	/* REDIRFS_FIFO_DOP_D_REVALIDATE, */
	/* REDIRFS_FIFO_DOP_D_HASH, */
	REDIRFS_FIFO_DOP_D_COMPARE,
	/* REDIRFS_FIFO_DOP_D_DELETE, */
	REDIRFS_FIFO_DOP_D_RELEASE,
	REDIRFS_FIFO_DOP_D_IPUT,
	/* REDIRFS_FIFO_DOP_D_NAME, */

	/* REDIRFS_LNK_DOP_D_REVALIDATE, */
	/* REDIRFS_LNK_DOP_D_HASH, */
	REDIRFS_LNK_DOP_D_COMPARE,
	/* REDIRFS_LNK_DOP_D_DELETE, */
	REDIRFS_LNK_DOP_D_RELEASE,
	REDIRFS_LNK_DOP_D_IPUT,
	/* REDIRFS_LNK_DOP_D_NAME, */

	/* REDIRFS_SOCK_DOP_D_REVALIDATE, */
	/* REDIRFS_SOCK_DOP_D_HASH, */
	REDIRFS_SOCK_DOP_D_COMPARE,
	/* REDIRFS_SOCK_DOP_D_DELETE, */
	REDIRFS_SOCK_DOP_D_RELEASE,
	REDIRFS_SOCK_DOP_D_IPUT,
	/* REDIRFS_SOCK_DOP_D_NAME, */

	REDIRFS_REG_IOP_PERMISSION,
	/* REDIRFS_REG_IOP_SETATTR, */

	REDIRFS_DIR_IOP_CREATE,
	REDIRFS_DIR_IOP_LOOKUP,
	REDIRFS_DIR_IOP_LINK,
	/* REDIRFS_DIR_IOP_UNLINK, */
	REDIRFS_DIR_IOP_SYMLINK, 
	REDIRFS_DIR_IOP_MKDIR,
	/* REDIRFS_DIR_IOP_RMDIR, */
	REDIRFS_DIR_IOP_MKNOD,
	REDIRFS_DIR_IOP_RENAME,
	REDIRFS_DIR_IOP_PERMISSION,
	/* REDIRFS_DIR_IOP_SETATTR, */

	REDIRFS_CHR_IOP_PERMISSION,
	/* REDIRFS_CHR_IOP_SETATTR, */

	REDIRFS_BLK_IOP_PERMISSION,
	/* REDIRFS_BLK_IOP_SETATTR, */

	REDIRFS_FIFO_IOP_PERMISSION,
	/* REDIRFS_FIFO_IOP_SETATTR, */

	REDIRFS_LNK_IOP_PERMISSION,
	/* REDIRFS_LNK_IOP_SETATTR, */

	REDIRFS_SOCK_IOP_PERMISSION,
	/* REDIRFS_SOCK_IOP_SETATTR, */

	REDIRFS_REG_FOP_OPEN,
	REDIRFS_REG_FOP_RELEASE,
	/* REDIRFS_REG_FOP_LLSEEK, */
	/* REDIRFS_REG_FOP_READ, */
	/* REDIRFS_REG_FOP_WRITE, */
	/* REDIRFS_REG_FOP_AIO_READ, */
	/* REDIRFS_REG_FOP_AIO_WRITE, */
	/* REDIRFS_REG_FOP_MMAP, */
	/* REDIRFS_REG_FOP_FLUSH, */

	REDIRFS_DIR_FOP_OPEN,
	REDIRFS_DIR_FOP_RELEASE,
	REDIRFS_DIR_FOP_READDIR,
	/* REDIRFS_DIR_FOP_FLUSH, */

	REDIRFS_CHR_FOP_OPEN,
	REDIRFS_CHR_FOP_RELEASE,
	/* REDIRFS_CHR_FOP_LLSEEK, */
	/* REDIRFS_CHR_FOP_READ, */
	/* REDIRFS_CHR_FOP_WRITE, */
	/* REDIRFS_CHR_FOP_AIO_READ, */
	/* REDIRFS_CHR_FOP_AIO_WRITE, */
	/* REDIRFS_CHR_FOP_FLUSH, */

	REDIRFS_BLK_FOP_OPEN,
	REDIRFS_BLK_FOP_RELEASE,
	/* REDIRFS_BLK_FOP_LLSEEK, */
	/* REDIRFS_BLK_FOP_READ, */
	/* REDIRFS_BLK_FOP_WRITE, */
	/* REDIRFS_BLK_FOP_AIO_READ, */
	/* REDIRFS_BLK_FOP_AIO_WRITE, */
	/* REDIRFS_BLK_FOP_FLUSH, */

	REDIRFS_FIFO_FOP_OPEN,
	REDIRFS_FIFO_FOP_RELEASE,
	/* REDIRFS_FIFO_FOP_LLSEEK, */
	/* REDIRFS_FIFO_FOP_READ, */
	/* REDIRFS_FIFO_FOP_WRITE, */
	/* REDIRFS_FIFO_FOP_AIO_READ, */
	/* REDIRFS_FIFO_FOP_AIO_WRITE, */
	/* REDIRFS_FIFO_FOP_FLUSH, */

	REDIRFS_LNK_FOP_OPEN,
	REDIRFS_LNK_FOP_RELEASE,
	/* REDIRFS_LNK_FOP_LLSEEK, */
	/* REDIRFS_LNK_FOP_READ, */
	/* REDIRFS_LNK_FOP_WRITE, */
	/* REDIRFS_LNK_FOP_AIO_READ, */
	/* REDIRFS_LNK_FOP_AIO_WRITE, */
	/* REDIRFS_LNK_FOP_FLUSH, */

	/* REDIRFS_REG_AOP_READPAGE, */
	/* REDIRFS_REG_AOP_WRITEPAGE, */
	/* REDIRFS_REG_AOP_READPAGES, */
	/* REDIRFS_REG_AOP_WRITEPAGES, */
	/* REDIRFS_REG_AOP_SYNC_PAGE, */
	/* REDIRFS_REG_AOP_SET_PAGE_DIRTY, */
	/* REDIRFS_REG_AOP_PREPARE_WRITE, */
	/* REDIRFS_REG_AOP_COMMIT_WRITE, */
	/* REDIRFS_REG_AOP_BMAP, */
	/* REDIRFS_REG_AOP_INVALIDATEPAGE, */
	/* REDIRFS_REG_AOP_RELEASEPAGE, */
	/* REDIRFS_REG_AOP_DIRECT_IO, */
	/* REDIRFS_REG_AOP_GET_XIP_PAGE, */
	/* REDIRFS_REG_AOP_MIGRATEPAGE, */
	/* REDIRFS_REG_AOP_LAUNDER_PAGE, */

	REDIRFS_OP_END
};

/**
 * enum redirfs_op_call - type of filter callback
 **/
enum redirfs_op_call {
	REDIRFS_PRECALL,
	REDIRFS_POSTCALL
};

/**
 * enum redirfs_rv - filter callback return value type
 *
 * Description:
 *     If a filter in the callchain returns REDIRFS_STOP, no other callbacks
 *     in the chain will be called. The original VFS operation doesn't get
 *     called either. REDIRFS_CONTINUE tells RedirFS to continue normally
 *     with the next callback in the callchain.
 **/
enum redirfs_rv {
	REDIRFS_STOP,
	REDIRFS_CONTINUE
};

/* pointers to opaque RedirFS objects */
typedef void *redirfs_filter;   /* RedirFS filter */
typedef void *redirfs_context;  /* VFS operation context */
typedef void *redirfs_path;     /* path information */
typedef void *redirfs_root;     /* RedirFS root */

/**
 * union redirfs_op_rv - VFS operations wrappers return value type
 *
 * Description:
 *     This union allows the creation of a single common interface for all
 *     VFS operations as they return different types of values.
 **/
union redirfs_op_rv {
	int		rv_int;
	ssize_t		rv_ssize;
	unsigned int	rv_uint;
	unsigned long	rv_ulong;
	loff_t		rv_loff;
	struct dentry	*rv_dentry;
	sector_t	rv_sector;
	struct page	*rv_page;
};

/**
 * union redirfs_op_args - VFS operations wrappers arguments
 *
 * Description:
 *     Union of structures representing the arguments for every supported
 *     VFS operation. The structures are named after the corresponding
 *     operation.
 **/
union redirfs_op_args {
	/*
	struct {
		struct dentry *dentry;
		struct nameidata *nd;
	} d_revalidate;	
	*/

	/*
	struct {
		struct dentry *dentry;
		struct qstr *name;
	} d_hash;
	*/

	struct {
		struct dentry *dentry;
		struct qstr *name1;
		struct qstr *name2;
	} d_compare;

	/*
	struct {
		struct dentry *dentry;
	} d_delete;
	*/

	struct {
		struct dentry *dentry;
	} d_release;

	struct {
		struct dentry *dentry;
		struct inode *inode;
	} d_iput;	

	struct {
		struct inode *dir;
		struct dentry *dentry;
		int mode;
		struct nameidata *nd;
	} i_create;

	struct {
		struct inode *dir;
		struct dentry *dentry;
		struct nameidata *nd;
	} i_lookup;

	struct {
		struct dentry *old_dentry;
		struct inode *dir;
		struct dentry *dentry;
	} i_link;

	/*
	struct {
		struct inode *dir;
		struct dentry *dentry;
	} i_unlink;
	*/

	struct {
		struct inode *dir;
		struct dentry *dentry;
		const char *oldname;
	} i_symlink;

	struct {
		struct inode *dir;
		struct dentry *dentry;
		int mode;
	} i_mkdir;

	/*
	struct {
		struct inode *dir;
		struct dentry *dentry;
	} i_rmdir;
	*/

	struct {
		struct inode *dir;
		struct dentry *dentry;
		int mode;
		dev_t rdev;
	} i_mknod;

	struct {
		struct inode *old_dir;
		struct dentry *old_dentry;
		struct inode *new_dir;
		struct dentry *new_dentry;
	} i_rename;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	struct {
		struct inode *inode;
		int mask;
		struct nameidata *nd;
	} i_permission;
#else
	struct {
		struct inode *inode;
		int mask;
	} i_permission;
#endif

	/*
	struct {
		struct dentry *dentry;
		struct iattr *iattr;
	} i_setattr;
	*/

	struct {
		struct inode *inode;
		struct file *file;
	} f_open;

	struct {
		struct inode *inode;
		struct file *file;
	} f_release;

	/*
	struct {
		struct file *file;
		fl_owner_t id;
	} f_flush;
	*/

	/*
	struct {
		struct file *file;
		struct vm_area_struct *vma;
	} f_mmap;
	*/

	struct {
		struct file *file;
		void *dirent;
		filldir_t filldir;
	} f_readdir;

	/*
	struct {
                struct file *file;
                loff_t offset;
                int origin;
	} f_llseek;
	*/

	/*
	struct {
		struct file *file;
		char __user *buf;
		size_t count;
		loff_t *pos;
	} f_read;
	*/

	/*
	struct {
		struct file *file;
		const char __user *buf;
		size_t count;
		loff_t *pos;
	} f_write;
	*/

	/*
	struct {
		struct kiocb *iocb;
		const struct iovec *iov;
		unsigned long nr_segs;
		loff_t pos;
	} f_aio_read;
	*/

	/*
	struct {
		struct kiocb *iocb;
		const struct iovec *iov;
		unsigned long nr_segs;
		loff_t pos;
	} f_aio_write;
	*/

	/*
	struct {
		struct file *file;
		struct page *page;
	} a_readpage;
	*/

	/*
	struct {
		struct page *page;
		struct writeback_control *wbc;
	} a_writepage;
	*/

	/*
	struct {
		struct file *file;
		struct address_space *mapping;
		struct list_head *pages;
		unsigned nr_pages;
	} a_readpages;
	*/

	/*
	struct {
		struct address_space *mapping;
		struct writeback_control *wbc;
	} a_writepages;
	*/

	/*
	struct {
		struct page *page;
	} a_sync_page;
	*/

	/*
	struct {
		struct page *page;
	} a_set_page_dirty;
	*/

	/*
	struct {
		struct file *file;
		struct page *page;
		unsigned from;
		unsigned to;
	} a_prepare_write;
	*/

	/*
	struct {
		struct file *file;
		struct page *page;
		unsigned from;
		unsigned to;
	} a_commit_write;
	*/

	/*
	struct {
		struct address_space *mapping;
		sector_t block;
	} a_bmap;
	*/

	/*
	struct {
		struct page *page;
		unsigned long offset;
	} a_invalidatepage;
	*/

	/*
	struct {
		struct page *page;
		gfp_t flags;
	} a_releasepage;
	*/

	/*
	struct {
		int rw;
		struct kiocb *iocb;
		const struct iovec *iov;
		loff_t offset;
		unsigned long nr_segs;
	} a_direct_IO;
	*/

	/*
	struct {
		struct address_space *mapping;
		sector_t offset;
		int create;
	} a_get_xip_page;
	*/

	/*
	struct {
		struct address_space *mapping;
		struct page *newpage;
		struct page *page;
	} a_migratepage;
	*/

	/*
	struct {
		struct page *page;
	} a_launder_page;
	*/
};

/**
 * struct redirfs_op_type - describes filter callbacks
 * @id:         identifies the VFS operation the callback is registred for
 * @call:       type of callback (pre or post callback)
 **/
struct redirfs_op_type {
	enum redirfs_op_id id;
	enum redirfs_op_call call;
};

/**
 * struct redirfs_args - arguments for VFS operation wrappers
 * @args:       arguments for the original operation
 * @rv:         used to store the original operation return value
 * @type:       callback type
 *
 * Description:
 *     A pointer to this structure is passed to VFS operation wrappers
 *     enabling them to the call the appropriate filter callbacks.
 **/
struct redirfs_args {
	union redirfs_op_args args;
	union redirfs_op_rv rv;
	struct redirfs_op_type type;
};

/**
 * struct redirfs_path_info - identifies a directory subtree
 * @dentry:     root dentry of the subtree
 * @vfsmount:   mountpoint information
 * @flags:      REDIRFS_PATH_INCLUDE or REDIRFS_PATH_EXCLUDE
 *
 * Description:
 *     Identifies a directory subtree to be include/excluded from filters
 *     path lists.
 **/
struct redirfs_path_info {
	struct dentry *dentry;
	struct vfsmount *mnt;
	int flags;
};

/**
 * struct redirfs_op_info - contains callbacks for a specific VFS operation
 * @op_id:      identifies the VFS operation
 * @pre_cb:     pre-callback
 * @post_cb:    post-callback
 *
 * Description:
 *      This structures is used to register filter callbacks.
 **/
struct redirfs_op_info {
	enum redirfs_op_id op_id;
	enum redirfs_rv (*pre_cb)(redirfs_context, struct redirfs_args *);
	enum redirfs_rv (*post_cb)(redirfs_context, struct redirfs_args *);
};

/**
 * struct redirfs_filter_operation - pointers to filter operations
 *
 * Description:
 *     Contains pointers to common filter operations like activation,
 *     including path into the filter's path list, etc. It is currently
 *     unused.
 **/
struct redirfs_filter_operations {
	 int (*activate)(void);
	 int (*deactivate)(void);
	 int (*add_path)(struct redirfs_path_info *);
	 int (*rem_path)(redirfs_path);
	 int (*unregister)(void);
	 int (*rem_paths)(void);
	 void (*move_begin)(void);
	 void (*move_end)(void);
	 int (*dentry_moved)(redirfs_root, redirfs_root, struct dentry *);
	 int (*inode_moved)(redirfs_root, redirfs_root, struct inode *);
};

/**
 * struct redirfs_filter_info - describes a RedirFS filter for registration
 * @owner:      module implementing the filter
 * @name:       name of the filter
 * @priority:   filter priority, lower means higher priority
 * @active:     if non-zero, the filter is activated upon registration
 * @ops:        filter operations callbacks, currently unused
 *
 * Description:
 *     This structure is used to register filters with RedirFS. The priority
 *     field is used when more than one filter is active for a specific VFS
 *     operation. Pre-callbacks of filters with higher priority are called
 *     first, post-callback are called in reverse order.
 **/
struct redirfs_filter_info {
	struct module *owner;
	const char *name;
	int priority;
	int active;
	struct redirfs_filter_operations *ops;
};

/**
 * struct redirfs_filter_attribute - describes a sysfs attribute
 * @attr:       kobject attribute
 * @show:       pointer to a function returning the attribute's value in buf
 * @store:      pointer to a function storing the attribute's value from buf
 *
 * Description:
 *     This structure is used to create sysfs attributes for filters.
 **/
struct redirfs_filter_attribute {
	struct attribute attr;
	ssize_t (*show)(redirfs_filter filter,
			struct redirfs_filter_attribute *attr, char *buf);
	ssize_t (*store)(redirfs_filter filter,
			struct redirfs_filter_attribute *attr, const char *buf,
			size_t count);
};

/**
 * struct redirfs_data - filter private data
 * @list:       list of private data structures
 * @cnt:        reference count
 * @filter:     filter owning the data
 * @free:       pointer to a function called when the data is to be freed
 * @detach:     pointer to a function called when the data is detached
 *
 * Description:
 *     Used by filters to attach private data to the current callback context
 *     (redirfs_context) or a VFS object. This is usually used by
 *     pre-callbacks to pass data to the corresponding post-callback.
 **/
struct redirfs_data {
	struct list_head list;
	atomic_t cnt;
	redirfs_filter filter;
	void (*free)(struct redirfs_data *);
	void (*detach)(struct redirfs_data *);
};

int redirfs_create_attribute(redirfs_filter filter,
		struct redirfs_filter_attribute *attr);
int redirfs_remove_attribute(redirfs_filter filter,
		struct redirfs_filter_attribute *attr);
struct kobject *redirfs_filter_kobject(redirfs_filter filter);
redirfs_path redirfs_add_path(redirfs_filter filter,
		struct redirfs_path_info *info);
int redirfs_rem_path(redirfs_filter filter, redirfs_path path);
int redirfs_get_id_path(redirfs_path path);
redirfs_path redirfs_get_path_id(int id);
redirfs_path redirfs_get_path(redirfs_path path);
void redirfs_put_path(redirfs_path path);
redirfs_path* redirfs_get_paths_root(redirfs_filter filter, redirfs_root root);
redirfs_path* redirfs_get_paths(redirfs_filter filter);
void redirfs_put_paths(redirfs_path *paths);
struct redirfs_path_info *redirfs_get_path_info(redirfs_filter filter,
		redirfs_path path);
void redirfs_put_path_info(struct redirfs_path_info *info);
int redirfs_rem_paths(redirfs_filter filter);
redirfs_root redirfs_get_root_file(redirfs_filter filter, struct file *file);
redirfs_root redirfs_get_root_dentry(redirfs_filter filter,
		struct dentry *dentry);
redirfs_root redirfs_get_root_inode(redirfs_filter filter, struct inode *inode);
redirfs_root redirfs_get_root_path(redirfs_path path);
redirfs_root redirfs_get_root(redirfs_root root);
void redirfs_put_root(redirfs_root root);
redirfs_filter redirfs_register_filter(struct redirfs_filter_info *info);
int redirfs_unregister_filter(redirfs_filter filter);
void redirfs_delete_filter(redirfs_filter filter);
int redirfs_set_operations(redirfs_filter filter, struct redirfs_op_info ops[]);
int redirfs_activate_filter(redirfs_filter filter);
int redirfs_deactivate_filter(redirfs_filter filter);
int redirfs_get_filename(struct vfsmount *mnt, struct dentry *dentry, char *buf,
		int size);
int redirfs_init_data(struct redirfs_data *data, redirfs_filter filter,
		void (*free)(struct redirfs_data *),
		void (*detach)(struct redirfs_data *));
struct redirfs_data *redirfs_get_data(struct redirfs_data *data);
void redirfs_put_data(struct redirfs_data *data);
struct redirfs_data *redirfs_attach_data_file(redirfs_filter filter,
		struct file *file, struct redirfs_data *data);
struct redirfs_data *redirfs_detach_data_file(redirfs_filter filter,
		struct file *file);
struct redirfs_data *redirfs_get_data_file(redirfs_filter filter,
		struct file *file);
struct redirfs_data *redirfs_attach_data_dentry(redirfs_filter filter,
		struct dentry *dentry, struct redirfs_data *data);
struct redirfs_data *redirfs_detach_data_dentry(redirfs_filter filter,
		struct dentry *dentry);
struct redirfs_data *redirfs_get_data_dentry(redirfs_filter filter,
		struct dentry *dentry);
struct redirfs_data *redirfs_attach_data_inode(redirfs_filter filter,
		struct inode *inode, struct redirfs_data *data);
struct redirfs_data *redirfs_detach_data_inode(redirfs_filter filter,
		struct inode *inode);
struct redirfs_data *redirfs_get_data_inode(redirfs_filter filter,
		struct inode *inode);
struct redirfs_data *redirfs_attach_data_context(redirfs_filter filter,
		redirfs_context context, struct redirfs_data *data);
struct redirfs_data *redirfs_detach_data_context(redirfs_filter filter,
		redirfs_context context);
struct redirfs_data *redirfs_get_data_context(redirfs_filter filter,
		redirfs_context context);
struct redirfs_data *redirfs_attach_data_root(redirfs_filter filter,
		redirfs_root root, struct redirfs_data *data);
struct redirfs_data *redirfs_detach_data_root(redirfs_filter filter,
		redirfs_root root);
struct redirfs_data *redirfs_get_data_root(redirfs_filter filter,
		redirfs_root root);
#endif

