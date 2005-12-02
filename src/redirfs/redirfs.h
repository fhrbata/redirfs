#ifndef _REDIRFS_REDIRFS_H
#define _REDIRFS_REDIRFS_H

#include <linux/vfs.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>

#define REDIRFS_OP_END {REDIRFS_END, 0, NULL, NULL}

enum {
	REDIRFS_I_REG,
	REDIRFS_I_DIR,
	REDIRFS_F_REG,
	REDIRFS_F_DIR,
	REDIRFS_DENTRY,
	REDIRFS_END
};

enum {
	REDIRFS_IOP_CREATE,
	REDIRFS_IOP_LOOKUP,
	REDIRFS_IOP_LINK,
	REDIRFS_IOP_UNLINK,
	REDIRFS_IOP_SYMLINK,
	REDIRFS_IOP_MKDIR,
	REDIRFS_IOP_RMDIR,
	REDIRFS_IOP_MKNOD,
	REDIRFS_IOP_RENAME,
	REDIRFS_IOP_READLINK,
	REDIRFS_IOP_FOLLOW_LINK,
	REDIRFS_IOP_PUT_LINK,
	REDIRFS_IOP_TRUNCATE,
	REDIRFS_IOP_PERMISSION,
	REDIRFS_IOP_SETATTR,
	REDIRFS_IOP_GETATTR,
	REDIRFS_IOP_SETXATTR,
	REDIRFS_IOP_GETXATTR,
	REDIRFS_IOP_LISTXATTR,
	REDIRFS_IOP_REMOVEXATTR,
	REDIRFS_IOP_END
};

enum {
	REDIRFS_FOP_LLSEEK,
	REDIRFS_FOP_READ,
	REDIRFS_FOP_AIO_READ,
	REDIRFS_FOP_WRITE,
	REDIRFS_FOP_AIO_WRITE,
	REDIRFS_FOP_READDIR,
	REDIRFS_FOP_POLL,
	REDIRFS_FOP_IOCTL,
	REDIRFS_FOP_MMAP,
	REDIRFS_FOP_OPEN,
	REDIRFS_FOP_FLUSH,
	REDIRFS_FOP_RELEASE,
	REDIRFS_FOP_FSYNC,
	REDIRFS_FOP_AIO_FSYNC,
	REDIRFS_FOP_FASYNC,
	REDIRFS_FOP_LOCK,
	REDIRFS_FOP_READV,
	REDIRFS_FOP_WRITEV,
	REDIRFS_FOP_SENDFILE,
	REDIRFS_FOP_SENDPAGE,
	REDIRFS_FOP_GET_UNMAPPED_AREA,
	REDIRFS_FOP_CHECK_FLAGS,
	REDIRFS_FOP_DIR_NOTIFY,
	REDIRFS_FOP_FLOCK,
	REDIRFS_FOP_END
};

enum {
	REDIRFS_DOP_REVALIDATE,
	REDIRFS_DOP_HASH,
	REDIRFS_DOP_COMPARE,
	REDIRFS_DOP_DELETE,
	REDIRFS_DOP_RELEASE,
	REDIRFS_DOP_IPUT,
	REDIRFS_DOP_END
};

enum redirfs_retv {
	REDIRFS_RETV_STOP,
	REDIRFS_RETV_CONTINUE
};

typedef void* redirfs_filter;
typedef void* redirfs_context;

union redirfs_op_args_t {
	struct {
		struct inode			*dir;
		struct dentry			*dentry;
		int				mode;
		struct nameidata		*nd;
	} i_create;
	
	struct {
		struct inode			*dir;
		struct dentry			*dentry;
		struct nameidata		*nd;
	} i_lookup;

	struct {
		struct dentry			*old_dentry;
		struct inode			*inode;
		struct dentry			*new_dentry;
	} i_link;

	struct {
		struct inode			*dir;
		struct dentry			*dentry;
	} i_unlink;

	struct {
		struct inode			*dir;
		struct dentry			*dentry;
		const char			*symname;
	} i_symlink;

	struct {
		struct inode			*dir;
		struct dentry			*dentry;
		int 				mode;
	} i_mkdir;

	struct {
		struct inode			*dir;
		struct dentry			*dentry;
	} i_rmdir;

	struct {
		struct inode			*dir;
		struct dentry			*dentry;
		dev_t				rdev;
	} i_mknod;

	struct {
		struct inode			*old_dir;
		struct dentry			*old_dentry;
		struct inode			*new_dir;
		struct dentry			*new_dentry;
	} i_rename;

	struct {
		struct dentry			*dentry;
		char __user			*buffer;
		int				size;
	} i_readlink;

	struct {
		struct dentry			*dentry;
		struct nameidata		*nd;
	} i_follow_link;

	struct {
		struct dentry			*dentry;
		struct nameidata		*nd;
	} i_put_link;

	struct {
		struct inode			*inode;
	} i_truncate;

	struct {
		struct inode			*inode;
		int				mode;
		struct nameidata		*nd;
	} i_permission;

	struct {
		struct dentry			*dentry;
		struct iattr			*iattr;
	} i_setattr;

	struct {
		struct vfsmount			*vfsmount;
		struct dentry			*dentry;
		struct kstat			*kstat;
	} i_getattr;

	struct {
		struct dentry			*dentry;
		const char			*name;
		const void			*value;
		size_t				size;
		int				flags;
	} i_setxattr;

	struct {
		struct dentry			*dentry;
		const char			*name;
		void				*value;
		size_t				size;
	} i_getxattr;

	struct {
		struct dentry			*dentry;
		char				*buffer;
		size_t				size;
	} i_listxattr;
	
	struct {
		struct dentry			*dentry;
		const char			*name;
	} i_removexttr;



	struct {
		struct file			*file;
		loff_t				offset;
		int				origin;
	} f_llseek;

	struct {
		struct file			*file;
		char __user			*buffer;
		size_t				count;
		loff_t				*pos;
	} f_read;

	struct {
		struct kiocb			*kiocb;
		char __user			*buffer;
		size_t				cound;
		loff_t				pos;
	} f_aio_read;

	struct {
		struct file			*file;
		const char __user		*buffer;
		size_t				count;
		loff_t				*pos;
	} f_write;

	struct {
		struct kiocb			*kiocb;
		const char __user		*buffer;
		size_t				cound;
		loff_t				pos;
	} f_aio_write;

	struct {
		struct file			*file;
		void				*dirent;
		filldir_t			filldir;
	} f_readdir;

	struct {
		struct file			*file;
		struct poll_table_struct	*poll_table;
	} f_poll;

	struct {
		struct inode			*inode;
		struct file			*file;
		unsigned int			cmd;
		unsigned long			arg;
	} f_ioctl;

	struct {
		struct file			*file;
		struct vm_area_struct		*vm_area;
	} f_mmap;

	struct {
		struct inode			*dir;
		struct file			*file;
	} f_open;

	struct {
		struct file			*file;
	} f_flush;

	struct {
		struct inode			*dir;
		struct file			*file;
	} f_release;

	struct {
		struct file			*file;
		struct dentry			*dentry;
		int				datasync;
	} f_fsync;

	struct {
		struct kiocb			*kiocb;
		int				datasync;
	} f_aio_fsync;

	struct {
		int				fd;
		struct file			*file;
		int				on;
	} f_fasync;

	struct {
		struct file			*file;
		int				cmd;
		struct file_lock		*lock;
	} f_lock;

	struct {
		struct file			*file;
		const struct iovec __user	*vec;
		unsigned long			vlen;
		loff_t				*pos;
	} f_readv;

	struct {
		struct file			*file;
		const struct iovec __user	*vec;
		unsigned long			vlen;
		loff_t				*pos;
	} f_writev;

	struct {
		struct file			*file;
		loff_t				*ppos;
		size_t				cound;
		read_actor_t			actor;
		void				*target;
	} f_sendfile;

	struct {
		struct file			*file;
		struct page			*page;
		int				offset;
		size_t				size;
		loff_t				*ppos;
		int				more;
	} f_sendpage;

	struct {
		struct file			*file;
		unsigned long			addr;
		unsigned long			len;
		unsigned long			pgoff;
		unsigned long			flags;
	} f_get_unmapped_area;

	struct {
		int				flags;
	} f_check_flags;

	struct {
		struct file			*file;
		unsigned long			arg;
	} f_dir_notify;

	struct {
		struct file			*file;
		int				flags;
		struct file_lock		*lock;
	} f_flock;



	struct {
		struct dentry			*dentry;
		struct nameidata		*nd;
	} d_revalidate;

	struct {
		struct dentry			*dentry;
		struct qstr			*name;
	} d_hash;

	struct {
		struct dentry			*dentry;
		struct qstr			*name1;
		struct qstr			*name2;
	} d_compare;

	struct {
		struct dentry			*dentry;
	} d_delete;

	struct {
		struct dentry			*dentry;
	} d_release;

	struct {
		struct dentry			*dentry;
		struct inode			*inode;
	} d_iput;
};

union redirfs_op_retv_t {
	int		rv_int;
	ssize_t		rv_ssize;
	unsigned int	rv_uint;
	unsigned long	rv_ulong;
	loff_t		rv_loff;
	struct dentry	*rv_dentry;
};

struct redirfs_op_exts_t{
	const char* full_path;
};

struct redirfs_args_t {
	union redirfs_op_args_t		args;
	struct redirfs_op_exts_t	exts;
	union redirfs_op_retv_t		retv;
};

struct redirfs_op_t {
	int type;
	int op;
	enum redirfs_retv (*pre_op)(redirfs_context context, struct redirfs_args_t *args);
	enum redirfs_retv (*post_op)(redirfs_context context, struct redirfs_args_t *args);
};

redirfs_filter	redirfs_register_filter(const char *name, int turn, unsigned long flags);
int 		redirfs_unregister_filter(redirfs_filter filter);
void 		redirfs_activate_filter(redirfs_filter filter);
void 		redirfs_deactivate_filter(redirfs_filter filter);
int		redirfs_set_operations(redirfs_filter filter, struct redirfs_op_t ops[]);
int 		redirfs_remove_operations(redirfs_filter filter, struct redirfs_op_t ops[]);
int 		redirfs_include_path(redirfs_filter filter, const char *path);
int 		redirfs_exclude_path(redirfs_filter filter, const char *path);

#endif
