#if !defined(_REDIRFS_H)
#define _REDIRFS_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>

enum rfs_op_id {
	RFS_NONE_DOP_D_REVALIDATE,
	RFS_NONE_DOP_D_HASH,
	RFS_NONE_DOP_D_COMPARE,
	RFS_NONE_DOP_D_DELETE,
	RFS_NONE_DOP_D_RELEASE,
	RFS_NONE_DOP_D_IPUT,

	RFS_REG_DOP_D_REVALIDATE,
	RFS_REG_DOP_D_HASH,
	RFS_REG_DOP_D_COMPARE,
	RFS_REG_DOP_D_DELETE,
	RFS_REG_DOP_D_RELEASE,
	RFS_REG_DOP_D_IPUT,

	RFS_DIR_DOP_D_REVALIDATE,
	RFS_DIR_DOP_D_HASH,
	RFS_DIR_DOP_D_COMPARE,
	RFS_DIR_DOP_D_DELETE,
	RFS_DIR_DOP_D_RELEASE,
	RFS_DIR_DOP_D_IPUT,

	RFS_CHR_DOP_D_REVALIDATE,
	RFS_CHR_DOP_D_HASH,
	RFS_CHR_DOP_D_COMPARE,
	RFS_CHR_DOP_D_DELETE,
	RFS_CHR_DOP_D_RELEASE,
	RFS_CHR_DOP_D_IPUT,

	RFS_BLK_DOP_D_REVALIDATE,
	RFS_BLK_DOP_D_HASH,
	RFS_BLK_DOP_D_COMPARE,
	RFS_BLK_DOP_D_DELETE,
	RFS_BLK_DOP_D_RELEASE,
	RFS_BLK_DOP_D_IPUT,

	RFS_FIFO_DOP_D_REVALIDATE,
	RFS_FIFO_DOP_D_HASH,
	RFS_FIFO_DOP_D_COMPARE,
	RFS_FIFO_DOP_D_DELETE,
	RFS_FIFO_DOP_D_RELEASE,
	RFS_FIFO_DOP_D_IPUT,

	RFS_LNK_DOP_D_REVALIDATE,
	RFS_LNK_DOP_D_HASH,
	RFS_LNK_DOP_D_COMPARE,
	RFS_LNK_DOP_D_DELETE,
	RFS_LNK_DOP_D_RELEASE,
	RFS_LNK_DOP_D_IPUT,

	RFS_SOCK_DOP_D_REVALIDATE,
	RFS_SOCK_DOP_D_HASH,
	RFS_SOCK_DOP_D_COMPARE,
	RFS_SOCK_DOP_D_DELETE,
	RFS_SOCK_DOP_D_RELEASE,
	RFS_SOCK_DOP_D_IPUT,

	RFS_REG_IOP_PERMISSION,

	RFS_DIR_IOP_CREATE,
	RFS_DIR_IOP_LOOKUP,
	RFS_DIR_IOP_LINK,
	RFS_DIR_IOP_UNLINK,
	RFS_DIR_IOP_MKDIR,
	RFS_DIR_IOP_RMDIR,
	RFS_DIR_IOP_MKNOD,
	RFS_DIR_IOP_PERMISSION,

	RFS_CHR_IOP_PERMISSION,

	RFS_BLK_IOP_PERMISSION,

	RFS_FIFO_IOP_PERMISSION,

	RFS_LNK_IOP_PERMISSION,

	RFS_SOCK_IOP_PERMISSION,

	RFS_REG_FOP_OPEN,
	RFS_REG_FOP_RELEASE,
	RFS_REG_FOP_LLSEEK,
	RFS_REG_FOP_READ,
	RFS_REG_FOP_WRITE,
	RFS_REG_FOP_FLUSH,

	RFS_DIR_FOP_OPEN,
	RFS_DIR_FOP_RELEASE,
	RFS_DIR_FOP_READDIR,
	RFS_DIR_FOP_FLUSH,

	RFS_CHR_FOP_OPEN,
	RFS_CHR_FOP_RELEASE,
	RFS_CHR_FOP_LLSEEK,
	RFS_CHR_FOP_READ,
	RFS_CHR_FOP_WRITE,
	RFS_CHR_FOP_FLUSH,

	RFS_BLK_FOP_OPEN,
	RFS_BLK_FOP_RELEASE,
	RFS_BLK_FOP_LLSEEK,
	RFS_BLK_FOP_READ,
	RFS_BLK_FOP_WRITE,
	RFS_BLK_FOP_FLUSH,

	RFS_FIFO_FOP_OPEN,
	RFS_FIFO_FOP_RELEASE,
	RFS_FIFO_FOP_LLSEEK,
	RFS_FIFO_FOP_READ,
	RFS_FIFO_FOP_WRITE,
	RFS_FIFO_FOP_FLUSH,

	RFS_LNK_FOP_OPEN,
	RFS_LNK_FOP_RELEASE,
	RFS_LNK_FOP_LLSEEK,
	RFS_LNK_FOP_READ,
	RFS_LNK_FOP_WRITE,
	RFS_LNK_FOP_FLUSH,

	RFS_SOCK_FOP_OPEN,
	RFS_SOCK_FOP_RELEASE,
	RFS_SOCK_FOP_LLSEEK,
	RFS_SOCK_FOP_READ,
	RFS_SOCK_FOP_WRITE,
	RFS_SOCK_FOP_FLUSH,

	RFS_OP_END
};

enum rfs_op_call {
	RFS_PRECALL,
	RFS_POSTCALL
};

enum rfs_retv {
	RFS_STOP,
	RFS_CONTINUE
};

union rfs_op_args {
	struct {
		struct dentry *dentry;
		struct nameidata *nd;
	} d_revalidate;	

	struct {
		struct dentry *dentry;
		struct qstr *name;
	} d_hash;

	struct {
		struct dentry *dentry;
		struct qstr *name1;
		struct qstr *name2;
	} d_compare;

	struct {
		struct dentry *dentry;
	} d_delete;

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

	struct {
		struct inode *dir;
		struct dentry *dentry;
	} i_unlink;

	struct {
		struct inode *dir;
		struct dentry *dentry;
		int mode;
	} i_mkdir;

	struct {
		struct inode *dir;
		struct dentry *dentry;
	} i_rmdir;

	struct {
		struct inode *dir;
		struct dentry *dentry;
		int mode;
		dev_t rdev;
	} i_mknod;

	struct {
		struct inode *inode;
		int mask;
		struct nameidata *nd;
	} i_permission;	

	struct {
		struct inode *inode;
		struct file *file;
	} f_open;

	struct {
		struct inode *inode;
		struct file *file;
	} f_release;

	struct {
		struct file *file;
		fl_owner_t id;
	} f_flush;

	struct {
		struct file *file;
		void *buf;
		filldir_t filldir;
	} f_readdir;

	struct {
                struct file *file;
                loff_t offset;
                int origin;
	} f_llseek;

	struct {
		struct file *file;
		char __user *buf;
		size_t count;
		loff_t *pos;
	} f_read;

	struct {
		struct file *file;
		const char __user *buf;
		size_t count;
		loff_t *pos;
	} f_write;
};

union rfs_op_retv {
	int		rv_int;
	ssize_t		rv_ssize;
	unsigned int	rv_uint;
	unsigned long	rv_ulong;
	loff_t		rv_loff;
	struct dentry	*rv_dentry;
};

struct rfs_op_type {
	enum rfs_op_id id;
	enum rfs_op_call call;
};

typedef void* rfs_filter;
typedef void* rfs_context;

struct rfs_args {
	union rfs_op_args args;
	union rfs_op_retv retv;
	struct rfs_op_type type;
};

#define RFS_PATH_SINGLE		1	
#define RFS_PATH_SUBTREE	2
#define RFS_PATH_INCLUDE	4	
#define RFS_PATH_EXCLUDE	8

struct rfs_path_info {
	char *path;
	int flags;
};

struct rfs_op_info {
	enum rfs_op_id op_id;
	enum rfs_retv (*pre_cb)(rfs_context, struct rfs_args *);
	enum rfs_retv (*post_cb)(rfs_context, struct rfs_args *);
};

struct rfs_flt_attribute {
	struct attribute attr;
	ssize_t (*show)(rfs_filter filter, struct rfs_flt_attribute *attr, char *buf);
	ssize_t (*store)(rfs_filter filter, struct rfs_flt_attribute *attr, const char *buf, size_t size);
	void *data;
};

enum rfs_ctl_id {
	RFS_CTL_ACTIVATE,
	RFS_CTL_DEACTIVATE,
	RFS_CTL_SETPATH
};

union rfs_ctl_data {
	struct rfs_path_info path_info;
};

struct rfs_priv_data {
	struct list_head list;
	atomic_t cnt;
	rfs_filter flt;
	void (*cb)(struct rfs_priv_data *);
};

struct rfs_ctl {
	enum rfs_ctl_id id;
	union rfs_ctl_data data;
};

struct rfs_filter_info {
	char *name;
	int priority;
	int active;
	int (*ctl_cb)(struct rfs_ctl *ctl);
};

int rfs_register_filter(rfs_filter *filter, struct rfs_filter_info *filter_info);
int rfs_set_operations(rfs_filter filter, struct rfs_op_info *op_info);
int rfs_set_path(rfs_filter filter, struct rfs_path_info *path_info);
int rfs_unregister_filter(rfs_filter filter);
int rfs_activate_filter(rfs_filter filter);
int rfs_deactivate_filter(rfs_filter filter);

int rfs_init_data(struct rfs_priv_data *data, rfs_filter filter, void (*cb)(struct rfs_priv_data *));
void rfs_put_data(struct rfs_priv_data *data);
struct rfs_priv_data *rfs_get_data(struct rfs_priv_data *data);

int rfs_attach_data_inode(rfs_filter filter, struct inode *inode, struct rfs_priv_data *data, struct rfs_priv_data **exist);
int rfs_attach_data_dentry(rfs_filter filter, struct dentry *dentry, struct rfs_priv_data *data, struct rfs_priv_data **exist);
int rfs_attach_data_file(rfs_filter filter, struct file *file, struct rfs_priv_data *data, struct rfs_priv_data **exist);
int rfs_detach_data_inode(rfs_filter filter, struct inode *inode, struct rfs_priv_data **data);
int rfs_detach_data_dentry(rfs_filter filter, struct dentry *dentry, struct rfs_priv_data **data);
int rfs_detach_data_file(rfs_filter filter, struct file *file, struct rfs_priv_data **data);
int rfs_get_data_inode(rfs_filter filter, struct inode *inode, struct rfs_priv_data **data);
int rfs_get_data_dentry(rfs_filter filter, struct dentry *dentry, struct rfs_priv_data **data);
int rfs_get_data_file(rfs_filter filter, struct file *file, struct rfs_priv_data **data);
int rfs_get_filename(struct dentry *dentry, char *buffer, int size);

int rfs_register_attribute(rfs_filter filter, struct rfs_flt_attribute *attr);
int rfs_unregister_attribute(rfs_filter filter, struct rfs_flt_attribute *attr);
int rfs_get_kobject(rfs_filter filter, struct kobject **kobj);


#define rfs_flt_attr(__name, __mode, __show, __store, __data)	\
struct rfs_flt_attribute rfs_flt_attr_##__name = { 		\
	.attr = { 						\
		.name  = __stringify(__name), 			\
		.mode  = __mode, 				\
		.owner = THIS_MODULE				\
	}, 							\
	.show = __show, 					\
	.store = __store, 					\
	.data = __data						\
}

#endif

