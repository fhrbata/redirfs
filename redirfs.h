#if !defined(_REDIRFS_H)
#define _REDIRFS_H

enum rfs_err {
	RFS_ERR_OK = 0,
	RFS_ERR_INVAL = -EINVAL,
	RFS_ERR_NOMEM = -ENOMEM,
	RFS_ERR_NOENT = -ENOENT,
	RFS_ERR_NAMETOOLONG = -ENAMETOOLONG,
	RFS_ERR_EXIST = -EEXIST
};

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

	RFS_REG_IOP_CREATE,
	RFS_REG_IOP_LOOKUP,
	RFS_REG_IOP_MKDIR,
	RFS_REG_IOP_PERMISSION,

	RFS_DIR_IOP_CREATE,
	RFS_DIR_IOP_LOOKUP,
	RFS_DIR_IOP_MKDIR,
	RFS_DIR_IOP_PERMISSION,

	RFS_REG_FOP_OPEN,
	RFS_REG_FOP_RELEASE,

	RFS_DIR_FOP_OPEN,
	RFS_DIR_FOP_RELEASE,

	RFS_OP_END
};

enum rfs_op_type {
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
		struct qstr *str1;
		struct qstr *str2;
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
		struct inode *dir;
		struct dentry *dentry;
		int mode;
	} i_mkdir;

	struct {
		struct inode *inode;
		int mode;
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
};

union rfs_op_retv {
	int		rv_int;
	ssize_t		rv_ssize;
	unsigned int	rv_uint;
	unsigned long	rv_ulong;
	loff_t		rv_loff;
	struct dentry	*rv_dentry;
};

struct rfs_op_exts {
	const char* path;
};

struct rfs_op_info {
	enum rfs_op_id id;
	enum rfs_op_type type;
};

typedef void* rfs_filter;
typedef void* rfs_context;

#define RFS_PATH_SINGLE		1	
#define RFS_PATH_SUBTREE	2
#define RFS_PATH_INCLUDE	4	
#define RFS_PATH_EXCLUDE	8

struct rfs_path_info {
	const char *path;
	int flags;
};

struct rfs_args {
	union rfs_op_args args;
	union rfs_op_retv retv;
	struct rfs_op_info info;
	struct rfs_op_exts exts;
};

struct rfs_filter_info {
	const char *name;
	int priority;
	int active;
};

struct rfs_op_info {
	enum rfs_op_id op_id;
	enum rfs_retv (*pre_cb)(rfs_context, struct rfs_args);
	enum rfs_retv (*post_cb)(rfs_context, struct rfs_args);
};

enum rfs_err rfs_register_filter(rfs_filter *filter, struct rfs_filter_info *filter_info);
enum rfs_err rfs_set_operations(rfs_filter filter, struct rfs_op_info *op_info);
enum rfs_err rfs_set_path(rfs_filter filter, struct rfs_path_info *path_info);
enum rfs_err rfs_unregister_filter(rfs_filter filter);
enum rfs_err rfs_activate_filter(rfs_filter filter);
enum rfs_err rfs_deactivate_filter(rfs_filter filter);

#endif
