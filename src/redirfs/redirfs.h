#ifndef _REDIRFS_REDIRFS_H
#define _REDIRFS_REDIRFS_H

#include <linux/vfs.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>

/**
 * \defgroup interface RedirFS Interface Documentation
 */

/*@{*/ 

#define REDIRFS_OP_END {REDIRFS_END, 0, NULL, NULL}	/**< end mark for operations array */


#define REDIRFS_NO_ERR			0		/**< no error occured */
#define REDIRFS_ERR_NOMEM		-ENOMEM		/**< kernel out of memory*/
#define REDIRFS_ERR_NAMETOOLONG		-ENAMETOOLONG	/**< dentry full path too long*/
#define REDIRFS_ERR_EXIST		-EEXIST		/**< Filter exists */
#define REDIRFS_ERR_INVAL		-EINVAL		/**< invalid argument */
#define REDIRFS_ERR_NOTDIR		-ENOTDIR	/**< path is not a directory */
#define REDIRFS_ERR_NOENT		-ENOENT		/**< path not found */
#define REDIRFS_ERR_NOTATTACHED		-201		/**< path can not be excluded because is not attached */

/**
 * Type of operations.
 *
 * Every operation is specified by type(group) of operations identifier and
 * by operations identifier. This enum contains all supported types of
 * operations.
 */
enum redirfs_op_type {
	REDIRFS_I_REG,		/**< inode operations of regular file */
	REDIRFS_I_DIR,		/**< inode operations of directory file */
	REDIRFS_F_REG,		/**< file operations of regular file */
	REDIRFS_F_DIR,		/**< file operations of directory file */
	REDIRFS_DENTRY,		/**< dentry operations */
	REDIRFS_END		/**< end mark for type of operations*/
};

/**
 * Inode operations
 *
 */
enum redirfs_iop {
	REDIRFS_IOP_CREATE,		/**< create regular file */
	REDIRFS_IOP_LOOKUP,		/**< directory lookup */ 
	REDIRFS_IOP_LINK,		/**< not implemented yet */
	REDIRFS_IOP_UNLINK,		/**< remove file */
	REDIRFS_IOP_SYMLINK,		/**< not implemented yet */
	REDIRFS_IOP_MKDIR,		/**< create directory */
	REDIRFS_IOP_RMDIR,		/**< remove directory */
	REDIRFS_IOP_MKNOD,		/**< not implemented yet */
	REDIRFS_IOP_RENAME,		/**< not implemented yet */
	REDIRFS_IOP_READLINK,		/**< not implemented yet */
	REDIRFS_IOP_FOLLOW_LINK,	/**< not implemented yet */
	REDIRFS_IOP_PUT_LINK,		/**< not implemented yet */
	REDIRFS_IOP_TRUNCATE,		/**< not implemented yet */
	REDIRFS_IOP_PERMISSION,		/**< check inode permissions */
	REDIRFS_IOP_SETATTR,		/**< not implemented yet */
	REDIRFS_IOP_GETATTR,		/**< not implemented yet */
	REDIRFS_IOP_SETXATTR,		/**< not implemented yet */
	REDIRFS_IOP_GETXATTR,		/**< not implemented yet */
	REDIRFS_IOP_LISTXATTR,		/**< not implemented yet */
	REDIRFS_IOP_REMOVEXATTR,	/**< not implemented yet */
	REDIRFS_IOP_END			/**< end mark for inode operations*/
};

/**
 * File operations identifiers.
 */
enum redirfs_fop {
	REDIRFS_FOP_LLSEEK,		/**< not implemented yet */
	REDIRFS_FOP_READ,		/**< not implemented yet */
	REDIRFS_FOP_AIO_READ,		/**< not implemented yet */
	REDIRFS_FOP_WRITE,		/**< not implemented yet */
	REDIRFS_FOP_AIO_WRITE,		/**< not implemented yet */
	REDIRFS_FOP_READDIR,		/**< not implemented yet */
	REDIRFS_FOP_POLL,		/**< not implemented yet */
	REDIRFS_FOP_IOCTL,		/**< not implemented yet */
	REDIRFS_FOP_MMAP,		/**< not implemented yet */
	REDIRFS_FOP_OPEN,		/**< open file */
	REDIRFS_FOP_FLUSH,		/**< close file - decreases usage counter*/
	REDIRFS_FOP_RELEASE,		/**< release file - no one is using it */
	REDIRFS_FOP_FSYNC,		/**< not implemented yet */
	REDIRFS_FOP_AIO_FSYNC,		/**< not implemented yet */
	REDIRFS_FOP_FASYNC,		/**< not implemented yet */
	REDIRFS_FOP_LOCK,		/**< not implemented yet */
	REDIRFS_FOP_READV,		/**< not implemented yet */
	REDIRFS_FOP_WRITEV,		/**< not implemented yet */
	REDIRFS_FOP_SENDFILE,		/**< not implemented yet */
	REDIRFS_FOP_SENDPAGE,		/**< not implemented yet */
	REDIRFS_FOP_GET_UNMAPPED_AREA,	/**< not implemented yet */
	REDIRFS_FOP_CHECK_FLAGS,	/**< not implemented yet */
	REDIRFS_FOP_DIR_NOTIFY,		/**< not implemented yet */
	REDIRFS_FOP_FLOCK,		/**< not implemented yet */
	REDIRFS_FOP_END			/**< end mark for file operations*/
};

/**
 * Dentry operations identifiers.
 */
enum redirfs_dop {
	REDIRFS_DOP_REVALIDATE,		/**< not implemented yet */
	REDIRFS_DOP_HASH,		/**< not implemented yet */
	REDIRFS_DOP_COMPARE,		/**< not implemented yet */
	REDIRFS_DOP_DELETE,		/**< not implemented yet */
	REDIRFS_DOP_RELEASE,		/**< not implemented yet */
	REDIRFS_DOP_IPUT,		/**< release the dentry's inode */
	REDIRFS_DOP_END			/**< end mark for dentry operations*/
};

/**
 * Callback function return values.
 */
enum redirfs_retv {
	REDIRFS_RETV_STOP,		/**< stop calling other Filters */
	REDIRFS_RETV_CONTINUE		/**< call next filter in a chain */
};

/**
 * Callback type identifiers.
 */
enum redirfs_call_type{
	REDIRFS_PRECALL,		/**< pre callback identifier */
	REDIRFS_POSTCALL		/**< post callback identifier */
};

typedef void* redirfs_filter;		/**< Filter's handler */
typedef void* redirfs_context;		/**< callback operation context - reserved for future use */

/**
 * Native filesystem calls arguments.
 *
 * This union contains paramters for all native filesystem calls.
 */
union redirfs_op_args_t {
	struct {
		struct inode			*parent;	/**< parent inode */
		struct dentry			*dentry;	/**< dentry name of new file */
		int				mode;		/**< mode for new file */
		struct nameidata		*nd;		/**< path_lookup result*/
	} i_create;						/**< create function arguments */
	
	struct {
		struct inode			*parent;	/**< parent inode */
		struct dentry			*dentry;	/**< searched dentry name */
		struct nameidata		*nd;		/**< path_lookup result */
	} i_lookup;						/**< lookup function arguments */

	struct {
		struct dentry			*old_dentry;
		struct inode			*inode;
		struct dentry			*new_dentry;
	} i_link;						/**< not implemented yet */

	struct {
		struct inode			*dir;		/**< directory inode */
		struct dentry			*dentry;	/**< dentry to remove */
	} i_unlink;						/**< unlink function arguments */

	struct {
		struct inode			*dir;
		struct dentry			*dentry;
		const char			*symname;
	} i_symlink;						/**< not implemented yet */

	struct {
		struct inode			*parent;	/**< parent inode */
		struct dentry			*dentry;	/**< dentry name of new directory */
		int 				mode;		/**< mode for new directory */
	} i_mkdir;						/**< mkdir function arguments */

	struct {
		struct inode			*dir;		/**< directory inode */
		struct dentry			*dentry;	/**< dentry to remove */
	} i_rmdir;						/**< rmdir function arguments */

	struct {
		struct inode			*dir;
		struct dentry			*dentry;
		dev_t				rdev;
	} i_mknod;						/**< not implemented yet */

	struct {
		struct inode			*old_dir;
		struct dentry			*old_dentry;
		struct inode			*new_dir;
		struct dentry			*new_dentry;
	} i_rename;						/**< not implemented yet */

	struct {
		struct dentry			*dentry;
		char __user			*buffer;
		int				size;
	} i_readlink;						/**< not implemented yet */

	struct {
		struct dentry			*dentry;
		struct nameidata		*nd;
	} i_follow_link;					/**< not implemented yet */

	struct {
		struct dentry			*dentry;
		struct nameidata		*nd;
	} i_put_link;						/**< not implemented yet */

	struct {
		struct inode			*inode;
	} i_truncate;						/**< not implemented yet */

	struct {
		struct inode			*inode;		/**< inode for permissions check */
		int				mode;		/**< which permissions to check */
		struct nameidata		*nd;		/**< path_lookup result */
	} i_permission;						/**< permission function arguments */

	struct {
		struct dentry			*dentry;
		struct iattr			*iattr;
	} i_setattr;						/**< not implemented yet */

	struct {
		struct vfsmount			*vfsmount;
		struct dentry			*dentry;
		struct kstat			*kstat;
	} i_getattr;						/**< not implemented yet */

	struct {
		struct dentry			*dentry;
		const char			*name;
		const void			*value;
		size_t				size;
		int				flags;
	} i_setxattr;						/**< not implemented yet */

	struct {
		struct dentry			*dentry;
		const char			*name;
		void				*value;
		size_t				size;
	} i_getxattr;						/**< not implemented yet */

	struct {
		struct dentry			*dentry;
		char				*buffer;
		size_t				size;
	} i_listxattr;						/**< not implemented yet */
	
	struct {
		struct dentry			*dentry;
		const char			*name;
	} i_removexttr;						/**< not implemented yet */



	struct {
		struct file			*file;
		loff_t				offset;
		int				origin;
	} f_llseek;						/**< not implemented yet */

	struct {
		struct file			*file;
		char __user			*buffer;
		size_t				count;
		loff_t				*pos;
	} f_read;						/**< not implemented yet */

	struct {
		struct kiocb			*kiocb;
		char __user			*buffer;
		size_t				cound;
		loff_t				pos;
	} f_aio_read;						/**< not implemented yet */

	struct {
		struct file			*file;
		const char __user		*buffer;
		size_t				count;
		loff_t				*pos;
	} f_write;						/**< not implemented yet */

	struct {
		struct kiocb			*kiocb;
		const char __user		*buffer;
		size_t				cound;
		loff_t				pos;
	} f_aio_write;						/**< not implemented yet */

	struct {
		struct file			*file;
		void				*dirent;
		filldir_t			filldir;
	} f_readdir;						/**< not implemented yet */

	struct {
		struct file			*file;
		struct poll_table_struct	*poll_table;
	} f_poll;						/**< not implemented yet */

	struct {
		struct inode			*inode;
		struct file			*file;
		unsigned int			cmd;
		unsigned long			arg;
	} f_ioctl;						/**< not implemented yet */

	struct {
		struct file			*file;
		struct vm_area_struct		*vm_area;
	} f_mmap;						/**< not implemented yet */

	struct {
		struct inode			*inode;		/**< file's inode */
		struct file			*file;		/**< new file object */
	} f_open;						/**< open function arguments */

	struct {
		struct file			*file;		/**< file object */
	} f_flush;						/**< flush function arguments */

	struct {
		struct inode			*inode;		/**< file's inode */
		struct file			*file;		/**< file object to release */
	} f_release;						/**< release function arguments */

	struct {
		struct file			*file;
		struct dentry			*dentry;
		int				datasync;
	} f_fsync;						/**< not implemented yet */

	struct {
		struct kiocb			*kiocb;
		int				datasync;
	} f_aio_fsync;						/**< not implemented yet */

	struct {
		int				fd;
		struct file			*file;
		int				on;
	} f_fasync;						/**< not implemented yet */

	struct {
		struct file			*file;
		int				cmd;
		struct file_lock		*lock;
	} f_lock;						/**< not implemented yet */

	struct {
		struct file			*file;
		const struct iovec __user	*vec;
		unsigned long			vlen;
		loff_t				*pos;
	} f_readv;						/**< not implemented yet */

	struct {
		struct file			*file;
		const struct iovec __user	*vec;
		unsigned long			vlen;
		loff_t				*pos;
	} f_writev;						/**< not implemented yet */

	struct {
		struct file			*file;
		loff_t				*ppos;
		size_t				cound;
		read_actor_t			actor;
		void				*target;
	} f_sendfile;						/**< not implemented yet */

	struct {
		struct file			*file;
		struct page			*page;
		int				offset;
		size_t				size;
		loff_t				*ppos;
		int				more;
	} f_sendpage;						/**< not implemented yet */

	struct {
		struct file			*file;
		unsigned long			addr;
		unsigned long			len;
		unsigned long			pgoff;
		unsigned long			flags;
	} f_get_unmapped_area;					/**< not implemented yet */

	struct {
		int				flags;
	} f_check_flags;					/**< not implemented yet */

	struct {
		struct file			*file;
		unsigned long			arg;
	} f_dir_notify;						/**< not implemented yet */

	struct {
		struct file			*file;
		int				flags;
		struct file_lock		*lock;
	} f_flock;						/**< not implemented yet */



	struct {
		struct dentry			*dentry;
		struct nameidata		*nd;
	} d_revalidate;						/**< not implemented yet */

	struct {
		struct dentry			*dentry;
		struct qstr			*name;
	} d_hash;						/**< not implemented yet */

	struct {
		struct dentry			*dentry;
		struct qstr			*name1;
		struct qstr			*name2;
	} d_compare;						/**< not implemented yet */

	struct {
		struct dentry			*dentry;
	} d_delete;						/**< not implemented yet */

	struct {
		struct dentry			*dentry;
	} d_release;						/**< not implemented yet */

	struct {
		struct dentry			*dentry;	/**< released dentry */
		struct inode			*inode;		/**< released inode */
	} d_iput;						/**< d_iput function arguments */
};

/**
 * Native filesystem calls return values.
 *
 * This is an union of all data types which can be returned by all native
 * filesystem calls. Filter can change return value of native filesytem
 * call via this union.
 */
union redirfs_op_retv_t {
	int		rv_int;
	ssize_t		rv_ssize;
	unsigned int	rv_uint;
	unsigned long	rv_ulong;
	loff_t		rv_loff;
	struct dentry	*rv_dentry;
};

/**
 * Extra info.
 *
 * Contains extra information for Filters.
 */
struct redirfs_op_exts_t{
	const char* full_path; /**< full path to the dentry object or NULL */
};

/**
 * Callback function information.
 *
 * This structure contains information about callback function. Filter can register only
 * one callback function for several native filesystem calls and then use this information
 * to distinguish between these calls.
 */
struct redirfs_op_info_t {
	enum redirfs_op_type type;	/**< type of operations identifier */
	int op;				/**< operation identifier */
	enum redirfs_call_type call;	/**< pre or post callback identifier */
};

/**
 * Callback function arguments.
 *
 * This structure contains all information passed to the Filter's callback function.
 */
struct redirfs_args_t {
	union redirfs_op_args_t		args; /**< native filesystem call arguments */
	struct redirfs_op_exts_t	exts; /**< extra info from the  RedirFS Framework */
	union redirfs_op_retv_t		retv; /**< return value from native filesystem call */
	struct redirfs_op_info_t	info; /**< callback function information */
};

/**
 * Used to register pre or post callback function for one native filesystem
 * call.
 *
 * This is used by the redirfs_set_operations function to set, reset or remove
 * pre and post callback functions for native filesystem calls. Every native filesystem
 * operation is indentified by group and operations identifier.
 */
struct redirfs_op_t {
	enum redirfs_op_type type;								/**< type of operations identifier */
	int op;											/**< operation identifier */ 
	enum redirfs_retv (*pre_op)(redirfs_context context, struct redirfs_args_t *args);	/**< pointer to the Filter's pre callback function or NULL */
	enum redirfs_retv (*post_op)(redirfs_context context, struct redirfs_args_t *args);	/**< pointer to the Filter's post callback function or NULL */
};

/**
 * Registers a new Filter to the RedirFS Framework.
 *
 * This is the first function which has to be called. Its return value is a
 * Filter's handler which has to be used in all others functions to identify
 * Filter.
 *
 * @param name Filter's name is used in debug and /proc info.
 * @param priority Filter's priority is a unique number determining Filter's
 * position in the Filter chain. RedirFS Framework allows to register one or
 * more Filters. The priority is used to determine order in which registered
 * Filters will be called.
 * @param flags Reserved for future use.
 *
 * @retval handler Handler to the new Filter.
 * @retval REDIRFS_ERR_EXIST Filter with selected priority is already registered.
 * @retval REDIRFS_ERR_INVAL Invalid Filter's name (NULL).
 * @retval REDIRFS_ERR_NOMEM Kernel out of memory.
 *
 * @note Use the IS_ERR and PTR_ERR macro to check the return value for error.
 */
redirfs_filter	redirfs_register_filter(const char *name, int priority, unsigned long flags);

/**
 * Unregisters a Filter from the RedirFS Framework.
 *
 * Removes all paths included or excluded by Filter and completely removes
 * Filter from the RedirFS Framework.
 *
 * @param filter Filter's handler
 *
 * @retval REDIRFS_NO_ERR Filter was successfully unregistered.
 * @retval REDIRFS_ERR_INVAL Invalid Filter's handler(NULL).
 */
int 		redirfs_unregister_filter(redirfs_filter filter);

/**
 * Activates Filter.
 *
 * If a Filter is already activated nothing happens.
 * Filter is by default deactivated so this function has to be called at
 * the beginnig, otherwise the Filter will not be called by the RedirFS
 * Framework.
 *
 * @param filter Filter's handler
 *
 * @retval REDIRFS_NO_ERR Filter was successfully activated.
 * @retval REDIRFS_ERR_INVAL Invalid Filter's handler(NULL).
 */
int		redirfs_activate_filter(redirfs_filter filter);

/**
 * Deactivates Filter.
 *
 * Deactivating Filter means that the Filter will not be called by the
 * RedirFS Framework but it will be still registered and can be anytime again
 * activated by the redirfs_activate_filter function.
 *
 * @param filter Filter's Handler.
 *
 * @retval REDIRFS_NO_ERR Filter was successfully deactivated.
 * @retval REDIRFS_ERR_INVAL Invalid Filter's handler(NULL).
 */
int		redirfs_deactivate_filter(redirfs_filter filter);

/**
 * Sets, resets or removes Filter's operations.
 *
 * If the Filter does not have defined selected pre or post callback function the new
 * function from the ops is set. If the Filter has already defined selected pre or post
 * callback function it will be replaced with the new function from ops. If the
 * Filter has already defined selected pre or post callback function and function in ops
 * is set to NULL the function will be removed.
 *
 * @param filter Filter's handler.
 * @param ops Array of pre and post callback functions.
 *
 * @retval REDIRFS_NO_ERR Operations successfully set.
 * @retval REDIRFS_ERR_INVAL Invalid Filter's handler(NULL) or invalid ops(NULL).
 */
int		redirfs_set_operations(redirfs_filter filter, struct redirfs_op_t ops[]);

/**
 * Includes path.
 *
 * With this function a Filter can select a path for which its pre and post
 * callback functions will be called. This function has to be called for
 * each path which the Filter wants to include.
 *
 * @param filter Filter's handler.
 * @param path Path to include.
 *
 * @retval REDIRFS_NO_ERR Path successfully included.
 * @retval REDIRFS_ERR_INVAL Invalid Filter's handler(NULL) or invalid path(NULL).
 * @retval REDIRFS_ERR_NOMEM Kernel out of memory.
 * @retval REDIRFS_ERR_NOTDIR Selected path is not a directory.
 * @retval REDIRFS_ERR_PATHNOTFOUND Selected path not found(path_lookup failed).
 */
int 		redirfs_include_path(redirfs_filter filter, const char *path);

/**
 * Excludes path.
 *
 * With this function a Filter can select a path for which its pre and post
 * callback functions will not be called. This function has to be called for
 * each path which the Filter wants to exclude. The excluded path has to be part
 * of some previously included path. Filter is not able to exclude a path if it
 * is not a part of a path previously included by Filter.
 *
 * @param filter Filter's handler.
 * @param path Path to exclude.
 *
 * @retval REDIRFS_NO_ERR Path successfully exluded.
 * @retval REDIRFS_ERR_INVAL Invalid Filter's handler(NULL) or invalid path(NULL).
 * @retval REDIRFS_ERR_NOMEM Kernel out of memory.
 * @retval REDIRFS_ERR_NOTDIR Selected path is not a directory.
 * @retval REDIRFS_ERR_NOENT Selected path not found(path_lookup failed).
 * @retval REDIRFS_ERR_NOTATTACHED Selected path cannot be excluded because it
 * is not a part of any previously included path. You can not exclude something
 * that was not included previously.
 */
int 		redirfs_exclude_path(redirfs_filter filter, const char *path);

/*@}*/

#endif
