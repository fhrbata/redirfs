#ifndef __LAREFS_H__
#define __LAREFS_H__

#include <sys/tree.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/ioccom.h>

#define MAXFILTERNAME   255
#define larefs_prior_info	larefs_attach_info

enum filter_op_id {
	LAREFS_ACCESS,
	LAREFS_ACCESSX,
	LAREFS_GETATTR,
	LAREFS_GETWRITEMOUNT,
	LAREFS_INACTIVE,
	LAREFS_LOCK,
	LAREFS_LOOKUP,
	LAREFS_OPEN,
	LAREFS_PRINT,
	LAREFS_RECLAIM,
	LAREFS_RENAME,
	LAREFS_SETATTR,
	LAREFS_UNLOCK,
	LAREFS_VPTOCNP,
	LAREFS_VPTOFH,
	LAREFS_IOCTL,
	LAREFS_BOTTOM
};

struct larefs_vop_vector {
	enum filter_op_id op_id;
	int (*pre_cb)(struct vop_generic_args *ap);
	int (*post_cb)(struct vop_generic_args *ap);
};

struct larefs_filter_t {
	char 	*name;
	struct larefs_vop_vector *reg_ops;
	SLIST_ENTRY(larefs_filter_t) entry;
	SLIST_HEAD(used_filter_list, lrfs_filter_info) used;
};

struct larefs_attach_info {
	char name[MAXFILTERNAME];
	int priority;
};

extern int larefs_register_filter(struct larefs_filter_t *);
extern int larefs_unregister_filter(struct larefs_filter_t *);

#define LRFS_ATTACH	_IOW('L', 0, struct larefs_attach_info)	/* Attach filter */
#define LRFS_DETACH	_IOW('L', 1, char[MAXFILTERNAME])	/* Detach filter */
#define LRFS_TGLACT	_IOW('L', 2, char[MAXFILTERNAME])	/* Toggle active */
#define LRFS_CHPRIO	_IOW('L', 3, struct larefs_prior_info)	/* Change priority */

#endif
