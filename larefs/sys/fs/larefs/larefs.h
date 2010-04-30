#ifndef __LAREFS_H__
#define __LAREFS_H__

#include <sys/tree.h>
#include <sys/mount.h>


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

struct lrfs_filter_chain {
	int 	count;
	int	active;
	RB_HEAD(lrfs_filtertree, lrfs_filter_info) head;
};

struct lrfs_filter_info {
	RB_ENTRY(lrfs_filter_info) node;	
	int 	active;
	int	order;
	char	*name;
	struct larefs_vop_vector reg_ops[LAREFS_BOTTOM];
};

struct larefs_filter_t {
	char 	*name;
	int	order;
	struct larefs_vop_vector *reg_ops;
	SLIST_ENTRY(larefs_filter_t) entry;
};

extern int larefs_register_filter(struct larefs_filter_t *);
extern int larefs_unregister_filter(struct larefs_filter_t *);

#endif
