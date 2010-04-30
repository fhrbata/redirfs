#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <machine/atomic.h>

#include <fs/larefs/larefs.h>
#include <fs/larefs/lrfs.h>

static MALLOC_DEFINE(M_LRFSCHAIN, "lrfs_filter_chain", "LRFS filter chain structure");
static MALLOC_DEFINE(M_LRFSFLTINFO, "lrfs_filter_info", "LRFS filter info structure");

static int
lrfs_filter_compare(struct lrfs_filter_info *fa,
	struct lrfs_filter_info *fb);
int
create_fltoper_vector(struct larefs_vop_vector *, 
	struct larefs_vop_vector *);

int
init_filter_chain(struct lrfs_filter_chain **chain) {
	struct lrfs_filter_chain *fchain;

	fchain = (struct lrfs_filter_chain *) 
		malloc(sizeof(struct lrfs_filter_chain),
		M_LRFSCHAIN, M_WAITOK);

	if (!fchain) {
		return (ENOMEM);
	}

	fchain->count = 0;
	fchain->active = 0;
	RB_INIT(&fchain->head);
	*chain =fchain;
	
	return 0;
}

int
free_filter_chain(struct lrfs_filter_chain *chain) 
{
	struct lrfs_filter_info *node, *next;
	
	for (node = RB_MIN(lrfs_filtertree, &chain->head);
		node; node = next) 
	{
		next = RB_NEXT(lrfs_filtertree, &chain->head, node);
		RB_REMOVE(lrfs_filtertree, &chain->head, node);
		free(node, M_LRFSFLTINFO);
	}

	free(chain, M_LRFSCHAIN);
	return (0);
}

int
create_fltoper_vector(struct larefs_vop_vector *old_v, 
	struct larefs_vop_vector *new_v)
{
	/* Is this necessatry ?? */
	for (int i = 0; i < LAREFS_BOTTOM; i++) {
		new_v[i].op_id = i; 
		new_v[i].pre_cb = VOP_NULL; 
		new_v[i].post_cb = VOP_NULL; 
	}
	
	for (int i = 0; (old_v[i].op_id != LAREFS_BOTTOM); i++) {
		new_v[old_v[i].op_id].pre_cb = old_v[i].pre_cb;
		new_v[old_v[i].op_id].post_cb = old_v[i].post_cb;
	}

	return (0);

}

int
attach_filter(const char *name, struct vnode *vn)
{
	struct larefs_filter_t *filter;
	struct lrfs_filter_info *new_info, *node;
	struct lrfs_mount *mntdata;
	struct lrfs_filter_chain *chain;

	if ((!name) || (!vn))
		return (EINVAL);
	mntdata = MOUNTTOLRFSMOUNT(vn->v_mount);
	chain = mntdata->filter_chain;

	filter = find_filter_byname(name);
	if (!filter)
		return (EINVAL);

	new_info = (struct lrfs_filter_info *)
		malloc(sizeof(struct lrfs_filter_info),
		M_LRFSFLTINFO, M_WAITOK);

	new_info->name = filter->name;
	new_info->active = 1;
	create_fltoper_vector(filter->reg_ops, new_info->reg_ops);

	/* Just debugging - REMOVE ME */
	for (int i = 0; i < LAREFS_BOTTOM; i++) {
		if (new_info->reg_ops[i].pre_cb != VOP_NULL) {
			uprintf("%d op. registered\n",i);
		}
	}
	/*	
	 * If there is a filter with the same priority, it returns pointer
	 * to that filter.
	 */
	node = RB_INSERT(lrfs_filtertree, &chain->head, new_info);
	if (node) {
		printf("Filter with the wame priority already exists in the chain\n");
		free(node, M_LRFSFLTINFO);
		return (EINVAL);
	}

	return (0);
}

int
detach_filter(const char *name, struct vnode *vn)
{
	struct lrfs_filter_info *node = NULL, *filter;
	struct lrfs_mount *mntdata;
	struct lrfs_filter_chain *chain;
	int len;

	if ((!name) || (!vn))
		return (EINVAL);
	mntdata = MOUNTTOLRFSMOUNT(vn->v_mount);
	chain = mntdata->filter_chain;
	
	/* Use strnlen instead !! - this includes setting filter max namelen */
	len = strlen(name);

	RB_FOREACH(filter, lrfs_filtertree , &chain->head) {
		if ((strncmp(filter->name, name, len) == 0) &&
			filter->name[len] == '\0')
		{
			node = filter;
			break;
		}
	}

	if (!node) {
		printf("Not such a filter in the chain\n");
		return (EINVAL);
	}

	filter = RB_REMOVE(lrfs_filtertree, &chain->head, node);
	if (!filter) {
		printf("Filter removal FAILS!\n");
		return (EINVAL);
	}

	free(node, M_LRFSFLTINFO);

	return (0);
}


static int
lrfs_filter_compare(struct lrfs_filter_info *fa,
	struct lrfs_filter_info *fb) 
{

	if (fa->order > fb->order)
		return (1);
	else if (fa->order < fb->order)
		return (-1);
	return (0);	
}

int
lrfs_precallbacks_chain(struct vop_generic_args *ap, int op_id)
{
	struct lrfs_filter_info *node;
	struct lrfs_mount *mntdata;
	struct lrfs_filter_chain *chain;
	struct vnodeop_desc *descp = ap->a_desc;
	int (*lrfs_fop)(struct vop_generic_args *ap);
	struct vnode **first_vp;
	int ret = 0;

	first_vp = VOPARG_OFFSETTO(struct vnode**, descp->vdesc_vp_offsets[0],ap);
	mntdata = MOUNTTOLRFSMOUNT((*first_vp)->v_mount);
	chain = mntdata->filter_chain;

	RB_FOREACH(node, lrfs_filtertree , &chain->head) {
		if (!atomic_load_acq_int(&node->active))
			continue;

		lrfs_fop = node->reg_ops[op_id].pre_cb;	

		/* Is this necessary ?? Evetything shloud be set */
		if (!lrfs_fop)
			continue;

		ret = lrfs_fop(ap);
	}

	return ret;
}

int
lrfs_postcallbacks_chain(struct vop_generic_args *ap, int op_id)
{
	struct lrfs_filter_info *node;
	struct lrfs_mount *mntdata;
	struct lrfs_filter_chain *chain;
	struct vnodeop_desc *descp = ap->a_desc;
	int (*lrfs_fop)(struct vop_generic_args *ap);
	struct vnode **first_vp;

	first_vp = VOPARG_OFFSETTO(struct vnode**, descp->vdesc_vp_offsets[0],ap);
	mntdata = MOUNTTOLRFSMOUNT((*first_vp)->v_mount);
	chain = mntdata->filter_chain;

	RB_FOREACH_REVERSE(node, lrfs_filtertree , &chain->head) {
		if (!atomic_load_acq_int(&node->active))
			continue;

		lrfs_fop = node->reg_ops[op_id].post_cb;

		/* Is this necessary ?? Evetything shloud be set */
		if (!lrfs_fop)
			continue;

		lrfs_fop(ap);
	}

	return (0);
}

RB_GENERATE(lrfs_filtertree, lrfs_filter_info, node,
    lrfs_filter_compare)
