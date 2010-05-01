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
lrfs_filter_compare(struct lrfs_filter_info *, struct lrfs_filter_info *);
int
create_fltoper_vector(struct larefs_vop_vector *, struct larefs_vop_vector *);

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
	*chain = fchain;
	
	return 0;
}

int
free_filter_chain(struct lrfs_filter_chain *chain) 
{
	struct lrfs_filter_info *finfo, *next;
	
	for (finfo = RB_MIN(lrfs_filtertree, &chain->head);
		finfo; finfo = next) 
	{
		next = RB_NEXT(lrfs_filtertree, &chain->head, finfo);

		/* 
		 * Remove finfo from per-filter used list, per-mount
		 * rb tree, and free it.
		 */
		detach_filter(finfo, chain);
		KASSERT(finfo, ("Filter found in the used list , but not in the chain!!\n"));
	}

	free(chain, M_LRFSCHAIN);
	return (0);
}

int
create_fltoper_vector(struct larefs_vop_vector *old_v, 
	struct larefs_vop_vector *new_v)
{
	/* Set every operation to VOP_NULL */
	for (int i = 0; i < LAREFS_BOTTOM; i++) {
		new_v[i].op_id = i; 
		new_v[i].pre_cb = VOP_NULL; 
		new_v[i].post_cb = VOP_NULL; 
	}

	/* Set registered operations */	
	for (int i = 0; (old_v[i].op_id != LAREFS_BOTTOM); i++) {
		new_v[old_v[i].op_id].pre_cb = old_v[i].pre_cb;
		new_v[old_v[i].op_id].post_cb = old_v[i].post_cb;
	}

	return (0);

}

struct lrfs_filter_info *
find_filter_inchain(const char *name, struct vnode *vn,
	struct lrfs_filter_chain **ch)
{
	struct lrfs_mount *mntdata;
	struct lrfs_filter_info *finfo;
	struct lrfs_filter_chain *chain;
	int len;

	mntdata = MOUNTTOLRFSMOUNT(vn->v_mount);
	chain = mntdata->filter_chain;
	*ch = chain;

	/* Use strnlen instead !! - this includes setting filter max namelen */
	len = strlen(name);

	RB_FOREACH(finfo, lrfs_filtertree, &chain->head) {
		if ((strncmp(finfo->name, name, len) == 0) &&
		     finfo->name[len] == '\0')
			return finfo;
	}

	return NULL;	
}

int
attach_filter(struct larefs_filter_t *filter, struct vnode *vn, int prio)
{
	struct lrfs_filter_info *new_info, *node;
	struct lrfs_mount *mntdata;
	struct lrfs_filter_chain *chain;

	if ((!filter) || (!vn))
		return (EINVAL);

	LRFSDEBUG("Attaching filter %s to vnode %p with priority %d\n", 
		filter->name, (void *)vn, prio);

	mntdata = MOUNTTOLRFSMOUNT(vn->v_mount);
	chain = mntdata->filter_chain;

	new_info = (struct lrfs_filter_info *)
		malloc(sizeof(struct lrfs_filter_info),
		M_LRFSFLTINFO, M_WAITOK);

	new_info->filter = filter;
	new_info->active = 1;
	new_info->priority = prio;
	new_info->name = filter->name;
	new_info->avn = vn;
	create_fltoper_vector(filter->reg_ops, new_info->reg_ops);

	/* Lock ! */
		
	/*	
	 * If there is a filter with the same priority, it returns pointer
	 * to that filter.
	 */
	node = RB_INSERT(lrfs_filtertree, &chain->head, new_info);
	if (node) {
		LRFSDEBUG("Filter with the same priority is here : %s\n",
			node->name);
		free(new_info, M_LRFSFLTINFO);
		return (EINVAL);
	}

	/* Keep track of used info for the filter */
	SLIST_INSERT_HEAD(&filter->used, new_info, entry);
	
	/* Just debugging - REMOVE ME */
	for (int i = 0; i < LAREFS_BOTTOM; i++) {
		if (new_info->reg_ops[i].pre_cb != VOP_NULL) {
			uprintf("%d op. registered\n",i);
		}
	}


	return (0);
}

int
detach_filter(struct lrfs_filter_info *finfo, struct lrfs_filter_chain *chain)
{
	struct larefs_filter_t *filter;

	if ((!finfo) || (!chain)) {
		return (EINVAL);
	}

	LRFSDEBUG("Detaching filter %s\n", finfo->name);

	/* Remove info from filter used list */
	filter = finfo->filter;
	SLIST_REMOVE(&filter->used, finfo, lrfs_filter_info, entry);
	
	/* Remove info from chain */
	if (!RB_REMOVE(lrfs_filtertree, &chain->head, finfo)) {
		printf("Removing filter %s FAILS! This is a BUG!\n",
			finfo->name);
		return (EINVAL);
	}

	free(finfo, M_LRFSFLTINFO);

	return (0);
}

int
toggle_filter_active(const char *name, struct vnode *vn) {
	struct lrfs_filter_info *finfo;
	struct lrfs_filter_chain *chain;

	if ((!name) || (!vn))
		return (EINVAL);

	LRFSDEBUG("Toggle activity of filter %s\n", name);

	finfo = find_filter_inchain(name, vn, &chain);
	if (!finfo) {
		LRFSDEBUG("There is no such a filter: %s\n", name);
		return (EINVAL);
	}

	/* lock the node */
	if (finfo->active) {
		finfo->active = 0;
		LRFSDEBUG("Filter %s is now inactive\n", finfo->name);
	} else {
		finfo->active = 1;
		LRFSDEBUG("Filter %s is now active\n", finfo->name);
	}
	/* unlock the node */

	return (0);
}

int
change_flt_priority(struct lrfs_filter_info *finfo, 
	struct lrfs_filter_chain *chain, int prio)
{
	struct lrfs_filter_info *node;
	int old_prio;

	if ((!finfo) || (!chain)) {
		return (EINVAL);
	}

	LRFSDEBUG("Change priority of filter %s ant vnode %p from %d to %d\n", 
		finfo->name, (void *)finfo->avn, finfo->priority, prio);

	if (prio == finfo->priority)
		return (0);

	/* Locks rbtree */

	if (!RB_REMOVE(lrfs_filtertree, &chain->head, finfo)) {
		printf("Removing filter %s FAILS! This is a BUG!\n",
			finfo->name);
		return (EINVAL);
	}
	
	old_prio = finfo->priority;
	finfo->priority = prio;

	node = RB_INSERT(lrfs_filtertree, &chain->head, finfo);
	if (node) {
		LRFSDEBUG("Filter with the same priority is here : %s\n",
			node->name);
		goto REWIND;
	}

	/* Unlock rbtree */

	return (0);
REWIND:
	/* Set old priority and get filter back */
	finfo->priority = old_prio;
	node = RB_INSERT(lrfs_filtertree, &chain->head, finfo);
	if (node) {
		printf("Can not insert filter back! This should not happend!!\n");
	}
	/* Unlock rbtree */
	return (EINVAL);
}


static int
lrfs_filter_compare(struct lrfs_filter_info *fa,
	struct lrfs_filter_info *fb) 
{

	if (fa->priority > fb->priority)
		return (1);
	else if (fa->priority < fb->priority)
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

		lrfs_fop(ap);
	}

	return (0);
}

RB_GENERATE(lrfs_filtertree, lrfs_filter_info, node,
    lrfs_filter_compare)
