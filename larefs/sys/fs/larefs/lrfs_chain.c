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
change_flt_priority(struct lrfs_filter_info *, struct lrfs_filter_chain *, int);

/*
 * Initialize filter chain. It is called when mounting larefs
 * thus no lock needed here.
 */
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
	sx_init(&fchain->chainlck, "lrfs_chain");
	RB_INIT(&fchain->head);
	*chain = fchain;
	
	return 0;
}

/*
 * Free filter chain. It is called when umounting larefs.
 */
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
		sx_slock(&chain->chainlck);
		detach_filter(finfo, chain);
		sx_sunlock(&chain->chainlck);

		KASSERT(finfo, ("Filter found in the used list , but not in the chain!!\n"));
	}

	sx_destroy(&chain->chainlck);
	free(chain, M_LRFSCHAIN);
	return (0);
}

/*
 * Generate vop_vector of registered operations for finfo.
 */
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
		if (old_v[i].pre_cb) {
			new_v[old_v[i].op_id].pre_cb = old_v[i].pre_cb;
		}
		if (old_v[i].post_cb) {
			new_v[old_v[i].op_id].post_cb = old_v[i].post_cb;
		}
	}

	return (0);
}

/*
 * Find filter info in the chain. Should be called under shared lock on chain
 */
struct lrfs_filter_info *
get_finfo_byname(const char *name, struct lrfs_filter_chain *chain)
{
	struct lrfs_filter_info *finfo;
	int len;

	len = strlen(name);

	RB_FOREACH(finfo, lrfs_filtertree, &chain->head) {
		if ((strncmp(finfo->name, name, len) == 0) &&
		     finfo->name[len] == '\0')
		{
			return finfo;
		}
	}

	return NULL;	
}

/*
 * Attach existing registered filter into the vnode's mp chain
 */
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

	/* Initialize new finfo */
	new_info->filter = filter;
	new_info->active = 1;
	new_info->priority = prio;
	new_info->name = filter->name;
	new_info->avn = vn;
	create_fltoper_vector(filter->reg_ops, new_info->reg_ops);

	/*	
	 * If there is a finfo with the same priority, it returns pointer
	 * to that finfo - new finfo can not be inserted.
	 */
	sx_xlock(&chain->chainlck);
	node = RB_INSERT(lrfs_filtertree, &chain->head, new_info);
	if (node) {
		LRFSDEBUG("Filter with the same priority is here : %s\n",
			node->name);
		sx_xunlock(&chain->chainlck);
		free(new_info, M_LRFSFLTINFO);
		return (EINVAL);
	}

	chain->count++;

	/* Keep track of used finfo for the filter */
	mtx_lock(&filter->fltmtx);
	filter->usecount++;
	SLIST_INSERT_HEAD(&filter->used, new_info, entry);
	mtx_unlock(&filter->fltmtx);

	sx_xunlock(&chain->chainlck);
	
	/* Just debugging - REMOVE ME */
	for (int i = 0; i < LAREFS_BOTTOM; i++) {
		if (new_info->reg_ops[i].pre_cb != VOP_NULL) {
			uprintf("%d op. registered\n",i);
		}
	}

	return (0);
}

/*
 * Find chain for vnode's mp, get shared lock on that chain
 * find finfo in the chain and detach it.
 */
int
try_detach_filter(const char *name, struct vnode *vn)
{
	struct lrfs_filter_info *finfo;
	struct lrfs_filter_chain *chain;
	int err = 0;

	chain = LRFSGETCHAIN(vn);
	
	sx_slock(&chain->chainlck);
	
	finfo = get_finfo_byname(name, chain);
	if (!finfo) {
		sx_sunlock(&chain->chainlck);
		return (EINVAL);
	}

	err = detach_filter(finfo, chain);
	sx_sunlock(&chain->chainlck);

	return (err);	
}

/*
 * Remove finfo from the chain. Should be called under shared lock on chain.
 */
int
detach_filter(struct lrfs_filter_info *finfo, struct lrfs_filter_chain *chain)
{
	struct larefs_filter_t *filter;
	struct lrfs_filter_info *node;

	if ((!finfo) || (!chain)) {
		return (EINVAL);
	}

	LRFSDEBUG("Detaching filter %s\n", finfo->name);

	/* Acquire exclusive chain lock */
	if (!sx_try_upgrade(&chain->chainlck)) {
		sx_sunlock(&chain->chainlck);
		sx_xlock(&chain->chainlck);
	}

	/* Remove info from chain */
	node = RB_REMOVE(lrfs_filtertree, &chain->head, finfo);
	if (!node) {
		printf("Removing filter %s FAILS! This is a BUG!\n",
			finfo->name);
		sx_downgrade(&chain->chainlck);
		return (EINVAL);
	}
	
	chain->count--;
	filter = finfo->filter;

	/* Remove info from filter used list */
	mtx_lock(&filter->fltmtx);
	filter->usecount--;
	SLIST_REMOVE(&filter->used, finfo, lrfs_filter_info, entry);
	free(finfo, M_LRFSFLTINFO);
	mtx_unlock(&filter->fltmtx);

	sx_downgrade(&chain->chainlck);

	return (0);
}

/*
 * Set filter active/inactive based on its immediate state
 */
int
toggle_filter_active(const char *name, struct vnode *vn) {
	struct lrfs_filter_info *finfo;
	struct lrfs_filter_chain *chain;

	if ((!name) || (!vn))
		return (EINVAL);
	
	LRFSDEBUG("Toggle activity of filter %s\n", name);

	chain = LRFSGETCHAIN(vn);

	sx_slock(&chain->chainlck);
	finfo = get_finfo_byname(name, chain);
	if (!finfo) {
		LRFSDEBUG("There is no such a filter: %s\n", name);
		sx_sunlock(&chain->chainlck);
		return (EINVAL);
	}
	
	/* Acquire exclusive chain lock */
	if (!sx_try_upgrade(&chain->chainlck)) {
		sx_sunlock(&chain->chainlck);
		sx_xlock(&chain->chainlck);
	}

	/* 
	 * Can I do this with atomic operations ???!!!
	 */
	if (finfo->active) {
		finfo->active = 0;
		LRFSDEBUG("Filter %s is now inactive\n", finfo->name);
	} else {
		finfo->active = 1;
		LRFSDEBUG("Filter %s is now active\n", finfo->name);
	}
	sx_xunlock(&chain->chainlck);

	return (0);
}

/*
 * Find finfo in the vnode's mp chain. Acquire shared lock to tha chain
 * and call change_flt_priority to change finfo's priority.
 */
int
try_change_fltpriority(struct larefs_prior_info *pinfo, struct vnode *vn)
{
	struct lrfs_filter_chain *chain;
	struct lrfs_filter_info *finfo;
	int err;

	chain = LRFSGETCHAIN(vn);
	
	sx_slock(&chain->chainlck);

	finfo = get_finfo_byname(pinfo->name, chain);
	if (!finfo) {
		sx_sunlock(&chain->chainlck);
		return (EINVAL);
	}

	err = change_flt_priority(finfo, chain, pinfo->priority);
	sx_sunlock(&chain->chainlck);

	return (0);
}

/*
 * Change filter's priority in particular chain. Should be called
 * with shared chain lock held.
 */
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

	/* Acquire exclusive chain lock */
	if (!sx_try_upgrade(&chain->chainlck)) {
		sx_sunlock(&chain->chainlck);
		sx_xlock(&chain->chainlck);
	}

	node = RB_REMOVE(lrfs_filtertree, &chain->head, finfo);
	if (!node) {
		printf("Removing filter %s FAILS! This is a BUG!\n",
			finfo->name);
		sx_downgrade(&chain->chainlck);
		return (EINVAL);
	}
	
	/* Store old priority in case when inserting fails */	
	old_prio = finfo->priority;
	finfo->priority = prio;
	
	/* 
	 * Store finfo with new priority back into the chain,
	 * when it fails, insert finfo with old priority back 
	 */
	node = RB_INSERT(lrfs_filtertree, &chain->head, finfo);
	if (node) {
		LRFSDEBUG("Filter with the same priority is here : %s\n",
			node->name);
		goto REWIND;
	}

	sx_downgrade(&chain->chainlck);
	return (0);
REWIND:
	/* Set old priority and get filter back */
	finfo->priority = old_prio;
	node = RB_INSERT(lrfs_filtertree, &chain->head, finfo);
	if (node) { 
		/* Since we have chain locked this should NOT happend */
		printf("Can not insert filter back! This should NOT happend!!\n");
	}

	sx_downgrade(&chain->chainlck);
	return (EINVAL);
}

/*
 * Compare two finfos by priority. Used as rbtree cmp function
 */
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

/*
 * Walk through the chain calling apropriate filte's pre operations
 * This should be called with shared chain lock held.
 */
int
lrfs_precallbacks_chain(struct vop_generic_args *ap,
	struct lrfs_filter_chain *chain, int op_id)
{
	struct lrfs_filter_info *node;
	flt_cb_t *lrfs_fop;
	int count = 0;
	
	RB_FOREACH(node, lrfs_filtertree , &chain->head) {
		count++;

		if (!node->active)
			continue;

		lrfs_fop = node->reg_ops[op_id].pre_cb;	

		if (lrfs_fop(node->data, ap) == LAREFS_STOP);
			break;
	}

	return count;
}

/*
 * Walk through the chain calling apropriate filte's post operations
 * This should be called with shared chain lock held.
 */
int
lrfs_postcallbacks_chain(struct vop_generic_args *ap,
	struct lrfs_filter_chain *chain, int op_id, int skip)
{
	struct lrfs_filter_info *node;
	flt_cb_t *lrfs_fop;

	RB_FOREACH_REVERSE(node, lrfs_filtertree , &chain->head) {
		if (skip != 0) {
			skip--;
			continue;
		}

		if (!node->active)
			continue;

		lrfs_fop = node->reg_ops[op_id].post_cb;

		lrfs_fop(node->data, ap);
	}

	return (0);
}

/* Generate rb tree functions for chain tree */
RB_GENERATE(lrfs_filtertree, lrfs_filter_info, node,
    lrfs_filter_compare)
