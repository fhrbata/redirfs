/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software donated to Berkeley by
 * Jan-Simon Pendry.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This software was derived form nullfs implementation in FreeBSD-8
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/vnode.h>

#include <fs/larefs/lrfs.h>
#include <fs/larefs/larefs.h>

#define LOG2_SIZEVNODE 8		/* log2(sizeof struct vnode) */
#define	NLRFSNODECACHE 16

/*
 * Null layer cache:
 * Each cache entry holds a reference to the lower vnode
 * along with a pointer to the alias vnode.  When an
 * entry is added the lower vnode is VREF'd.  When the
 * alias is removed the lower vnode is vrele'd.
 */

#define	LRFS_NHASH(vp) \
	(&lrfs_node_hashtbl[(((uintptr_t)vp)>>LOG2_SIZEVNODE) & lrfs_node_hash])

static LIST_HEAD(lrfs_node_hashhead, lrfs_node) *lrfs_node_hashtbl;
static u_long lrfs_node_hash;
struct mtx lrfs_hashmtx;

static MALLOC_DEFINE(M_LRFSHASH, "lrfs_hash", "LRFS hash table");
MALLOC_DEFINE(M_LRFSNODE, "lrfs_node", "LRFS vnode private part");

static struct vnode * lrfs_hashget(struct mount *, struct vnode *);
static struct vnode * lrfs_hashins(struct mount *, struct lrfs_node *);
struct lrfs_filters *registered_filters;

/*
 * Initialise cache headers
 */
int
lrfs_init(vfsp)
	struct vfsconf *vfsp;
{
	LRFSDEBUG("lrfs_init\n");		/* printed during system boot */

	init_filter_list(&registered_filters);

	lrfs_node_hashtbl = hashinit(NLRFSNODECACHE, M_LRFSHASH, &lrfs_node_hash);
	mtx_init(&lrfs_hashmtx, "lrfshs", NULL, MTX_DEF);

	return (0);
}

int
lrfs_uninit(vfsp)
	struct vfsconf *vfsp;
{
	mtx_destroy(&lrfs_hashmtx);
	free(lrfs_node_hashtbl, M_LRFSHASH);
	free_filter_list(registered_filters);
	return (0);
}

/*
 * Return a VREF'ed alias for lower vnode if already exists, else 0.
 * Lower vnode should be locked on entry and will be left locked on exit.
 */
static struct vnode *
lrfs_hashget(mp, lowervp)
	struct mount *mp;
	struct vnode *lowervp;
{
	struct lrfs_node_hashhead *hd;
	struct lrfs_node *a;
	struct vnode *vp;

	ASSERT_VOP_LOCKED(lowervp, "lrfs_hashget");

	/*
	 * Find hash base, and then search the (two-way) linked
	 * list looking for a lrfs_node structure which is referencing
	 * the lower vnode.  If found, the increment the lrfs_node
	 * reference count (but NOT the lower vnode's VREF counter).
	 */
	hd = LRFS_NHASH(lowervp);
	mtx_lock(&lrfs_hashmtx);
	LIST_FOREACH(a, hd, lrfs_hash) {
		if (a->lrfs_lowervp == lowervp && LRFSTOV(a)->v_mount == mp) {
			/*
			 * Since we have the lower node locked the lrfs
			 * node can not be in the process of recycling.  If
			 * it had been recycled before we grabed the lower
			 * lock it would not have been found on the hash.
			 */
			vp = LRFSTOV(a);
			vref(vp);
			mtx_unlock(&lrfs_hashmtx);
			return (vp);
		}
	}
	mtx_unlock(&lrfs_hashmtx);
	return (NULLVP);
}

/*
 * Act like lrfs_hashget, but add passed lrfs_node to hash if no existing
 * node found.
 */
static struct vnode *
lrfs_hashins(mp, xp)
	struct mount *mp;
	struct lrfs_node *xp;
{
	struct lrfs_node_hashhead *hd;
	struct lrfs_node *oxp;
	struct vnode *ovp;

	hd = LRFS_NHASH(xp->lrfs_lowervp);
	mtx_lock(&lrfs_hashmtx);
	LIST_FOREACH(oxp, hd, lrfs_hash) {
		if (oxp->lrfs_lowervp == xp->lrfs_lowervp &&
		    LRFSTOV(oxp)->v_mount == mp) {
			/*
			 * See lrfs_hashget for a description of this
			 * operation.
			 */
			ovp = LRFSTOV(oxp);
			vref(ovp);
			mtx_unlock(&lrfs_hashmtx);
			return (ovp);
		}
	}
	LIST_INSERT_HEAD(hd, xp, lrfs_hash);
	mtx_unlock(&lrfs_hashmtx);
	return (NULLVP);
}

static void
lrfs_insmntque_dtr(struct vnode *vp, void *xp)
{
	vp->v_data = NULL;
	vp->v_vnlock = &vp->v_lock;
	free(xp, M_LRFSNODE);
	vp->v_op = &dead_vnodeops;
	(void) vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	vgone(vp);
	vput(vp);
}

/*
 * Make a new or get existing lrfs node.
 * Vp is the alias vnode, lowervp is the lower vnode.
 * 
 * The lowervp assumed to be locked and having "spare" reference. This routine
 * vrele lowervp if lrfs node was taken from hash. Otherwise it "transfers"
 * the caller's "spare" reference to created lrfs vnode.
 */
int
lrfs_nodeget(mp, lowervp, vpp)
	struct mount *mp;
	struct vnode *lowervp;
	struct vnode **vpp;
{
	struct lrfs_node *xp;
	struct vnode *vp;
	int error;

	/* Lookup the hash firstly */
	*vpp = lrfs_hashget(mp, lowervp);
	if (*vpp != NULL) {
		vrele(lowervp);
		return (0);
	}

	/*
	 * We do not serialize vnode creation, instead we will check for
	 * duplicates later, when adding new vnode to hash.
	 *
	 * Note that duplicate can only appear in hash if the lowervp is
	 * locked LK_SHARED.
	 */

	/*
	 * Do the MALLOC before the getnewvnode since doing so afterward
	 * might cause a bogus v_data pointer to get dereferenced
	 * elsewhere if MALLOC should block.
	 */
	xp = malloc(sizeof(struct lrfs_node),
	    M_LRFSNODE, M_WAITOK);

	error = getnewvnode("lrfs", mp, &lrfs_vnodeops, &vp);
	if (error) {
		free(xp, M_LRFSNODE);
		return (error);
	}

	xp->lrfs_vnode = vp;
	xp->lrfs_lowervp = lowervp;
	vp->v_type = lowervp->v_type;
	vp->v_data = xp;
	vp->v_vnlock = lowervp->v_vnlock;
	if (vp->v_vnlock == NULL)
		panic("lrfs_nodeget: Passed a NULL vnlock.\n");
	error = insmntque1(vp, mp, lrfs_insmntque_dtr, xp);
	if (error != 0)
		return (error);
	/*
	 * Atomically insert our new node into the hash or vget existing 
	 * if someone else has beaten us to it.
	 */
	*vpp = lrfs_hashins(mp, xp);
	if (*vpp != NULL) {
		vrele(lowervp);
		vp->v_vnlock = &vp->v_lock;
		xp->lrfs_lowervp = NULL;
		vrele(vp);
		return (0);
	}
	*vpp = vp;

	return (0);
}

/*
 * Remove node from hash.
 */
void
lrfs_hashrem(xp)
	struct lrfs_node *xp;
{

	mtx_lock(&lrfs_hashmtx);
	LIST_REMOVE(xp, lrfs_hash);
	mtx_unlock(&lrfs_hashmtx);
}

#ifdef DIAGNOSTIC

struct vnode *
lrfs_checkvp(vp, fil, lno)
	struct vnode *vp;
	char *fil;
	int lno;
{
	struct lrfs_node *a = VTOLRFS(vp);

#ifdef notyet
	/*
	 * Can't do this check because vop_reclaim runs
	 * with a funny vop vector.
	 */
	if (vp->v_op != lrfs_vnodeop_p) {
		printf ("lrfs_checkvp: on non-lrfs-node\n");
		panic("lrfs_checkvp");
	}
#endif
	if (a->lrfs_lowervp == NULLVP) {
		/* Should never happen */
		int i; u_long *p;
		printf("vp = %p, ZERO ptr\n", (void *)vp);
		for (p = (u_long *) a, i = 0; i < 8; i++)
			printf(" %lx", p[i]);
		printf("\n");
		panic("lrfs_checkvp");
	}
	VI_LOCK_FLAGS(a->lrfs_lowervp, MTX_DUPOK);
	if (a->lrfs_lowervp->v_usecount < 1) {
		int i; u_long *p;
		printf("vp = %p, unref'ed lowervp\n", (void *)vp);
		for (p = (u_long *) a, i = 0; i < 8; i++)
			printf(" %lx", p[i]);
		printf("\n");
		panic ("lrfs with unref'ed lowervp");
	}
	VI_UNLOCK(a->lrfs_lowervp);
#ifdef notyet
	printf("lrfs %x/%d -> %x/%d [%s, %d]\n",
	        LRFSTOV(a), vrefcnt(LRFSTOV(a)),
		a->lrfs_lowervp, vrefcnt(a->lrfs_lowervp),
		fil, lno);
#endif
	return (a->lrfs_lowervp);
}
#endif
