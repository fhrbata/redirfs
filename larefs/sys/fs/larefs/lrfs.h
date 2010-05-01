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
#ifndef __LRFS_H__
#define __LRFS_H__

#include <sys/tree.h>
#include <fs/larefs/larefs.h>

#define LRFS_DEBUG

struct lrfs_mount {
	struct mount	*lrfsm_vfs;
	struct vnode	*lrfsm_rootvp;	/* Reference to root lrfs_node */
	struct lrfs_filter_chain	*filter_chain;
};

#ifdef _KERNEL
/*
 * A cache of vnode references
 */
struct lrfs_node {
	LIST_ENTRY(lrfs_node)	lrfs_hash;	/* Hash list */
	struct vnode	        *lrfs_lowervp;	/* VREFed once */
	struct vnode		*lrfs_vnode;	/* Back pointer */
};

struct lrfs_filters {
	SLIST_HEAD(lrfs_filter_list, larefs_filter_t) head;
	int 	count;
};

struct lrfs_filter_chain {
	int     count;
	int     active;
	RB_HEAD(lrfs_filtertree, lrfs_filter_info) head;
};   

struct lrfs_filter_info {
	RB_ENTRY(lrfs_filter_info) 	node;	
	SLIST_ENTRY(lrfs_filter_info)	entry;
	struct larefs_filter_t		*filter;
	int 	active;
	int	priority;
	char	*name;
	struct vnode *avn;
	struct larefs_vop_vector reg_ops[LAREFS_BOTTOM];
};
#define	MOUNTTOLRFSMOUNT(mp) ((struct lrfs_mount *)((mp)->mnt_data))
#define	VTOLRFS(vp) ((struct lrfs_node *)(vp)->v_data)
#define	LRFSTOV(xp) ((xp)->lrfs_vnode)

int lrfs_init(struct vfsconf *vfsp);
int lrfs_uninit(struct vfsconf *vfsp);
int lrfs_nodeget(struct mount *mp, struct vnode *target, struct vnode **vpp);
void lrfs_hashrem(struct lrfs_node *xp);
int lrfs_bypass(struct vop_generic_args *ap);
int lrfs_proceed_oper(struct vop_generic_args *ap, int op_id);

/*
 * FIlter list handling prototypes
 */
int init_filter_list(struct lrfs_filters **);
int free_filter_list(struct lrfs_filters *);
struct larefs_filter_t *find_filter_inlist(const char *);

/*
 * Filter chain (rbtree) handling prototypes
 */
RB_PROTOTYPE(lrfs_filtertree, lrfs_filter_info, node,
	lrfs_filter_compare)

int init_filter_chain(struct lrfs_filter_chain **chain);
int free_filter_chain(struct lrfs_filter_chain *chain);
int attach_filter(struct larefs_filter_t *, struct vnode *, int);
int detach_filter(struct lrfs_filter_info *, struct lrfs_filter_chain *);
int toggle_filter_active(const char *, struct vnode *);

struct lrfs_filter_info *
find_filter_inchain(const char *, struct vnode *, struct lrfs_filter_chain **);

int change_flt_priority(struct lrfs_filter_info *,
		struct lrfs_filter_chain *, int );

int lrfs_precallbacks_chain(struct vop_generic_args *, int);
int lrfs_postcallbacks_chain(struct vop_generic_args *, int);

#ifdef DIAGNOSTIC
struct vnode *lrfs_checkvp(struct vnode *vp, char *fil, int lno);
#define	LRFSVPTOLOWERVP(vp) lrfs_checkvp((vp), __FILE__, __LINE__)
#else
#define	LRFSVPTOLOWERVP(vp) (VTOLRFS(vp)->lrfs_lowervp)
#endif

extern struct vop_vector lrfs_vnodeops;
extern struct lrfs_filters *registered_filters; 

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_LRFSNODE);
#endif

#ifdef LRFS_DEBUG
#define LRFSDEBUG(format, args...) printf(format ,## args)
#else
#define LRFSDEBUG(format, args...)
#endif /* LRFS_DEBUG */


#endif /* _KERNEL */
#endif /* _LRFS_H_ */
