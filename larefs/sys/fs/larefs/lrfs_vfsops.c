/*-
 * Copyright (c) 1992, 1993, 1995
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
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/vnode.h>

#include <fs/larefs/lrfs.h>

static MALLOC_DEFINE(M_LRFSMNT, "lrfs_mount", "LRFS mount structure");

static vfs_fhtovp_t	lrfs_fhtovp;
static vfs_mount_t	lrfs_mount;
static vfs_quotactl_t	lrfs_quotactl;
static vfs_root_t	lrfs_root;
static vfs_sync_t	lrfs_sync;
static vfs_statfs_t	lrfs_statfs;
static vfs_unmount_t	lrfs_unmount;
static vfs_vget_t	lrfs_vget;
static vfs_extattrctl_t	lrfs_extattrctl;

static int
subdir(const char *p, const char *dir)
{
	int l;

	l = strlen(dir);
	if (l <= 1)
		return (1);

	if ((strncmp(p, dir, l) == 0) && (p[l] == '/' || p[l] == '\0'))
		return (1);

	return (0);
}

/*
 * Mount lrfs layer
 */
static int
lrfs_mount(struct mount *mp)
{
	int error = 0;
	struct vnode *lowerrootvp, *vp;
	struct vnode *lrfsm_rootvp;
	struct lrfs_mount *xmp;
	char *from, *from_free;
	int isvnunlocked = 0, len;
	struct nameidata nd, *ndp = &nd;

	LRFSDEBUG("lrfs_mount(mp = %p)\n", (void *)mp);

	if (mp->mnt_flag & MNT_ROOTFS)
		return (EOPNOTSUPP);
	/*
	 * Update is a no-op
	 */
	if (mp->mnt_flag & MNT_UPDATE) {
		/*
		 * Only support update mounts for NFS export.
		 */
		if (vfs_flagopt(mp->mnt_optnew, "export", NULL, 0))
			return (0);
		else
			return (EOPNOTSUPP);
	}

	/*
	 * Get argument
	 */
	error = vfs_getopt(mp->mnt_optnew, "from", (void **)&from, &len);
	if (error || from[len - 1] != '\0')
		return (EINVAL);

	/*
	 * Unlock lower node to avoid deadlock.
	 * (XXX) VOP_ISLOCKED is needed?
	 */
	if ((mp->mnt_vnodecovered->v_op == &lrfs_vnodeops) &&
		VOP_ISLOCKED(mp->mnt_vnodecovered)) {
		VOP_UNLOCK(mp->mnt_vnodecovered, 0);
		isvnunlocked = 1;
	}

	/*
	 * Find lower node
	 */
	NDINIT(ndp, LOOKUP, FOLLOW|LOCKLEAF, UIO_SYSSPACE, from, curthread);
	error = namei(ndp);


	if (error == 0) {
		from_free = NULL;
		error = vn_fullpath(curthread, ndp->ni_vp, &from,
		&from_free);
		if (error != 0)
			NDFREE(ndp, NDF_ONLY_PNBUF);
		else
			vfs_mountedfrom(mp, from);
		free(from_free, M_TEMP);
	}

	/*
	 * Re-lock vnode.
	 */
	if (isvnunlocked && !VOP_ISLOCKED(mp->mnt_vnodecovered))
		vn_lock(mp->mnt_vnodecovered, LK_EXCLUSIVE | LK_RETRY);

	if (error)
		return (error);
	NDFREE(ndp, NDF_ONLY_PNBUF);

	/*
	 * Sanity check on lower vnode
	 */
	lowerrootvp = ndp->ni_vp;

	/*
	* Check multi pefs mount to avoid `lock against myself' panic.
	*/
	if (lowerrootvp->v_mount->mnt_vfc == mp->mnt_vfc) {
		LRFSDEBUG("lrfs_mount: multi pefs mount\n");
		vput(lowerrootvp);
		return (EDEADLK);
	}

	/*
	* Check paths are not nested
	*/
	if ((lowerrootvp != mp->mnt_vnodecovered) &&
	    (subdir(mp->mnt_stat.f_mntfromname, mp->mnt_stat.f_mntonname) ||
	    subdir(mp->mnt_stat.f_mntonname, mp->mnt_stat.f_mntfromname))) {
		LRFSDEBUG("lrfs_mount: %s and %s are nested paths\n",
		mp->mnt_stat.f_mntfromname, mp->mnt_stat.f_mntonname);
		vput(lowerrootvp);
		return (EINVAL);
	}

	xmp = (struct lrfs_mount *) malloc(sizeof(struct lrfs_mount),
				M_LRFSMNT, M_WAITOK);	/* XXX */

	/*
	 * Save reference to underlying FS
	 */
	xmp->lrfsm_vfs = lowerrootvp->v_mount;

	/*
	 * Save reference.  Each mount also holds
	 * a reference on the root vnode.
	 */
	error = lrfs_nodeget(mp, lowerrootvp, &vp);
	/*
	 * Make sure the node alias worked
	 */
	if (error)
		goto ERROUT;

	/* 
	 * Initialize filter chain
	 */
	xmp->filter_chain = NULL;
	error = init_filter_chain(&xmp->filter_chain);
	if (error)
		goto ERROUT;

	/*
	 * Keep a held reference to the root vnode.
	 * It is vrele'd in lrfs_unmount.
	 */
	lrfsm_rootvp = vp;
	lrfsm_rootvp->v_vflag |= VV_ROOT;
	xmp->lrfsm_rootvp = lrfsm_rootvp;

	/*
	 * Unlock the node (either the lower or the alias)
	 */
	VOP_UNLOCK(vp, 0);

	if (LRFSVPTOLOWERVP(lrfsm_rootvp)->v_mount->mnt_flag & MNT_LOCAL) {
		MNT_ILOCK(mp);
		mp->mnt_flag |= MNT_LOCAL;
		MNT_IUNLOCK(mp);
	}
	MNT_ILOCK(mp);
	mp->mnt_kern_flag |= lowerrootvp->v_mount->mnt_kern_flag & MNTK_MPSAFE;
	MNT_IUNLOCK(mp);
	mp->mnt_data =  xmp;
	vfs_getnewfsid(mp);

	LRFSDEBUG("lrfs_mount: lower %s, alias at %s\n",
		mp->mnt_stat.f_mntfromname, mp->mnt_stat.f_mntonname);
	return (0);

ERROUT:
	VOP_UNLOCK(vp, 0);
	vrele(lowerrootvp);
	free(xmp, M_LRFSMNT);
	return (error);
}

/*
 * Free reference to lrfs layer
 */
static int
lrfs_unmount(mp, mntflags)
	struct mount *mp;
	int mntflags;
{
	struct lrfs_mount *mntdata;
	int error;
	int flags = 0;

	LRFSDEBUG("lrfs_unmount: mp = %p\n", (void *)mp);

	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;

	/* There is 1 extra root vnode reference (lrfsm_rootvp). */
	error = vflush(mp, 1, flags, curthread);
	if (error)
		return (error);

	/*
	 * Finally, throw away the lrfs_mount structure
	 */
	mntdata = MOUNTTOLRFSMOUNT(mp);
	
	free_filter_chain(mntdata->filter_chain);

	mp->mnt_data = 0;
	free(mntdata, M_LRFSMNT);
	return 0;
}

static int
lrfs_root(mp, flags, vpp)
	struct mount *mp;
	int flags;
	struct vnode **vpp;
{
	struct vnode *vp;

	LRFSDEBUG("lrfs_root(mp = %p, vp = %p->%p)\n", (void *)mp,
	    (void *)MOUNTTOLRFSMOUNT(mp)->lrfsm_rootvp,
	    (void *)LRFSVPTOLOWERVP(MOUNTTOLRFSMOUNT(mp)->lrfsm_rootvp));

	/*
	 * Return locked reference to root.
	 */
	vp = MOUNTTOLRFSMOUNT(mp)->lrfsm_rootvp;
	VREF(vp);

#ifdef LRFS_DEBUG
	if (VOP_ISLOCKED(vp))
		panic("root vnode is locked.\n");
#endif
	vn_lock(vp, flags | LK_RETRY);
	*vpp = vp;
	return 0;
}

static int
lrfs_quotactl(mp, cmd, uid, arg)
	struct mount *mp;
	int cmd;
	uid_t uid;
	void *arg;
{
	return VFS_QUOTACTL(MOUNTTOLRFSMOUNT(mp)->lrfsm_vfs, cmd, uid, arg);
}

static int
lrfs_statfs(mp, sbp)
	struct mount *mp;
	struct statfs *sbp;
{
	int error;
	struct statfs mstat;

	LRFSDEBUG("lrfs_statfs(mp = %p, vp = %p->%p)\n", (void *)mp,
	    (void *)MOUNTTOLRFSMOUNT(mp)->lrfsm_rootvp,
	    (void *)LRFSVPTOLOWERVP(MOUNTTOLRFSMOUNT(mp)->lrfsm_rootvp));

	bzero(&mstat, sizeof(mstat));

	error = VFS_STATFS(MOUNTTOLRFSMOUNT(mp)->lrfsm_vfs, &mstat);
	if (error)
		return (error);

	/* now copy across the "interesting" information and fake the rest */
	sbp->f_type = mstat.f_type;
	sbp->f_flags = mstat.f_flags;
	sbp->f_bsize = mstat.f_bsize;
	sbp->f_iosize = mstat.f_iosize;
	sbp->f_blocks = mstat.f_blocks;
	sbp->f_bfree = mstat.f_bfree;
	sbp->f_bavail = mstat.f_bavail;
	sbp->f_files = mstat.f_files;
	sbp->f_ffree = mstat.f_ffree;
	return (0);
}

static int
lrfs_sync(mp, waitfor)
	struct mount *mp;
	int waitfor;
{
	/*
	 * XXX - Assumes no data cached at lrfs layer.
	 */
	return (0);
}

static int
lrfs_vget(mp, ino, flags, vpp)
	struct mount *mp;
	ino_t ino;
	int flags;
	struct vnode **vpp;
{
	int error;
	error = VFS_VGET(MOUNTTOLRFSMOUNT(mp)->lrfsm_vfs, ino, flags, vpp);
	if (error)
		return (error);

	return (lrfs_nodeget(mp, *vpp, vpp));
}

static int
lrfs_fhtovp(mp, fidp, vpp)
	struct mount *mp;
	struct fid *fidp;
	struct vnode **vpp;
{
	int error;
	error = VFS_FHTOVP(MOUNTTOLRFSMOUNT(mp)->lrfsm_vfs, fidp, vpp);
	if (error)
		return (error);

	return (lrfs_nodeget(mp, *vpp, vpp));
}

static int
lrfs_extattrctl(mp, cmd, filename_vp, namespace, attrname)
	struct mount *mp;
	int cmd;
	struct vnode *filename_vp;
	int namespace;
	const char *attrname;
{
	return VFS_EXTATTRCTL(MOUNTTOLRFSMOUNT(mp)->lrfsm_vfs, cmd, filename_vp,
	    namespace, attrname);
}


static struct vfsops lrfs_vfsops = {
	.vfs_extattrctl =	lrfs_extattrctl,
	.vfs_fhtovp =		lrfs_fhtovp,
	.vfs_init =		lrfs_init,
	.vfs_mount =		lrfs_mount,
	.vfs_quotactl =		lrfs_quotactl,
	.vfs_root =		lrfs_root,
	.vfs_statfs =		lrfs_statfs,
	.vfs_sync =		lrfs_sync,
	.vfs_uninit =		lrfs_uninit,
	.vfs_unmount =		lrfs_unmount,
	.vfs_vget =		lrfs_vget,
};

VFS_SET(lrfs_vfsops, larefs, VFCF_LOOPBACK);
MODULE_VERSION(larefs, 1);
