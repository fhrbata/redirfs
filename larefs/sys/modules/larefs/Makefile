# $FreeBSD$

.PATH:	${.CURDIR}/../../fs/larefs

KMOD=	larefs
SRCS=	vnode_if.h \
	lrfs_subr.c lrfs_vfsops.c lrfs_vnops.c \
	lrfs_chain.c lrfs_flt.c

DEBUG_FLAGS+= -g
#DEBUG_FLAGS+= -DPEFS_DEBUG
#DEBUG_FLAGS+= -DPEFS_DEBUG_EXTRA

CFLAGS+= -I${.CURDIR}/../../

.include <bsd.kmod.mk>

