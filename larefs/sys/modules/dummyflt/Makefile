# $FreeBSD$

.PATH:	${.CURDIR}/../../filters/dummyflt

KMOD=	dummyflt
SRCS=	dummyflt.c

SRCS+=	vnode_if.h

DEBUG_FLAGS+= -g
#DEBUG_FLAGS+= -DPEFS_DEBUG
#DEBUG_FLAGS+= -DPEFS_DEBUG_EXTRA

CFLAGS+= -I${.CURDIR}/../../

.include <bsd.kmod.mk>

