# $FreeBSD$

.PATH:	${.CURDIR}/../../dev/larefsdev/

KMOD=	larefsdev
SRCS=	larefsdev.c


DEBUG_FLAGS+= -g
#DEBUG_FLAGS+= -DPEFS_DEBUG
#DEBUG_FLAGS+= -DPEFS_DEBUG_EXTRA

CFLAGS+= -I${.CURDIR}/../../

.include <bsd.kmod.mk>

