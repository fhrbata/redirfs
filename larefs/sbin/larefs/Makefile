# $FreeBSD$

SYS=    ${.CURDIR}/../../sys
CFLAGS+=-I${SYS}

PROG=	larefs
SRCS=	larefs.c

WARNS?=	6
DEBUG_FLAGS+= -g

NO_MAN=	noman

BINDIR?= /sbin

.include <bsd.prog.mk>
