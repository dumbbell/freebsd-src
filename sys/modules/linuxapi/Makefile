# $FreeBSD$

.PATH:	${.CURDIR}/../../compat/linuxapi/common/src	\
	${.CURDIR}/../../compat/linuxapi/3.15/src

KMOD=	linuxapi

SRCS=	kmod.c		\
	compat.c	\
	device.c	\
	idr.c		\
	kobject.c	\
	radix.c		\
	rbtree.c

SRCS+=	bus_if.h	\
	device_if.h	\
	vnode_if.h

CFLAGS  += -I${.IMPSRC:H:H}/include
CFLAGS  += -I${.CURDIR}/../../compat/linuxapi/common/include

CWARNFLAGS	+= -Wno-pointer-arith -Wno-pointer-sign

.include <bsd.kmod.mk>
