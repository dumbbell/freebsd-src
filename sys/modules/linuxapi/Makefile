# $FreeBSD$

.PATH:	${.CURDIR}/../../compat/linuxapi/common/src	\
	${.CURDIR}/../../compat/linuxapi/3.15/src

KMOD=	linuxapi

# Code common to all Linux versions.
SRCS=	kmod.c		\
	rbtree.c

# Linux 3.15 and later.
SRCS+=	compat_3.15.c	\
	device_3.15.c	\
	idr_3.15.c	\
	kobject_3.15.c	\
	pci_3.15.c	\
	radix_3.15.c

SRCS+=	bus_if.h	\
	device_if.h	\
	pci_if.h	\
	vnode_if.h

CFLAGS  += -I${.IMPSRC:H:H}/include
CFLAGS  += -I${.CURDIR}/../../compat/linuxapi/common/include

CWARNFLAGS	+= -Wno-pointer-arith -Wno-pointer-sign

.include <bsd.kmod.mk>
