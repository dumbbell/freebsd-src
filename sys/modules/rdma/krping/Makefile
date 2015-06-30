# $FreeBSD$

RDMA= ${.CURDIR}/../../../contrib/rdma/krping
.PATH: ${RDMA}

KMOD= krping
SRCS= krping.c krping_dev.c getopt.c
SRCS+=  bus_if.h device_if.h pci_if.h pcib_if.h vnode_if.h
SRCS+=  opt_sched.h opt_inet.h opt_inet6.h
CFLAGS+= -I${.CURDIR}/../../../ofed/include
CFLAGS+= -I${.CURDIR}/../../../compat/linuxkpi/3.15/include -I${.CURDIR}/../../../compat/linuxkpi/common/include

.include <bsd.kmod.mk>
