# $FreeBSD$
.PATH:  ${.CURDIR}/../../ofed/drivers/infiniband/hw/mlx4

KMOD=	mlx4ib
SRCS=	device_if.h bus_if.h vnode_if.h pci_if.h \
	opt_inet.h opt_inet6.h \
	alias_GUID.c mcg.c sysfs.c ah.c cq.c \
	doorbell.c mad.c main.c mr.c qp.c srq.c wc.c cm.c

CFLAGS+= -I${.CURDIR}/../../ofed/drivers/infiniband/hw/mlx4
CFLAGS+= -I${.CURDIR}/../../ofed/include/
CFLAGS+= -I${.CURDIR}/../../compat/linuxapi/3.15/include -I${.CURDIR}/../../compat/linuxapi/common/include
CFLAGS+= -DCONFIG_INFINIBAND_USER_MEM
CFLAGS+= -DINET6 -DINET
CFLAGS+= -fms-extensions

.include <bsd.kmod.mk>

CFLAGS+= -Wno-cast-qual -Wno-pointer-arith ${GCC_MS_EXTENSIONS}
