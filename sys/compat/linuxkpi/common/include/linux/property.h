/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#ifndef	_LINUXKPI_LINUX_PROPERTY_H_
#define	_LINUXKPI_LINUX_PROPERTY_H_

#include <linux/args.h>
#include <linux/array_size.h>
#include <linux/bits.h>
#include <linux/cleanup.h>
#include <linux/fwnode.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/util_macros.h>

struct device;

static inline struct fwnode_handle *
dev_fwnode(struct device *dev)
{
	return (NULL);
}

#endif /* _LINUXKPI_LINUX_PROPERTY_H_ */
