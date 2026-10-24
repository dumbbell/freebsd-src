/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2016 Kip Macy
 * Copyright (c) 2018 Johannes Lundberg
 */

#ifndef _LINUXKPI_LINUX_BITS_H_
#define	_LINUXKPI_LINUX_BITS_H_

#include <linux/bitops.h>

#define	GENMASK(h, l)		(((~0UL) >> (BITS_PER_LONG - (h) - 1)) & ((~0UL) << (l)))
#define	GENMASK_ULL(h, l)	(((~0ULL) >> (BITS_PER_LONG_LONG - (h) - 1)) & ((~0ULL) << (l)))

#define	GENMASK_TYPE(type, h, l)	((type)(GENMASK_ULL(h, l)))

#define	GENMASK_U8(h, l)	GENMASK_TYPE(u8, h, l)
#define	GENMASK_U16(h, l)	GENMASK_TYPE(u16, h, l)
#define	GENMASK_U32(h, l)	GENMASK_TYPE(u32, h, l)
#define	GENMASK_U64(h, l)	GENMASK_TYPE(u64, h, l)

#define	BIT_TYPE(type, nr)	((type)(BIT_ULL(nr)))

#define	BIT_U8(nr)		BIT_TYPE(u8, nr)
#define	BIT_U16(nr)		BIT_TYPE(u16, nr)
#define	BIT_U32(nr)		BIT_TYPE(u32, nr)
#define	BIT_U64(nr)		BIT_TYPE(u64, nr)

#endif /* _LINUXKPI_LINUX_BITS_H_ */
