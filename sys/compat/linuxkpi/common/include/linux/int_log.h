/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#ifndef	_LINUXKPI_LINUX_INT_LOG_H_
#define	_LINUXKPI_LINUX_INT_LOG_H_

static inline unsigned int
intlog10(uint32_t value)
{
	unsigned int log;

	if (value == 0)
		return (0);

	for (log = 1; value; value /= 10, ++log)
		continue;

	log--;

	/* The result is shifted left by 24 bits on Linux. */
	return (log << 24);
}

#endif /* _LINUXKPI_LINUX_INT_LOG_H__ */
