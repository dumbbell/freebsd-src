/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2013-2017 Mellanox Technologies, Ltd.
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#include <linux/rwsem.h>

void
linuxkpi_init_rwsem(struct rw_semaphore *rw, const char *name)
{
	memset(rw, 0, sizeof(*rw));
	sx_init_flags(&rw->sx, name, SX_NOWITNESS);
	/* `rw->waiters_count` is already zero. */
}

void
linuxkpi_down_write(struct rw_semaphore *rw)
{
	if (!sx_try_xlock(&rw->sx)) {
		/* `rw->waiters_count` is used by `rwsem_is_contended()`. */
		rw->waiters_count++;
		sx_xlock(&rw->sx);
		rw->waiters_count--;
	}
}

void
linuxkpi_up_write(struct rw_semaphore *rw)
{
	sx_xunlock(&rw->sx);
}

void
linuxkpi_down_read(struct rw_semaphore *rw)
{
	if (!sx_try_slock(&rw->sx)) {
		/* `rw->waiters_count` is used by `rwsem_is_contended()`. */
		rw->waiters_count++;
		sx_slock(&rw->sx);
		rw->waiters_count--;
	}
}

void
linuxkpi_up_read(struct rw_semaphore *rw)
{
	sx_sunlock(&rw->sx);
}
