/*-
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * Copyright (c) 2013, 2014 Mellanox Technologies, Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef	_LINUX_COMPLETION_H_
#define	_LINUX_COMPLETION_H_

#include <linux/_linuxkpi_shim.h>

#include <linux/errno.h>

struct completion {
	unsigned int done;
};

#define	INIT_COMPLETION(c) \
	((c).done = 0)
#define	init_completion(c) \
	((c)->done = 0)
#define	complete(c)				\
	complete_common((c), 0)
#define	complete_all(c)				\
	complete_common((c), 1)
#define	wait_for_completion(c)			\
	wait_for_common((c), 0)
#define	wait_for_completion_interuptible(c)	\
	wait_for_common((c), 1)
#define	wait_for_completion_timeout(c, timeout)	\
	wait_for_timeout_common((c), (timeout), 0)
#define	wait_for_completion_interruptible_timeout(c, timeout)	\
	wait_for_timeout_common((c), (timeout), 1)

#define complete_common LINUXKPI_PREFIXED_SYM(complete_common)
void complete_common(struct completion *, int);
#define wait_for_common LINUXKPI_PREFIXED_SYM(wait_for_common)
long wait_for_common(struct completion *, int);
#define wait_for_timeout_common LINUXKPI_PREFIXED_SYM(wait_for_timeout_common)
long wait_for_timeout_common(struct completion *, long, int);
#define try_wait_for_completion LINUXKPI_PREFIXED_SYM(try_wait_for_completion)
int try_wait_for_completion(struct completion *);
#define completion_done LINUXKPI_PREFIXED_SYM(completion_done)
int completion_done(struct completion *);

#endif					/* _LINUX_COMPLETION_H_ */
