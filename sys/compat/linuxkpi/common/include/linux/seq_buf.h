/*-
 * Copyright (c) 2025 The FreeBSD Foundation
 * Copyright (c) 2025 Jean-Sébastien Pédron <dumbbell@FreeBSD.org>
 *
 * This software was developed by Jean-Sébastien Pédron under sponsorship
 * from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#ifndef _LINUXKPI_LINUX_SEQ_BUF_H_
#define	_LINUXKPI_LINUX_SEQ_BUF_H_

#include <linux/bug.h>
#include <linux/minmax.h>
#include <linux/seq_file.h>
#include <linux/types.h>

struct seq_buf {
	char	*buffer;
	size_t	 size;
	size_t	 len;
};

#define DECLARE_SEQ_BUF(NAME, SIZE)			\
	struct seq_buf NAME = {				\
		.buffer = (char[SIZE]) { 0 },		\
		.size = SIZE,				\
	}

static inline void
seq_buf_clear(struct seq_buf *s)
{
	s->len = 0;
	if (s->size > 0)
		s->buffer[0] = '\0';
}

static inline bool
seq_buf_has_overflowed(struct seq_buf *s)
{
	return (s->len > s->size);
}

static inline bool
seq_buf_buffer_left(struct seq_buf *s)
{
	if (seq_buf_has_overflowed(s))
		return (0);

	return (s->size - s->len);
}

#define	seq_buf_init(s, buf, size) lkpi_seq_buf_init((s), (buf), (size))
void lkpi_seq_buf_init(struct seq_buf *s, char *buf, unsigned int size);

#define	seq_buf_printf(s, f, ...) lkpi_seq_buf_printf((s), (f), __VA_ARGS__)
int lkpi_seq_buf_printf(struct seq_buf *s, const char *fmt, ...) \
    __printflike(2, 3);

#define	seq_buf_vprintf(s, f, a) lkpi_seq_buf_vprintf((s), (f), (a))
int lkpi_seq_buf_vprintf(struct seq_buf *s, const char *fmt, va_list args);

#define	seq_buf_str(s) lkpi_seq_buf_str((s))
const char * lkpi_seq_buf_str(struct seq_buf *s);

#endif /* defined(_LINUXKPI_LINUX_SEQ_BUF_H_) */
