/*-
 * Copyright (c) 2024-2025 The FreeBSD Foundation
 * Copyright (c) 2024-2025 Jean-Sébastien Pédron <dumbbell@FreeBSD.org>
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

#include <linux/seq_buf.h>
 
void
lkpi_seq_buf_init(struct seq_buf *s, char *buf, unsigned int size)
{
	s->buffer = buf;
	s->size = size;

	seq_buf_clear(s);
}
 
int
lkpi_seq_buf_printf(struct seq_buf *s, const char *fmt, ...)
{
	int ret;
	va_list args;

	va_start(args, fmt);
	ret = seq_buf_vprintf(s, fmt, args);
	va_end(args);

	return (ret);
}
 
int
lkpi_seq_buf_vprintf(struct seq_buf *s, const char *fmt, va_list args)
{
	int ret;

	ret = vsnprintf(s->buffer, s->size, fmt, args);
	if (ret >= 0)
		s->len = ret;

	return (ret);
}

const char *
lkpi_seq_buf_str(struct seq_buf *s)
{
	if (s->size == 0)
		return ("");

	if (seq_buf_buffer_left(s))
		s->buffer[s->len] = '\0';
	else
		s->buffer[s->size - 1] = '\0';

	return (s->buffer);
}
