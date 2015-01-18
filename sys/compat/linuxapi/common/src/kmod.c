/* $FreeBSD$ */
/*-
 * Copyright (c) 2015 Mellanox Technologies, Ltd.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>

MALLOC_DEFINE(M_IDR, "linuxapi_idr", "Linux IDR compat");
MALLOC_DEFINE(M_KMALLOC, "linuxapi_kmalloc", "Linux kmalloc compat");
MALLOC_DEFINE(M_RADIX, "linuxapi_radix", "Linux radix compat");

static int
linuxapi_mod_handler(module_t mod, int type, void *data)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		error = 0;
		break;
	case MOD_UNLOAD:
		error = 0;
		break;
	default:
		error = EINVAL;
	}

	return (error);
}

static moduledata_t linuxapi_mod = {
	"linuxapi", linuxapi_mod_handler, NULL
};

MODULE_VERSION(linuxapi, 1);
MODULE_DEPEND(linuxapi, pci, 1, 1, 1);
DECLARE_MODULE(linuxapi, linuxapi_mod, SI_SUB_DRIVERS, SI_ORDER_ANY);
