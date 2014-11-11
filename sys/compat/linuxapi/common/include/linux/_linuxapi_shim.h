#ifndef _LINUXAPI_SHIM_H
#define	_LINUXAPI_SHIM_H

#include <compat/linuxapi/common/include/linux/_linuxapi_helper.h>

#define	LINUXAPI_VERSION_MAJOR	0
#define	LINUXAPI_VERSION_MINOR	0

#define	LINUXAPI_PREFIXED_SYM(sym)	linuxapi ## _ ## sym

#endif /* !defined(_LINUXAPI_SHIM_H) */
