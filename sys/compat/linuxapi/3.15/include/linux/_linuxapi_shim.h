#ifndef _LINUXAPI_SHIM_H
#define	_LINUXAPI_SHIM_H

#include <compat/linuxapi/common/include/linux/_linuxapi_helper.h>

#define	LINUXAPI_VERSION_MAJOR	3
#define	LINUXAPI_VERSION_MINOR	15

#define	LINUXAPI_PREFIXED_SYM_3_15(sym)	LINUXAPI_VERSIONED_PREFIXED_SYM(sym, 3, 15)
#define	LINUXAPI_PREFIXED_SYM(sym)	LINUXAPI_PREFIXED_SYM_3_15(sym)

#endif /* !defined(_LINUXAPI_SHIM_H) */
