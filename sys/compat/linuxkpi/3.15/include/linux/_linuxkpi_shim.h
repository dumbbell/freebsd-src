#ifndef _LINUXKPI_SHIM_H
#define	_LINUXKPI_SHIM_H

#include <compat/linuxkpi/common/include/linux/_linuxkpi_helper.h>

#define	LINUXKPI_VERSION_MAJOR	3
#define	LINUXKPI_VERSION_MINOR	15

#define	LINUXKPI_PREFIXED_SYM(sym)	LINUXKPI_VERSIONED_PREFIXED_SYM(sym, 3, 15)

#endif /* !defined(_LINUXKPI_SHIM_H) */
