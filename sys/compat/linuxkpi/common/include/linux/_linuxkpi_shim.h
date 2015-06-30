#ifndef _LINUXKPI_SHIM_H
#define	_LINUXKPI_SHIM_H

#include <compat/linuxkpi/common/include/linux/_linuxkpi_helper.h>

#define	LINUXKPI_VERSION_MAJOR	0
#define	LINUXKPI_VERSION_MINOR	0

#define	LINUXKPI_PREFIXED_SYM(sym)	linuxkpi ## _ ## sym

#endif /* !defined(_LINUXKPI_SHIM_H) */
