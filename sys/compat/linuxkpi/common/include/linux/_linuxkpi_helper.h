#ifndef _LINUXKPI_HELPER_H
#define	_LINUXKPI_HELPER_H

#define	LINUXKPI_VERSION						\
    #LINUXKPI_VERSION_MAJOR "." #LINUXKPI_VERSION_MINOR

#define	LINUXKPI_VERSIONED_PREFIXED_SYM(sym, major, minor)		\
    linuxkpi ## major ## minor ## _ ## sym

#endif /* !defined(_LINUXKPI_HELPER_H) */
