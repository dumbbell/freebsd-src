#ifndef _LINUXAPI_HELPER_H
#define	_LINUXAPI_HELPER_H

#define	LINUXAPI_VERSION						\
    #LINUXAPI_VERSION_MAJOR "." #LINUXAPI_VERSION_MINOR

#define	LINUXAPI_VERSIONED_PREFIXED_SYM(sym, major, minor)		\
    linuxapi ## major ## minor ## _ ## sym

#endif /* !defined(_LINUXAPI_HELPER_H) */
