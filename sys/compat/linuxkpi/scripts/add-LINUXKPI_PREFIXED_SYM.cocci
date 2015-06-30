@r@
identifier func;
@@

 #define	func	LINUXKPI_PREFIXED_SYM(func)

@s1 disable optional_storage@
identifier r.func;
position p;
@@

 func@p(...) {...}

@disable optional_storage@
identifier func;
position p != s1.p;
@@

+#define	func	LINUXKPI_PREFIXED_SYM(func)
 func@p(...) { ... }

@s2 disable optional_storage@
type ret;
identifier r.func;
position p;
@@

 ret func@p(...);

@disable optional_storage@
type ret;
identifier func;
position p != s2.p;
@@

+#define	func	LINUXKPI_PREFIXED_SYM(func)
 ret func@p(...);
