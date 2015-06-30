ADD_LINUXKPI_PREFIXED_SYM=	scripts/add-LINUXKPI_PREFIXED_SYM.cocci
ADD_INCLUDE_LINUXKPI_SHIM=	scripts/add-include-linuxkpi_shim.awk

all:
	for dir in common 3.*; do					\
	  if test ! -d $$dir; then					\
	    continue;							\
	  fi;								\
	  spatch -I $$dir/include -I ../..				\
	   --sp-file ${ADD_LINUXKPI_PREFIXED_SYM}			\
	   --in-place --include-headers					\
	   --dir $$dir/include;						\
	done
	for file in $$(find . -type f -name "*.h" \! -name "_linuxkpi_*"); do \
	  grep -q '_linuxkpi_shim.h' $$file ||				\
	  ((grep -q 'LINUXKPI_PREFIXED_SYM(' $$file &&			\
	    echo "HANDLING: $$file" &&					\
	    awk -f ${ADD_INCLUDE_LINUXKPI_SHIM} $$file			\
	    > $$file.include && mv $$file.include $$file) || :);	\
	done
