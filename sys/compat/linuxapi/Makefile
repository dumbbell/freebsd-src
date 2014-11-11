ADD_LINUXAPI_PREFIXED_SYM=	scripts/add-LINUXAPI_PREFIXED_SYM.cocci
ADD_INCLUDE_LINUXAPI_SHIM=	scripts/add-include-linuxapi_shim.awk

all:
	for dir in common 3.*; do					\
	  if test ! -d $$dir; then					\
	    continue;							\
	  fi;								\
	  spatch -I $$dir/include -I ../..				\
	   --sp-file ${ADD_LINUXAPI_PREFIXED_SYM}			\
	   --in-place --include-headers					\
	   --dir $$dir/include;						\
	done
	for file in $$(find . -type f -name "*.h" \! -name "_linuxapi_*"); do \
	  grep -q '_linuxapi_shim.h' $$file ||				\
	  ((grep -q 'LINUXAPI_PREFIXED_SYM(' $$file &&			\
	    echo "HANDLING: $$file" &&					\
	    awk -f ${ADD_INCLUDE_LINUXAPI_SHIM} $$file			\
	    > $$file.include && mv $$file.include $$file) || :);	\
	done
