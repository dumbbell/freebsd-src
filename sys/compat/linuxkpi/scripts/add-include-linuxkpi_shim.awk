#!/usr/bin/awk -f

BEGIN {
	empty_line = 0;
}

/^#ifndef/ {
	id = $2;
}
/^#define/ {
	print;
	if (id && id == $2 && !include_added) {
		print "";
		print "#include <linux/_linuxkpi_shim.h>";
		include_added = 1;
	}
	next;
}
{
	print;
}
