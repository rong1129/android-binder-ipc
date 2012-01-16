#!/bin/sh

echo >deps.h

SYMS="__lock_task_sighand get_files_struct put_files_struct unmap_kernel_range expand_files zap_page_range get_vm_area can_nice"
for sym in $SYMS; do 
	addr=`cat /proc/kallsyms | grep -Ee '^[0-9a-f]+ T '$sym'$' | sed -e 's/\s.*$//g'`
	if [ a$addr = 'a' ]; then
		echo "Error: can't find symbol $sym"
		exit 1
	fi

	name=`echo $sym | tr '[:lower:]' '[:upper:]'`
	echo "#define $name\t(void *)0x$addr" >> deps.h
done
