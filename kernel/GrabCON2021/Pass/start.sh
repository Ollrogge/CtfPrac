#!/bin/sh

qemu-system-x86_64 \
	-s \
	-m 256M \
	-kernel ./bzImage \
	-initrd ./initramfs.cpio \
       	-nographic \
	-append "kpti=1 +smep +smap kaslr root=/dev/ram rw console=ttyS0 oops=panic paneic=1 quiet" \
	-monitor /dev/null \


