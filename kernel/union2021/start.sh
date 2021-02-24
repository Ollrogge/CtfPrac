#!/bin/sh

#cd /home/nutty
timeout --foreground 300 qemu-system-x86_64 \
	-s \
	-m 128 \
	-kernel bzImage \
	-nographic \
        -smp 1 \
        -cpu kvm64,+smep,+smap \
	-append "console=ttyS0 quiet kaslr" \
        -initrd my_initramfs.cpio \
	-monitor /dev/null \
