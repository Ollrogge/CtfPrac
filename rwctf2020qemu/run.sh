#!/bin/sh
#Using to build docker environment
#export LD_LIBRARY_PATH=/lib/x86_64-linux-gnu/pulseaudio
#gdb -x cmds --args qemu-system-x86_64
gdb -x cmds --args qemu-system-x86_64 -L ./dependency -kernel ./vmlinuz-5.4.0-58-generic -initrd ./own_rootfs.cpio -cpu kvm64,+smep \
	-m 64M \
	-monitor none \
	-device fun \
	-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \
	-nographic 

