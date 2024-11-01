#!/bin/sh
qemu-system-x86_64 -s -initrd ./rootfs.cpio -kernel ./bzImage  -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' -monitor /dev/null -m 512M --nographic -smp cores=1,threads=1 -cpu kvm64,+smep,+smap
