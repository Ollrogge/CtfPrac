#!/bin/bash

stty intr ^]
qemu-system-x86_64 \
    -s \
    -kernel ./bzImage \
    -initrd ./initramfs.cpio.gz \
    -cpu qemu64,+smep,+smap \
    -m 256M \
    -append "console=ttyS0 oops=panic panic=1 quiet" \
    -monitor /dev/null \
    -nographic \
    -no-reboot
