#!/bin/sh

qemu-system-x86_64 \
    -s \
    -m 256M \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio \
    -nographic \
    -cpu qemu64,+smep,-smap -smp cores=2 \
    -append "root=/dev/ram rw console=ttyS0 loglevel=2 oops=panic panic=1 nosmap init_on_alloc=0 init_on_free=0" \
    -monitor none \
    -no-reboot \
    -nodefaults -snapshot \
    -no-kvm \
    -chardev stdio,id=char0 -serial chardev:char0 \
    -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny
