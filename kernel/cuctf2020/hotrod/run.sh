#!/bin/sh

timeout --foreground 300 qemu-system-x86_64 \
    -s \
    -m 64M \
    -nographic \
    -kernel "./bzImage" \
    -append "console=ttyS0 quiet loglevel=3 oops=panic panic=-1 pti=on kaslr nosmap min_addr=4096" \
    -cpu qemu64,+smep \
    -monitor none \
    -initrd "./rootfs.cpio" \
    -no-reboot \
    -smp 2 \
    -smp cores=2 \
    -smp threads=1
