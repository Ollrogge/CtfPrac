#!/bin/sh
timeout --foreground 300 qemu-system-x86_64 \
        -s \
        -m 64M \
        -nographic \
        -kernel bzImage \
        -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on nokaslr" \
        -no-reboot \
        -cpu kvm64,+smap,+smep \
        -smp 1 \
        -monitor /dev/null \
        -initrd my_rootfs.cpio \
        -net nic,model=virtio \
        -net user
