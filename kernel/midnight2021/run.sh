#!/bin/bash
qemu-system-x86_64 \
    -s \
    -m 128M \
    -kernel ./kernel \
    -initrd ./my_initrd \
    -nographic \
    -monitor /dev/null \
    -append "nokaslr root=/dev/ram rw console=ttyS0 oops=panic paneic=1 quiet"
