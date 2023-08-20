#!/bin/bash

cd initramfs/
find . -print0 \
| cpio --null -ov --format=newc > ../my_rootfs.cpio
cd ../
