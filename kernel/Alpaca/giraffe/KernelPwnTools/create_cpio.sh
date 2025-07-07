#!/bin/bash

cd ../cpio_files
find . -print0 | cpio --null -ov --format=newc > ../rootfs_exp.cpio
cd -
