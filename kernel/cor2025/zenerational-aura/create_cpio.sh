#!/bin/bash

cd ./cpio_files
find . | cpio --quiet -H newc -o | gzip -9 -n > ../initramfs.cpio.gz
cd -
