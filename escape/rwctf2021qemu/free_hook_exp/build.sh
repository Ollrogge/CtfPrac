#!/bin/sh
rm -f ../cpio_files/exp
#diet gcc -o ../cpio_files/exp exploit.c || exit 1
gcc -static -s -Os -o ../cpio_files/exp exploit.c || exit 1
