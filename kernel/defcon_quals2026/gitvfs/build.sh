#!/bin/bash
#

musl-gcc -static -pthread exp.c -o exp
gcc -masm=intel -static exp_qemu.c -o exp_qemu
musl-gcc -static -pthread exp1.c -o exp1
musl-gcc -static -pthread exp2.c -o exp2

if [[ -d cpio_files ]]; then
    cp exp cpio_files
    cp exp1 cpio_files
    cp exp2 cpio_files
    cp exp_qemu cpio_files
fi
