#!/bin/bash
#
musl-gcc -static -o exp exp.c
musl-gcc -static -o exp2 exp2.c
musl-gcc -static -o exp3 exp3.c

if [[ -d ./cpio_files ]]; then
    cp exp ./cpio_files/home/ctf
    cp exp2 ./cpio_files/home/ctf
    cp exp3 ./cpio_files/home/ctf
fi
