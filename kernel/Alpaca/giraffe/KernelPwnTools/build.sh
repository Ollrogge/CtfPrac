#!/bin/bash
#
musl-gcc -static -o exp exp.c

if [[ -d ../cpio_files ]]; then
    cp exp ../cpio_files
fi
