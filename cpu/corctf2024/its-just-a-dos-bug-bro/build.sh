#!/bin/bash

musl-gcc -masm=intel -static -o exp exp.c
#gcc -masm=intel -static -s -O2 -msse2 -o exp exp.c

cp exp cpio_files/home/ctf

#gcc -D_FILE_OFFSET_BITS=64 -o fusefs fusefs.c -lkeyutils -L$PWD `pkg-config fuse --static --cflags --libs`
#cp fusefs cpio_files/home/note
