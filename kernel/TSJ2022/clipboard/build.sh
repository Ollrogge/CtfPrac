#!/bin/bash
musl-gcc -static -o exp exp.c -lpthread
musl-gcc -static -o exp2 exp2.c
#gcc -static -o exp exp.c -lpthread
mv exp cpio_files/home/tsj
mv exp2 cpio_files/home/tsj
