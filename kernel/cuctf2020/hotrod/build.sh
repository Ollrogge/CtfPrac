#!/bin/bash
musl-gcc -I/usr/lib/musl/include/ -static -o exp exp.c
mv exp cpio_files/
