#!/bin/bash

gcc -S exp.c -o exp.S -pthread
musl-gcc -static -Os exp.S -o exp

# musl-gcc -static -Os

#mv exp cpio_files
