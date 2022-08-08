#!/bin/bash

musl-gcc -static -Os -o exp exp.c

# musl-gcc -static -Os

mv exp initramfs/home/ctf
