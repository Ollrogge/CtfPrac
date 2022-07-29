#!/bin/bash

musl-gcc -static -I/usr/lib/musl/include/ -o exp exp.c

mv exp initramfs
