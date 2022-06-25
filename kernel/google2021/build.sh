#!/bin/bash

musl-gcc -static -o exp exp.c

mv exp initramfs
