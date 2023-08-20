#!/bin/bash

musl-gcc -static -o exp exp.c

sudo mv exp initramfs
