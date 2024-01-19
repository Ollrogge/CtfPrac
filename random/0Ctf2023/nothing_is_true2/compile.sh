#!/bin/bash
#

nasm -f elf64 -o exp.o exp.nasm
#ld -m elf_x86_64 -T link.ld exp.o -o exp
gcc -o exp exp.o -T link.ld -nostdlib -no-pie -mcmodel=medium
