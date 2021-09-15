from pwn import *
import os

#HOST = "209.182.235.203"
HOST = "172.20.10.2"
PORT = 1014

#context.log_level = 'debug'

io = remote(HOST, PORT)

file_size = os.path.getsize('./sandbox/exp')
io.sendlineafter("How many bytes is your executable?", f"{file_size}")

io.recvuntil("Give me the bytes:")

print("Sending")

with open("./sandbox/exp", "rb") as f:
    data = f.read()
    io.send(data)

io.interactive()
