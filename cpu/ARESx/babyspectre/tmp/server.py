#!/usr/bin/python3
import sys
import os
import uuid

def make_executable(path):
    mode = os.stat(path).st_mode
    mode |= (mode & 0o444) >> 2    # copy R bits to X
    os.chmod(path, mode)

size = int(input("How many bytes is your executable? "))
print("Give me the bytes:")
sys.stdout.flush()
exe = bytearray()
while len(exe) < size:
    r = sys.stdin.buffer.read(size)
    exe.extend(r)
exe = exe[:size]

fname = str(uuid.uuid4())
os.chdir("sandbox")
with open(fname, "wb") as f:
    f.write(exe)
make_executable(fname)

os.execlp("./lottery", "./lottery", "./"+fname)
