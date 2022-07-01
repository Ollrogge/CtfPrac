from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')

print(shellcraft.sh())
sc = asm(shellcraft.sh())

print(sc)

final = []
for i in range(0, len(sc), 0x8):
    tmp = sc[i:i+8]
    tmp = u64(tmp)
    final.append(p64(tmp, endian="big").hex())

for x in final:
    print("0x"+x + ",")

print("")
