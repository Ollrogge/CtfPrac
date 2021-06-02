
bla = [-1] * 0x12

final = [0] * 0x12

for i in range(512):
    tmp = i >> 3
    if tmp >= 0x12:
        break

    if (bla[tmp] == -1):
        final[tmp] = i


print(final)
