push rbp
mov rbp, rsp
sub rsp, 32
mov eax, 1
mov edi, 1
lea rsi, [rip+ask_name]
mov edx, 17
syscall

mov eax, 0
mov edi, 0
lea rsi, [rbp-32]
mov edx, 32
syscall
mov rbx, rax

mov eax, 1
mov edi, 1
lea rsi, [rip+show_name]
mov edx, 13
syscall

mov eax, 1
mov edi, 1
lea rsi, [rbp-32]
mov rdx, rbx
syscall

leave
ret
ask_name:
.ascii "Enter your name: "
show_name:
.ascii "Your name is "