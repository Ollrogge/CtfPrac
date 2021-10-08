
**Challenge**
Custom printf implementation inside the kernel.
Arbitrary write (%n) and read (%s) possible.

**Exploit**
Strings not null terminated. Leak heap pointer and search heap
for kernel pointer
Use arb read / write to overwrite task->cred with new value / ptr.

**Writeup**
https://stdnoerr.github.io/kernel-pwn/2021/09/10/pass-grabcon.html

