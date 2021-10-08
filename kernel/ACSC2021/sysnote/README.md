
**Challenge**
strcpy to buffer in task_struct before cred pointers

**Bug**
string max length not checked + not null terminated

**Exploit**
* overwrite cred ptrs with heap location holding kernel address
* leak lower 4 bytes of kernel address via getuid() since we overwrote cred
ptr
* get address of init_cred and overwrite cred ptrs with it.

**Writeup**
* https://stdnoerr.github.io/ctf/2021/09/19/ACSC2021.html

