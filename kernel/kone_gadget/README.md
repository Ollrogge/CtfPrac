## Chal
* we get execution but all registers except rax are cleared -> where to jump to ?

## Solution
* use BPF JIT compliation to build a shellcode that disables SMAP
  * shellcode is hidden inside `mov instructions`
  * use arbitrary jump to jump to the shellcode
* then jump to ROP chain in user space
