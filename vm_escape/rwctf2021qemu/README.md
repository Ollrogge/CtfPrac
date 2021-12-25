## Real World Ctf 2021 QEMU escape challenge

Custom vulnerable PCI device added to QEMU source.

Bug: Can point result address to a register of the PCI device and trigger
     a free which results in a UAF.

Free_hook Exploit:
- use UAF to get arena leak
- use arena leak to find qemu_base and calc address of GOT entry.
- Leak libc from GOT
- Simple tcache poisoning + free hook to get shell

Shellcode exploit:
- Tcache poisoning to get chunk pointing to codegen buffer
- Write shellcode to codegen buffer
- codegen buffer is corrupted until last mmio_write. Exploit code needs to be compiled optimized to reduce JIT recompilations.