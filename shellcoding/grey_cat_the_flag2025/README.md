### Vexed challenge
Write shellcode using only AVX2 instructions and no instruction containing "mov" in its name.

Approach:
- Encode shellcode as displacement / immediate ofr vpaddb instruction
- Load the shellcode in 2 byte steps into ymm0
- Write the shellcode in overlapping 128 bit writes to memory
