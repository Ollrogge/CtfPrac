## 0CTF 2019 babyheap challenge

Bug: Off by one nullbyte in edit function

Other: Big malloc (0x1f000) at beginning

Parameters:
  - Calloc is used instead of malloc
    - memory zeroed out
    - doesnt use tcache
  - Max 0xf chunks, max size 0x58

Exploit:
  - Use nullbyte poisoning to reduce size of top chunk
    - When size top chunk < requested size, libc will call
      malloc consolidate => consolidate fastbins
  - Use fastbin consolidate to get chunk in unsorted bin
  - Poison size of unsorted bin to prevent malloc from adjusting prev_size
    of adjacent chunk
  - Trigger consolidate again with specific heap layout to get overlapping
    chunks
  - Leak libc
  - Use fastbin fd attack to get a chunk in main arena
  - Set top_chunk to an address with val != 0 before free hook
  - Allocate until chunk at free hook
  - System + /bin/sh
