
**Vuln**
* 32 byte buffer overflow in kmalloc-256 slab

**Solution**
* Since no structure in kmalloc-256 has anything to gain code
  execution by overflowing 32 bytes, need to find other way
* Idea: Try and overflow a kmalloc-256 slab at a page boundary
* Overflow into seq_operations struct (kmalloc-32)
