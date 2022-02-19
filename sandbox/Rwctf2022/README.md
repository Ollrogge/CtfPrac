
## RwCTF 2022 QLaaS
sandbox escape from qiling version 1.4.1

Compile with:
```bash
 RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-unknown-linux-gnu
```

### Vuln
if openat is called sandbox will have no effect:

```python
def open_ql_file(self, path, openflags, openmode, dir_fd=None):
        if self.has_mapping(path):
            self.ql.log.info(f"mapping {path}")
            return self._open_mapping_ql_file(path, openflags, openmode)
        else:
            if dir_fd:
                return ql_file.open(path, openflags, openmode, dir_fd=dir_fd)

            real_path = self.ql.os.path.transform_to_real_path(path)
            return ql_file.open(real_path, openflags, openmode)
```

With openat we can supply a dir_fd. In this case `transform_to_real_path`, which prepends the rootfs path, won't be called. This allows us to escape the rootfs.


### Exploit
Escape sandbox and open actual root directory. Find libc mapping and address in `/proc/self/maps`. Overwrite libc code by writing to `/proc/self/mem`.

### Resources
https://www.kalmarunionen.dk/writeups/2022/rwctf/qlaas/