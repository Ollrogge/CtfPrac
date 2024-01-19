SECTIONS

{

. = 0x400000;
.text32 : { *(.text32) }

. = 0x3400000000;
.text64 : { *(.text64) }

. = 0x1337000;
.data_code32 : { *(.data_code32) }

. = 0x1337331000;
.data_code64 : { *(.data_code64) }

.bss : { *(.bss) }

}
