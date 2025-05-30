OUTPUT_FORMAT("elf64-littleaarch64", "elf64-littleaarch64", "elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_vector_table)

MEMORY
{
    /*The flash address range on LS1028A RDB is 0x20000000 - 0x23FFFFFF.*/
    FLASH (rx) : ORIGIN = @WOLFBOOT_ORIGIN@, LENGTH = @BOOTLOADER_PARTITION_SIZE@

    /* DDR4 - 2GB */
    DRAM (rwx) : ORIGIN = 0x80001000 , LENGTH = 0xBFFFFFFF

    /* OCRAM 256K for startup RAM */
    OCRAM (rwx) : ORIGIN = 0x18000000, LENGTH = 256K
}

SECTIONS
{
    PROVIDE (_DDR_ADDRESS = 0x80001000);
    PROVIDE (_OCRAM_ADDRESS = 0x18000000);
    PROVIDE (_FLASH_ADDRESS = @WOLFBOOT_ORIGIN@);
    PROVIDE (_CORE_NUMBER = 0);
    PROVIDE (_MEMORY_SIZE = LENGTH(OCRAM));
    PROVIDE (_FLASH_SIZE = LENGTH(FLASH));
    PROVIDE (_STACK_SIZE = 64K);
    PROVIDE (_EL0_STACK_SIZE = DEFINED(_EL0_STACK_SIZE) ? _EL0_STACK_SIZE : 1024);
    PROVIDE (_EL1_STACK_SIZE = DEFINED(_EL1_STACK_SIZE) ? _EL1_STACK_SIZE : 2048);
    PROVIDE (_EL2_STACK_SIZE = DEFINED(_EL2_STACK_SIZE) ? _EL2_STACK_SIZE : 1024);

    .boot :
    {
        PROVIDE(_vector_table = .);
        ._vector_table = .;
        . = ALIGN(0x800);
        KEEP(*(.vector_table))
        KEEP(*(.boot*))
    } > FLASH


    /* Read-only sections, merged into text segment: */
    .interp         : { *(.interp) }
    .note.gnu.build-id : { *(.note.gnu.build-id) }
    .hash           : { *(.hash) }
    .gnu.hash       : { *(.gnu.hash) }
    .dynsym         : { *(.dynsym) }
    .dynstr         : { *(.dynstr) }
    .gnu.version    : { *(.gnu.version) }
    .gnu.version_d  : { *(.gnu.version_d) }
    .gnu.version_r  : { *(.gnu.version_r) }
    .rela.init      : { *(.rela.init) }
    .rela.fini      : { *(.rela.fini) }
    .rela.rodata    : { *(.rela.rodata .rela.rodata.* .rela.gnu.linkonce.r.*) }
    .rela.data.rel.ro   : { *(.rela.data.rel.ro .rela.data.rel.ro.* .rela.gnu.linkonce.d.rel.ro.*) }
    .rela.data      : { *(.rela.data .rela.data.* .rela.gnu.linkonce.d.*) }
    .rela.tdata     : { *(.rela.tdata .rela.tdata.* .rela.gnu.linkonce.td.*) }
    .rela.tbss      : { *(.rela.tbss .rela.tbss.* .rela.gnu.linkonce.tb.*) }
    .rela.ctors     : { *(.rela.ctors) }
    .rela.dtors     : { *(.rela.dtors) }
    .rela.got       : { *(.rela.got) }
    .rela.bss       : { *(.rela.bss .rela.bss.* .rela.gnu.linkonce.b.*) }

    .text :
    {
        _start_text = .;
        *(.text*)
        *(.note.*)
        . = ALIGN(8);
        _end_text = .;
    } > FLASH

    .rodata :
    {
        _rodata_start = .;
        *(.rodata)
        *(.rodata.*)
        . = ALIGN(8);
        _rodata_end = .;
    } > FLASH

    PROVIDE(_stored_data = .);

    .data :
    {
        _start_data = .;
        KEEP(*(.data .data.* .gnu.linkonce.d.*))
        . = ALIGN(8);
        KEEP(*(.ramcode))
        . = ALIGN(8);
        _end_data = .;
    } > OCRAM AT > FLASH

    .bss :
    {
        _start_bss = .;
        __bss_start__ = .;
        *(.dynbss)
        *(.bss .bss.* .gnu.linkonce.b.*)
        *(COMMON)
        . = ALIGN(8);
        _end_bss = .;
        __bss_end__ = .;
        _end = .;
    } > OCRAM

    . = ALIGN(16);

    .stack (NOLOAD) : {
        . = ALIGN(64);
        _start_stack = .;
        _el3_stack_end = .;
        . += _STACK_SIZE;
        __el3_stack = .;
        _el2_stack_end = .;
        . += _EL2_STACK_SIZE;
        . = ALIGN(64);
        __el2_stack = .;
        _el1_stack_end = .;
        . += _EL1_STACK_SIZE;
        . = ALIGN(64);
        __el1_stack = .;
        _el0_stack_end = .;
        . += _EL0_STACK_SIZE;
        . = ALIGN(64);
        __el0_stack = .;

        _end_stack = .;
    } > OCRAM

    PROVIDE(_stack_base = .);
}