# binary-analysis
binary analysis tools - from Practical Binary Analysis book by Denis Andriesse

loader.h
--------

The _load_binary_ function takes a binary file as input and gets you a **Binary** object. The **Binary** object contains
information such as the binary type, entry point, CPU ISA, the list of **Section**s and the list of **Symbol**s. The
loader uses the libbfd (Binary File Descriptor library) underneath.

* **Section**s are either code or data sections. You can get the start address and size as well as the raw
content.

* **Symbol**s are either _function_ or _objects_ symbols. In libbfd terminology, _object_ symbols are synonyms of data
symbols (e.g., string labels)

See _loader_demo.cc_ for an example of a tool using the loader.
```asm
Usage:
./loader_demo <binary>
	List sections and symbols from <binary>
./loader_demo <binary> <section>
	Hexdump of <section> from <binary>
```

##### Examples
```asm
./loader_demo /usr/bin/ls
loaded binary '/bin/ls'
elf64-x86-64/i386:x86-64 (64 bits)
entry@0x0000000000005ae0

   virtual_address size     name                 type
 0x0000000000004000 27       .init                CODE
 0x0000000000004020 77187    .text                CODE
 0x0000000000016da4 13       .fini                CODE
 0x0000000000017000 20937    .rodata              DATA
 0x000000000001c1cc 2244     .eh_frame_hdr        DATA
...

 scanned symbol tables: 
 name                                        virtual_address type     link     scope    weak
 _obstack_begin_1                         0x00000000000162c0 FUNC     DYNAMIC  GLOBAL           
 program_invocation_name                  0x00000000000222a0 OBJECT   DYNAMIC  UNK      WEAK    
 obstack_alloc_failed_handler             0x0000000000022260 OBJECT   DYNAMIC  GLOBAL           
 optarg                                   0x0000000000022298 OBJECT   DYNAMIC  GLOBAL           
 stdout                                   0x0000000000022288 OBJECT   DYNAMIC  GLOBAL           
 __progname                               0x0000000000022280 OBJECT   DYNAMIC  GLOBAL           
 _obstack_begin                           0x00000000000162a0 FUNC     DYNAMIC  GLOBAL           
 _obstack_free                            0x0000000000016420 FUNC     DYNAMIC  GLOBAL           
 program_invocation_short_name            0x0000000000022280 OBJECT   DYNAMIC  UNK      WEAK 
...
```

```asm
./loader_demo /usr/bin/ls .text
loaded binary '/bin/ls'
elf64-x86-64/i386:x86-64 (64 bits)
entry@0x0000000000005ae0

Section .text, start 0x0000000000004020, size 77187, type CODE

0x00004020:     ff1582dc 0100ff15 7cdc0100 ff1576dc ........|.....v.
0x00004030:     0100ff15 70dc0100 ff156adc 0100ff15 ....p.....j.....
0x00004040:     64dc0100 ff155edc 0100ff15 58dc0100 d.....^.....X...
0x00004050:     ff1552dc 0100ff15 4cdc0100 0f1f4000 ..R.....L.....@.
0x00004060:     41574156 41554154 5589fd53 4889f348 AWAVAUATU..SH..H
0x00004070:     83ec5848 8b3e6448 8b042528 00000048 ..XH.>dH..%(...H
0x00004080:     89442448 31c067e8 04eb0000 488d35ae .D$H1.g.....H.5.
...
```