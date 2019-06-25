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
