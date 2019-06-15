#ifndef LOADER_H
#define LOADER_H

#include <stdint.h>
#include <string>
#include <vector>
#include <memory>

class Binary;
class Section;
class Symbol;

class Symbol {
public:
    enum SymbolType {
        SYM_TYPE_UNK = 0,
        SYM_TYPE_FUN = 1,
        SYM_TYPE_OBJ = 2,
    };

    enum SymbolLinkType {
        SYM_LINK_UNK = 0,
        SYM_LINK_STATIC = 1,
        SYM_LINK_DYNAMIC = 2,
    };

    enum SymbolBindType {
        SYM_BIND_UNK = 0,
        SYM_BIND_GLOBAL = 1,
        SYM_BIND_LOCAL = 2,
    };

    Symbol() : type(SYM_TYPE_UNK), name(), addr(0), weak(false), linkType(SYM_LINK_UNK), bindType(SYM_BIND_UNK) {}

    SymbolType      type;
    std::string     name;
    uint64_t        addr;
    bool            weak;
    SymbolLinkType  linkType;
    SymbolBindType  bindType;
};

class Section {
public:
    enum SectionType {
        SEC_TYPE_NONE = 0,
        SEC_TYPE_CODE = 1,
        SEC_TYPE_DATA = 2,
    };

    Section() : binary(NULL), name(), type(SEC_TYPE_NONE), vma(0), size(0),
                bytes() {}

    bool contains(uint64_t addr) { return (addr >= vma) && (addr-vma < size); }

    Binary 		*binary;
    std::string name;
    SectionType	type;
    uint64_t	vma;
    uint64_t	size;
    std::unique_ptr<uint8_t[]> bytes;
};

class Binary {
public:
    enum BinaryType {
        BIN_TYPE_AUTO = 0, /* determine out type automatically */
        BIN_TYPE_ELF  = 1,
        BIN_TYPE_PE   = 2,
    };
    enum BinaryArch {
        ARCH_NONE = 0,
        ARCH_X86  = 1, /* also represents amd64, use bits to distinguish */
    };

    Binary() : type(BIN_TYPE_AUTO), arch(ARCH_NONE), bits(0), entry(0) {}

    Section *get_text_sections()
    { for(auto &s : sections) if(s.name == ".text") return &s; return NULL; }

    std::string             filename;
    BinaryType 	            type;
    std::string             type_str;
    BinaryArch		        arch;
    std::string		        arch_str;
    unsigned		        bits; 	/* bit width e.g., 64 bits*/
    uint64_t	     	    entry; 	/* entry point */
    std::vector<Section> 	sections;
    std::vector<Symbol>  	symbols;

};

int load_binary(std::string &fname, Binary *bin, Binary::BinaryType type);

#endif /* LOADER_H */
