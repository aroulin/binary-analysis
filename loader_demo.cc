#include <stdio.h>
#include <stdint.h>
#include <string>
#include "loader.h"

int dump_sections_and_symbols(Binary &bin)
{
    Section *sec;
    Symbol *sym;
    size_t i;

    for(i = 0; i < bin.sections.size(); i++) {sec = &bin.sections[i];
        printf(" 0x%016jx %-8ju %-20s %s\n",
               sec->vma, sec->size, sec->name.c_str(),
               sec->type == Section::SEC_TYPE_CODE ? "CODE" : "DATA");
    }

    if(bin.symbols.size() > 0) {
        printf("scanned symbol tables\n");

        for(i = 0; i < bin.symbols.size(); i++) {
            sym = &bin.symbols[i];
            printf(" %-40s 0x%016jx %s\n", sym->name.c_str(), sym->addr,
                   (sym->type & Symbol::SYM_TYPE_FUN) ? "FUNC" : "");
        }
    }

    return 0;
}

int dump_section(Binary &bin, std::string section_name)
{
    Section *section = NULL;

    for (auto &sec: bin.sections)
        if (sec.name == section_name)
            section = &sec;

    if (!section) {
        fprintf(stderr, "Section %s does not exist\n", section_name.c_str());
        return -1;
    }
    printf("Section %s, start 0x%016jx, size %ju, type %s\n\n",
           section->name.c_str(), section->vma, section->size,
           section->type == Section::SEC_TYPE_CODE ? "CODE" : "DATA");

    std::string ascii_string{};

    uint64_t off;
    for (off = 0; off < section->size; off++) {
        if (off % 0x10 == 0)
            printf("0x%08jx:\t", section->vma + off);

        uint8_t byte = section->bytes[off];
        printf("%02jx", byte);

        if (isprint(byte))
            ascii_string.push_back(byte);
        else
            ascii_string.push_back('.');

        if ((off+1) % 16 == 0) {
            printf(" %s\n", ascii_string.c_str());
            ascii_string.clear();
        }
        else if ((off + 1) % 4 == 0)
            printf(" ");
    }

    if ((off + 1) % 16)
        printf(" %s\n", ascii_string.c_str());

    return 0;
}

int main(int argc, char *argv[])
{
    Binary bin;
    int ret = 0;

    std::string fname;

    if(argc < 2 || argc > 3) {
        printf("Usage:\n"
               "%s <binary>\n"
               "\tList sections and symbols from <binary>\n"
               "%s <binary> <section>\n"
               "\tHexdump of <section> from <binary>\n", argv[0], argv[0]);
        return 1;
    }

    fname.assign(argv[1]);
    if(load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0) {
        return 1;
    }

    printf("loaded binary '%s' %s/%s (%u bits) entry@0x%016jx\n",
           bin.filename.c_str(), bin.type_str.c_str(), bin.arch_str.c_str(),
           bin.bits, bin.entry);

    if (argc == 2)
        ret = dump_sections_and_symbols(bin);
    else if (argc == 3)
        ret = dump_section(bin, argv[2]);

    return ret;
}
