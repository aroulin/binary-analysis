#include <bfd.h>
#include "loader.h"

int load_binary_bfd(std::string &fname, Binary *bin, Binary::BinaryType type)
{
    return 0;
}

int load_binary(std::string &fname, Binary *bin, Binary::BinaryType type)
{
    return load_binary_bfd(fname, bin, type);
}

void unload_binary(Binary *bin)
{
    size_t i;
    Section *sec;

    for (i = 0; i < bin->sections.size(); i++) {
        sec = &bin->sections[i];
        if (sec->bytes)
            free(sec->bytes);
    }
}

static bfd* open_bfd(std::string &fname)
{
    static int bfd_inited = 0;
    bfd *bfd_h;

    if (!bfd_inited) {
        bfd_init();
        bfd_inited = 1;
    }

    bfd_h = bfd_openr(fname.c_str(), NULL);
    if (!bfd_h) {
        fprintf(stderr, "file '%s' does not look like an executable (%s)\n",
                fname.c_str(), bfd_errmsg(bfd_get_error()));
        return NULL;
    }

    if(!bfd_check_format(bfd_h, bfd_object)) {
        fprintf(stderr, "file '%s' does not look like an executable (%s)\n",
                fname.c_str(), bfd_errmsg(bfd_get_error()));
        return NULL;
    }

    /* Some versions of bfd_check_format pessimistically set a wrong_format
    * error before detecting the format and then neglect to unset it once
    * the format has been detected. We unset it manually to prevent problems.
    */
    bfd_set_error(bfd_error_no_error);

    if (bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour) {
        fprintf(stderr, "unrecognized format for binary '%s' (%s)\n",
                fname.c_str(), bfd_errmsg(bfd_get_error()));
        return NULL;
    }

    return bfd_h;
}

