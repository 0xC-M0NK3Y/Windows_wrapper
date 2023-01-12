#ifndef STRUCTS_H_
# define STRUCTS_H_

#include <windows.h>

/* Structure with pointers to all headers and sections we need to correctly load a PE */
typedef struct pe_hdr {
    PIMAGE_DOS_HEADER           dos;
    PIMAGE_NT_HEADERS           nt;
    PIMAGE_SECTION_HEADER       section;
    PIMAGE_IMPORT_DESCRIPTOR    import;
    PIMAGE_EXPORT_DIRECTORY     export;
    PIMAGE_BASE_RELOCATION      reloc;
}   pe_hdr_t;

typedef void* PE;

typedef struct dll_func {
    char *name;
    void *func;
}   dll_func_t;

#endif