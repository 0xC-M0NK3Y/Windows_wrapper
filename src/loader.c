#include <stdio.h>
#include <stdint.h>

#include <windows.h>

#include "structs.h"

static uint32_t find_rva(uint32_t rva, PIMAGE_SECTION_HEADER section, uint16_t nb_of_section) {
    /* Finding the Relative Virtual Address from offset in file */
    /* We actually don't need to call this function, only usefull in file state */
    /* The pointer to raw data are equal to virtualaddess so it return only rva */
    for (int i = 0; i < nb_of_section; i++) {
        if (rva >= section[i].VirtualAddress && rva < section[i].VirtualAddress + section[i].Misc.VirtualSize) {
            return rva - section[i].VirtualAddress + section[i].PointerToRawData;
        }
    }
    return 0;
}

static uintptr_t find_section(pe_hdr_t hdr, PE ptr, char *name) {

    uint16_t nb_section = hdr.nt->FileHeader.NumberOfSections;

    /* Finding the pointer to the section we are looking for */
    for (uint16_t i = 0; i < nb_section; i++) {
        if (memcmp(hdr.section[i].Name, name, strlen(name) + 1) == 0) {
            return (uintptr_t)(ptr + find_rva(hdr.section[i].VirtualAddress, hdr.section, nb_section));
        }
    }
    return 0;
}

static int parse_pe(pe_hdr_t hdr) {
    /* Verify DOS magic number */
    if (hdr.dos->e_magic != IMAGE_DOS_SIGNATURE)
        return -1;
    /* Verify signature */
    if (hdr.nt->Signature != IMAGE_NT_SIGNATURE)
        return -1;
    /* Verify its 64 bits */
    if (hdr.nt->OptionalHeader.Magic != 0x20B)
        return -1;
    return 1;
}

static int map_pe(void *pe, pe_hdr_t hdr, PE *ptr) {

    /* Fetching all variable needed here, more lisible code */
    //uintptr_t image_base = hdr.nt->OptionalHeader.ImageBase;
    uint32_t size_of_image = hdr.nt->OptionalHeader.SizeOfImage;
    uint32_t size_of_headers = hdr.nt->OptionalHeader.SizeOfHeaders;
    uint16_t nb_sections = hdr.nt->FileHeader.NumberOfSections;

    /* Alloc the total image of pe */
    // better to VirtualAlloc to image_base to avoid relocations, first parameter
    *ptr = VirtualAlloc((void *)NULL, size_of_image, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (*ptr == NULL)
        return -1;

    /* memset 0 always good */
    memset(*ptr, 0, size_of_image);

    /* Start mapping headers */
    memcpy(*ptr, pe, size_of_headers);

    /* Map sections */
    for (uint16_t i = 0; i < nb_sections; i++) {
        if (hdr.section[i].PointerToRawData != 0)
            memcpy(*ptr + hdr.section[i].VirtualAddress, pe + hdr.section[i].PointerToRawData, hdr.section[i].SizeOfRawData);
        if (hdr.section[i].Misc.VirtualSize > hdr.section[i].SizeOfRawData)
            memset(*ptr + hdr.section[i].VirtualAddress + hdr.section[i].SizeOfRawData, 0, hdr.section[i].Misc.VirtualSize - hdr.section[i].SizeOfRawData);
    }
    return 1;
}

static int do_relocations(PE ptr, pe_hdr_t hdr) {

    /* Getting the delta we need to fix relocations */
    int64_t                 delta = ((uintptr_t)ptr - (uintptr_t)hdr.nt->OptionalHeader.ImageBase);
    PIMAGE_BASE_RELOCATION  reloc = hdr.reloc;

    while (reloc->VirtualAddress)
    {
        /* Getting the number of entry we need to modify */
        /* (SizeOfBlock - 8) / sizeof(WORD) because we have n number of WORD TypeOffset and the header itself doesn't count so -8 */
        uint32_t entry = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        /* Getting the pointer to our TypeOffset, just after the actuel reloc header as (WORD *) */
        uint16_t *tmp = (uint16_t *)((PIMAGE_BASE_RELOCATION)reloc + 1);

        for (uint32_t i = 0; i < entry; i++) {
            /* 4 first bits are the type */
            int8_t type = tmp[i] >> 12;
            /* 12 next bits are the offset of the virtual address actual (corresponding a section) to witch we need to relocate */
            int32_t offset = tmp[i] & 0XFFF;
            /* Getting the pointer to the pointer we need to relocate */
            uintptr_t *address = (uintptr_t *)(ptr + reloc->VirtualAddress + offset);
            if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64)
                *address += delta;
        }
        /* Go to the next relocation to do */
        reloc = (PIMAGE_BASE_RELOCATION)(((uint8_t *)reloc) + reloc->SizeOfBlock); 
    }
    return 1;
}

static int fixe_mapped_pe(pe_hdr_t hdr) {

    uint16_t nb_sections = hdr.nt->FileHeader.NumberOfSections;

    /* PE is mapped so we don't have PointerToRawData anymore, only VirtualAddress */
    for (uint16_t i = 0; i < nb_sections; i++)
        hdr.section[i].PointerToRawData = hdr.section[i].VirtualAddress;
    return 1;
}


static int load_imports(pe_hdr_t hdr, PE ptr) {

    PIMAGE_IMPORT_DESCRIPTOR import = hdr.import;

    /* Loop throught all dll to import */
    while (import->Name)
    {
        /* Getting the name of the dll to load, import->Name is a RVA */
        char *name = ptr + find_rva(import->Name, hdr.section, hdr.nt->FileHeader.NumberOfSections);
        /* In theorie if anything goes wrong, a function is not load and linked, everything gets instable and would certenly crash */
        if (name == ptr) {
            import++;
            continue;
        }
        /* Loading the dll needed */
        HMODULE module = LoadLibraryExA(name, NULL, 0);
        if (module == NULL) {
            import++;
            continue;
        }
        /* Accessing the thunks with the RVA */
        /* We have 2 thunks not pointing to the same location, one thunk to view and one to modify */
        PIMAGE_THUNK_DATA64 view_thunk = ptr + find_rva(import->OriginalFirstThunk, hdr.section, hdr.nt->FileHeader.NumberOfSections);;
        PIMAGE_THUNK_DATA64 set_thunk = ptr + find_rva(import->FirstThunk, hdr.section, hdr.nt->FileHeader.NumberOfSections);
        /* Can happen we don't have view_thunk, not a probleme */
        if (view_thunk == ptr)
            view_thunk = (PIMAGE_THUNK_DATA64)set_thunk;
        /* We loop throught all functions to import */
        while (set_thunk->u1.AddressOfData)
        {
            /* If we need to import throught ordinal (not used anymore in theory) */
            if (IMAGE_SNAP_BY_ORDINAL64(set_thunk->u1.Ordinal)) {
				uintptr_t address = (uintptr_t)GetProcAddress(module, ((LPCSTR)IMAGE_ORDINAL64(set_thunk->u1.Ordinal)));
                if (address == 0) {
                    view_thunk++;
                    set_thunk++;
                    continue;
                }
				*(uintptr_t *)set_thunk = address;
            } else {
                /* Importing by name */
                PIMAGE_IMPORT_BY_NAME func = ptr + find_rva(view_thunk->u1.AddressOfData, hdr.section, hdr.nt->FileHeader.NumberOfSections);
                uintptr_t address = (uintptr_t) GetProcAddress(module, func->Name);
                if (address == 0) {
                    view_thunk++;
                    set_thunk++;
                    continue;
                }
                /* linking the function needed with the one we loaded in RAM */
				*(uintptr_t *)set_thunk = address;
            }
            view_thunk++;
            set_thunk++;
        }
        import++;
    }
    /* We resolved the imports */
    import->TimeDateStamp = 1;
    return 1;
}

static void *search_wrapped_func(char *name, dll_func_t *func) {
    while (func->name)
    {
        if (strncmp(name, &func->name[5], strlen(name)) == 0)
            return func->func;
        func++;
    }
    return NULL;
}

/* Almost the same as load_imports, possibility to make just one for the 2 */
static int load_wrapped_imports(pe_hdr_t hdr, PE ptr, dll_func_t *wrapped_func) {

    PIMAGE_IMPORT_DESCRIPTOR import = hdr.import;

    /* Loop throught all dll to import */
    while (import->Name)
    {
        /* Getting the name of the dll to load, import->Name is a RVA */
        char *name = ptr + find_rva(import->Name, hdr.section, hdr.nt->FileHeader.NumberOfSections);
        /* In theorie if anything goes wrong, a function is not load and linked, everything gets instable and would certenly crash */
        if (name == ptr) {
            import++;
            continue;
        }
        /* Loading the dll needed */
        HMODULE module = LoadLibraryExA(name, NULL, 0);
        if (module == NULL) {
            import++;
            continue;
        }
        /* Accessing the thunks with the RVA */
        /* We have 2 thunks not pointing to the same location, one thunk to view and one to modify */
        PIMAGE_THUNK_DATA64 view_thunk = ptr + find_rva(import->OriginalFirstThunk, hdr.section, hdr.nt->FileHeader.NumberOfSections);;
        PIMAGE_THUNK_DATA64 set_thunk = ptr + find_rva(import->FirstThunk, hdr.section, hdr.nt->FileHeader.NumberOfSections);
        /* Can happen we don't have view_thunk, not a probleme */
        if (view_thunk == ptr)
            view_thunk = (PIMAGE_THUNK_DATA64)set_thunk;
        /* We loop throught all functions to import */
        while (set_thunk->u1.AddressOfData)
        {
            /* If we need to import throught ordinal (not used anymore in theory) */
            if (IMAGE_SNAP_BY_ORDINAL64(set_thunk->u1.Ordinal)) {
				uintptr_t address = (uintptr_t)GetProcAddress(module, ((LPCSTR)IMAGE_ORDINAL64(set_thunk->u1.Ordinal)));
                if (address == 0) {
                    view_thunk++;
                    set_thunk++;
                    continue;
                }
				*(uintptr_t *)set_thunk = address;
            } else {
                /* Importing by name */
                PIMAGE_IMPORT_BY_NAME func = ptr + find_rva(view_thunk->u1.AddressOfData, hdr.section, hdr.nt->FileHeader.NumberOfSections);
                *(uintptr_t *)set_thunk = (uintptr_t)search_wrapped_func(func->Name, wrapped_func);
                if (*(uintptr_t *)set_thunk != 0) {
                    view_thunk++;
                    set_thunk++;
                    continue;                
                }
                uintptr_t address = (uintptr_t) GetProcAddress(module, func->Name);
                if (address == 0) {
                    view_thunk++;
                    set_thunk++;
                    continue;
                }
                /* linking the function needed with the one we loaded in RAM */
				*(uintptr_t *)set_thunk = address;
            }
            view_thunk++;
            set_thunk++;
        }
        import++;
    }
    /* We resolved the imports */
    import->TimeDateStamp = 1;
    return 1;
}

static int load_exports(pe_hdr_t hdr, PE ptr, dll_func_t **func) {

    PIMAGE_EXPORT_DIRECTORY export = hdr.export;
    uint32_t nb_of_functions = export->NumberOfNames;
    /* Pointer to array of RVA to name of functions */
    uint32_t *name_ptr = ptr + find_rva(export->AddressOfNames, hdr.section, hdr.nt->FileHeader.NumberOfSections);
    /* Pointer to array of RVA to pointer of functions */
    uint32_t *func_ptr = ptr + find_rva(export->AddressOfFunctions, hdr.section, hdr.nt->FileHeader.NumberOfSections);

	*func = malloc(sizeof(dll_func_t) * (nb_of_functions + 1));
	if (*func == NULL)
		return -1;
	(*func)[nb_of_functions].name = NULL;
	(*func)[nb_of_functions].func = NULL;
    /* Getting all the functions */
    for (uint32_t i = 0; i < nb_of_functions; i++) {
        (*func)[i].name = ptr + find_rva(name_ptr[i], hdr.section, hdr.nt->FileHeader.NumberOfSections);
		(*func)[i].func = ptr + find_rva(func_ptr[i], hdr.section, hdr.nt->FileHeader.NumberOfSections);
    }
	return 1;
}



int dll_loader(void *pe, PE *ptr, dll_func_t **func) {

    pe_hdr_t hdr = {0};

    /* First we take pointers to our temporary PE */
    hdr.dos = pe;
    hdr.nt = pe + hdr.dos->e_lfanew;
    hdr.section = IMAGE_FIRST_SECTION(hdr.nt);

    /* Parse the PE */
    if (parse_pe(hdr) < 0)
        return -__LINE__;
    /* Map it */
    if (map_pe(pe, hdr, ptr) < 0)
        return -__LINE__;
    /* We don't need our temporary PE anymore, we can free it here */
    free(pe);

    memset(&hdr, 0, sizeof(pe_hdr_t));

    /* Then we take the pointers to our mapped PE */
    hdr.dos = *ptr;
    hdr.nt = *ptr + hdr.dos->e_lfanew;
    hdr.section = IMAGE_FIRST_SECTION(hdr.nt);
    /* Fix the PointerToRawData not existing anymore, not at a file stade, we are at mapped stade */
    fixe_mapped_pe(hdr);
    hdr.import = (PIMAGE_IMPORT_DESCRIPTOR)find_section(hdr, *ptr, ".idata");
    hdr.export = (PIMAGE_EXPORT_DIRECTORY)find_section(hdr, *ptr, ".edata");
    hdr.reloc = (PIMAGE_BASE_RELOCATION)find_section(hdr, *ptr, ".reloc");
    /* Do relocation if needed */
    if (*ptr != (void *)hdr.nt->OptionalHeader.ImageBase && hdr.reloc)
        do_relocations(*ptr, hdr);
    /* Load imports */
    load_imports(hdr, *ptr);
    /* Get the exports */
    if (load_exports(hdr, *ptr, func) < 0)
        return -__LINE__;
    return 1;
}

uintptr_t get_exe_entry(void *pe) {
    pe_hdr_t hdr = {0};

    hdr.dos = pe;
    hdr.nt = pe + hdr.dos->e_lfanew;

    return (uintptr_t)(pe + hdr.nt->OptionalHeader.AddressOfEntryPoint);
}

int exe_loader(void *pe, PE *ptr, dll_func_t *func) {

    pe_hdr_t hdr = {0};
    /* First we take pointers to our temporary PE */
    hdr.dos = pe;
    hdr.nt = pe + hdr.dos->e_lfanew;
    hdr.section = IMAGE_FIRST_SECTION(hdr.nt);
    /* Parse the PE */
    if (parse_pe(hdr) < 0)
        return -__LINE__;
    /* Map it */
    if (map_pe(pe, hdr, ptr) < 0)
        return -__LINE__;
    /* We don't need our temporary PE anymore, we can free it here */
    free(pe);
    /* Then we take the pointers to our mapped PE */
    hdr.dos = *ptr;
    hdr.nt = *ptr + hdr.dos->e_lfanew;
    hdr.section = IMAGE_FIRST_SECTION(hdr.nt);
    /* Fix the PointerToRawData not existing anymore, not at a file stade, we are at mapped stade */
    fixe_mapped_pe(hdr);
    hdr.import = (PIMAGE_IMPORT_DESCRIPTOR)find_section(hdr, *ptr, ".idata");
    hdr.export = (PIMAGE_EXPORT_DIRECTORY)find_section(hdr, *ptr, ".edata");
    hdr.reloc = (PIMAGE_BASE_RELOCATION)find_section(hdr, *ptr, ".reloc");
    /* Do relocation if needed */
    if (*ptr != (void *)hdr.nt->OptionalHeader.ImageBase && hdr.reloc)
        do_relocations(*ptr, hdr);
    /* Load imports */
    load_wrapped_imports(hdr, *ptr, func);
    return 1;
}
