#include <stdio.h>
#include <stdlib.h>

#include "structs.h"
#include "utils.h"
#include "loader.h"

int main(int argc, char **argv)
{
    void *tmp_dll = NULL;
    void *tmp_exe = NULL;
    void *dll = NULL;
    void *exe = NULL;
    dll_func_t *functions = NULL;

    if (argc != 3) {
        printf("Usage: %s <wrapped_dll> <executable>\n");
        return 0;
    }
    /* Load the file in RAM as files */
    tmp_dll = copy_file_in_ram(argv[1]);
    if (tmp_dll == NULL) {
        puts("FATAL ERROR");
        return EXIT_FAILURE;
    }
    tmp_exe = copy_file_in_ram(argv[2]);
    if (tmp_exe == NULL) {
        puts("FATAL ERROR");
        return EXIT_FAILURE;
    }
    /* Load dll */
    if (dll_loader(tmp_dll, &dll, &functions) < 0) {
        puts("FAILED LOAD DLL");
        return EXIT_FAILURE;
    }
    /* Load exe by linking functions with the wrapped ones if they exists */
    if (exe_loader(tmp_exe, &exe, functions) < 0) {
        puts("FAILED LOAD EXE");
        return EXIT_FAILURE;
    }
    /* We now juste need to jump on the AddressOfEntryPoint of our executable */
    /* call the function to retrieve the entry point and jump on it (rax) */
    get_exe_entry(exe);
    __asm__("jmp %rax");
    return 0;
}