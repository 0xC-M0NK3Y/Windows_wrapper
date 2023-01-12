#ifndef LOADER_H_
# define LOADER_H_

#include "structs.h"

int exe_loader(void *pe, PE *ptr, dll_func_t *func);
int dll_loader(void *pe, PE *ptr, dll_func_t **func);
uintptr_t get_exe_entry(void *pe);
#endif