# Windows_wrapper
Program to link functions to your wrapped function

/!\ Only 64 bits /!\

Example:

wrapped.c :

#include <stdio.h>

int wrap_puts(const char *s) {
  puts("WRAPPED PUTS");
  puts(s);
  return 2626;
}

compile the wrapped.c as dll :

x86_64-w64-mingw32-gcc -c wrapped.c -o wrapped.o
x86_64-w64-mingw32-gcc -shared wrapped.o -o wrapped.dll

testprog.c : 

#include <stdio.h>

int main(void)
{
  int dummy;
  
  printf("testing wrapped function puts : \n");
  dummy = puts("Call to puts");
  printf("dummy = %d\n");
  return 0;
}

compile the testprog.c as executable :

x86_64-w64-mingw32-gcc -c testprog.c -o testprog.o
x86_64-w64-mingw32-gcc testprog.o -o testprog.exe

Then just compile the actual wrapper program :

make

Finally launch the programme like this :

./wrapper.exe wrapped.dll testprog.exe

You'll see the results

You can use this on every program and wrappe the function you want.

Enjoy <3
Please give it a heart. Thanks.
