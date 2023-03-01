# Windows_wrapper
Program to link functions to your wrapped function

/!\ Only 64 bits /!\

Example:

wrapped.c :
```c
    #include <stdio.h>
    
    // wrapped function must start with wrap_, or any 5 caracteres before the real function name
    int wrap_puts(const char *s) {
      puts("WRAPPED PUTS");
      puts(s);
      return 2626;
    }
 ``` 
compile the wrapped.c as dll :
```sh
    $ x86_64-w64-mingw32-gcc -shared wrapped.c -o wrapped.dll
```
testprog.c : 
```c
    #include <stdio.h>

    int main(void)
    {
      int dummy;

      printf("testing wrapped function puts : \n");
      dummy = puts("Call to puts");
      printf("dummy = %d\n", dummy);
      return 0;
    }
```
compile the testprog.c as executable :
```sh
    $ x86_64-w64-mingw32-gcc -c testprog.c -o testprog.o
    $ x86_64-w64-mingw32-gcc testprog.o -o testprog.exe
```
Then just compile the actual wrapper program :
```sh
    $ make
```
Finally launch the programme like this :
```sh
    $ ./wrapper.exe wrapped.dll testprog.exe
```

![WRAPPER](https://user-images.githubusercontent.com/102142537/222030269-808c87d8-7513-4770-9c20-e76449910c97.png)



