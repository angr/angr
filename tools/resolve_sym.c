/**
 * This little c program retrieve and resolve the indirect symbols
 * present in a dynamic library.
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main(int argc, char **argv)
{
  char *lib = argv[1];
  int i;
  int show = 1, ret;
  Dl_info info;

  void *so_ptr = dlopen(lib, RTLD_NOW);

  for (i = 2; i < argc; i++) {
    char *func = argv[i];
    void *func_ptr = dlsym(so_ptr, func);
    if (show) {    
      show = 0;
      ret = dladdr(func_ptr+1, &info);
      printf("Base_SO %p\n", (ret) ? info.dli_fbase : "???");      
    }
    printf("%s %p\n", func, func_ptr);
  }
}
