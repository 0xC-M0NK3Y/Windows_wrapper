#ifndef MACRO_H
# define MACRO_H

# ifdef __DEBUG__
#  define DEBUG_PRINTF(...) {fprintf(stderr, __VA_ARGS__);}
# else
#  define DEBUG_PRINTF(...) {}
# endif

#endif