#include <stdint.h>
int register_uffd(uint64_t pages, uint64_t memsize, uint64_t data, void (*func)(void));