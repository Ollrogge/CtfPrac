#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <sched.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>

extern uint64_t user_cs,user_ss,user_sp,user_rflags;

#define WAIT(void) {getc(stdin); fflush(stdin);}
#define errExit(msg) do { perror(msg); exit(EXIT_FAILURE);} while (0)
#define fail(msg) do {error(msg); exit(EXIT_FAILURE);} while (0)

#define ARRAY_SIZE(a) (sizeof((a)) / sizeof((a)[0]))
#define HEAP_MASK 0xffff000000000000
#define KERNEL_MASK 0xffffffff00000000
#define PAGE_SZ 0x1000

bool is_kernel_ptr(uint64_t val);

bool is_heap_ptr(uint64_t val);

void info(const char *format, ...);

void error(const char *format, ...);

void hexdump(void* buf, size_t len);

void get_shell_docker(void);

void assign_thread_to_core(int core_id);

void assign_to_core(int core_id);

int ulimit_fd(void);

void save_state(void);

void unshare_setup(uid_t uid, gid_t gid);
