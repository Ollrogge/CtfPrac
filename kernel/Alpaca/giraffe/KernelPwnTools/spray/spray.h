#include <stddef.h>
#include <stdint.h>
#include <poll.h>

#define POLL_LIST_SZ 0x10
#define POLL_FD_SZ 0x8
#define MAX_POLL_LIST_FDS 510
#define POLLFD_PER_PAGE  ((PAGE_SZ-sizeof(struct poll_list)) / sizeof(struct pollfd))
#define STACK_PPS_SZ 0x100

extern int pipes[0x1000][0x02];
extern int qids[0x1000];
extern int keys[0x1000];
extern int seq_ops[0x10000];
extern int ptmx[0x1000];
extern int fds[0x1000];
extern int n_keys;

typedef struct msg_msg_seg msg_msg_seg_t;
struct msg_msg_seg {
    msg_msg_seg_t* next;
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

typedef struct {
    struct rcu_head m_list;
    long m_type;
    size_t m_ts;      /* message text size */
    struct msg_msgseg *next;
    void *security;
    /* the actual message follows immediately */
} msg_msg_t;

typedef int32_t key_serial_t;

typedef struct {
	struct poll_list *next;
	int len;
	struct pollfd entries[];
} poll_list_t;

typedef struct {
    int fd_read;
    unsigned amt;
    unsigned timeout;
    bool suspend;
} thread_args_t;

void alloc_tty(int i);
void free_tty(int i);

// pipe_buf
void alloc_pipe_buf(int i);
void release_pipe_buf(int i);

// user_key_payload
long free_key(key_serial_t key);
int get_key(int i, char* buf, size_t sz);
void alloc_key(int id, char *buf, size_t size);

// msg_msg
void alloc_qid(int i);
void send_msg(int qid, int c, int size, long type);
void send_msg_payload(int qid, char* buf, int size, long type);
long recv_msg(int qid, void* data, int size, long type, bool copy);

// timer
int create_timer(bool leak);

void init_fd(int i);
