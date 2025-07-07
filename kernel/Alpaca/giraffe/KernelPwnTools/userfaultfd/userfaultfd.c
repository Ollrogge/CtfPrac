#include <stdio.h>
#include <poll.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>
#include "userfaultfd.h"

#define errExit(msg) do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)

struct info {
    uintptr_t uffd;
    uint64_t fault_addr;
    uint64_t size;
    uint64_t data;
    void (*func)(void);
};

void* handler(void *arg)
{
	struct uffd_msg msg;
    struct info* uffd_info = (struct info *)arg;
	uintptr_t uffd = uffd_info->uffd;
    struct uffdio_range uf_range;

	struct pollfd pollfd;
	int nready;
	pollfd.fd = uffd;
	pollfd.events = POLLIN;
	nready = poll(&pollfd,1,-1);
	if (nready != 1) {
        errExit("wrong poll return val");
    }

	if (read(uffd, &msg, sizeof(msg)) != sizeof(msg)) {
        errExit("Error reading uffd_msg");
    }

    uf_range.len = 0x1000;
    uf_range.start = uffd_info->fault_addr;

    uffd_info->func();

    struct uffdio_copy uc;
    uc.src = (uintptr_t)uffd_info->data;
    uc.dst = (uintptr_t)uffd_info->fault_addr;
    uc.len = 0x1000;
    uc.mode = 0;

    if(ioctl(uffd, UFFDIO_COPY, &uc) == -1) {
        errExit("UFDIO_COPY");
    }

    if (ioctl(uffd, UFFDIO_UNREGISTER, (unsigned long)&uf_range) == -1)
    {
        errExit("UFDIO_UNREGISTER");
    }

	/*
    if (munmap((void *)uffd_info->fault_addr, 0x1000) == -1)
    {
        errExit("unmap fault page");
    }
	*/

	return NULL;
}

int register_uffd(uint64_t pages, uint64_t memsize, uint64_t data, void (*func)(void)) {
	int fd = 0;
	if ((fd = syscall(SYS_userfaultfd, O_NONBLOCK)) == -1) {
        errExit("userfaultfd");
	}
	/* When first opened the userfaultfd must be enabled invoking the
	   UFFDIO_API ioctl specifying a uffdio_api.api value set to UFFD_API
	   (or a later API version) which will specify the read/POLLIN protocol
	   userland intends to speak on the UFFD and the uffdio_api.features
	   userland requires. The UFFDIO_API ioctl if successful (i.e. if the
	   requested uffdio_api.api is spoken also by the running kernel and the
	   requested features are going to be enabled) will return into
	   uffdio_api.features and uffdio_api.ioctls two 64bit bitmasks of
	   respectively all the available features of the read(2) protocol and
	   the generic ioctl available. */
	struct uffdio_api api = { .api = UFFD_API };
	if (ioctl(fd, UFFDIO_API, &api)) {
        errExit("UFDIO_API");
	}
	/* "Once the userfaultfd has been enabled the UFFDIO_REGISTER ioctl
	   should be invoked (if present in the returned uffdio_api.ioctls
	   bitmask) to register a memory range in the userfaultfd by setting the
	   uffdio_register structure accordingly. The uffdio_register.mode
	   bitmask will specify to the kernel which kind of faults to track for
	   the range (UFFDIO_REGISTER_MODE_MISSING would track missing
	   pages). The UFFDIO_REGISTER ioctl will return the uffdio_register
	   . ioctls bitmask of ioctls that are suitable to resolve userfaults on
	   the range registered. Not all ioctls will necessarily be supported
	   for all memory types depending on the underlying virtual memory
	   backend (anonymous memory vs tmpfs vs real filebacked mappings)." */
	if (api.api != UFFD_API) {
        errExit("unexpected uffd api version");
	}
	/* mmap some pages, set them up with the userfaultfd. */
	struct uffdio_register reg = {
		.mode = UFFDIO_REGISTER_MODE_MISSING,
		.range = {
			.start = pages,
			.len = memsize
		}
	};

	if (ioctl(fd, UFFDIO_REGISTER,  &reg)) {
        errExit("UFFDIO_REGISTER");
	}

	// if (reg.ioctls != UFFD_API_RANGE_IOCTLS) {
	// 	fprintf(stderr, "++ unexpected UFFD ioctls. %llx %llx \n", reg.ioctls, UFFD_API_RANGE_IOCTLS);
	// 	exit(-1);
	// }

    struct info* inf = (struct info*)malloc(sizeof(struct info));
    inf->uffd = fd;
    inf->fault_addr = pages;
    inf->size = memsize;
    inf->data = data;
    inf->func = func;

    pthread_t thr;

    int s = pthread_create(&thr,NULL,handler,(void*)inf);
	if(s!=0)
		errExit("pthread_create");

	return fd;
}
