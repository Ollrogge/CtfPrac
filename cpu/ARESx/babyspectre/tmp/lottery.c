#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <mqueue.h>
#include <time.h>
#include <sched.h>

#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "lottery.h"

/* Victim */

const char lotto[256 * 4096] = {0x99, 0x98, 0x97, 0x96};
const uint64_t zero = 0x99999997;

char secret[4096];
uint64_t secret_token = 0;

volatile size_t ticket = 0;

void setup_secret() {
	secret_token = 0x4141414142424242;
	FILE* f = fopen("../flag.txt", "r");
	int r = fread(secret, 1, 4096, f);
	fclose(f);
}

void lottery(size_t i) {
	/* Hey, what gives? This'll never happen! */
	if (zero == secret_token) {
		ticket &= 0x9f8e7d6c ^ lotto[secret[i] * 4096];
	}
}

int find_min_load_cpu() {
	FILE* stats = fopen("/proc/stat", "r");
	if (stats == NULL) {
		perror("fopen");
		exit(1);
	}
	char buf[256];

#define check_fgets(a, b, c) \
	if (fgets(a, b, c) == NULL) { \
		perror("fgets"); \
		exit(1); \
	}

	/* Skip first line which is just "cpu" */
	check_fgets(buf, sizeof(buf), stats);
	unsigned int min_cpu = 0;
	double min_percent = 1.;
	unsigned int cpu = 0;
	unsigned int hardirq, softirq, user, idle;
	int scanned;
	do {
		check_fgets(buf, sizeof(buf), stats);
		scanned = sscanf(buf, "cpu%u %u %u %u %u", &cpu, &hardirq, &softirq, &user, &idle);
		if (scanned == 5) {
			double percent = (double)(hardirq + softirq + user) / (double)(hardirq + softirq + user + idle);
			if (percent < min_percent) {
				min_cpu = cpu;
				min_percent = percent;
			}
		}
	} while (scanned == 5);
	fclose(stats);
	return min_cpu;

#undef check_fgets
}

void setup_affinity(int cpu) {
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	int r = sched_setaffinity(0, sizeof(mask), &mask);
	if (r != 0) {
		perror("sched_setaffinity");
	}
}

void setup_chroot() {
	int r;
	r = chroot(".");
	if (r != 0) {
		perror("chroot");
		exit(1);
	}
	r = chdir("/");
	if (r != 0) {
		perror("chdir");
		exit(1);
	}
}

void drop_root() {
	if (setgid(1000) == -1) {
		perror("setgid");
		exit(1);
	}
	if (setuid(1000) == -1) {
		perror("setuid");
		exit(1);
	}
}

int pid;

void kill_child(int sig) {
	kill(pid, SIGKILL);
	exit(1);
}

int main(int argc, char* argv[]) {
	setbuf(stdout, NULL);

	if (argc < 2) {
		printf("Usage: ./lottery [child]\n");
		return 1;
	}

	setup_secret();

	printf("Setting up the lottery... ");
	for (int i = 0; i < 256 * 4096; i++) {
		volatile uint8_t u = lotto[i];
	}
	printf("done.\n");
	
	int cpu = find_min_load_cpu();
	printf("Minimum load cpu = %d\n", cpu);
	setup_chroot();
	drop_root();
	setup_affinity(cpu);
	
	pid = fork();

	if (pid == 0) {
		char* const argv_new[] = {argv[1], NULL};
		execvp(argv_new[0], argv_new);
	} else {
		signal(SIGTERM, kill_child);

		printf("Have a shot at the lottery:\n");

		mq_unlink("/lotto");
		struct mq_attr mqa = {0};
		mqa.mq_msgsize = sizeof(lotto_msg);
		mqa.mq_maxmsg = 10;
		mqd_t lotto_mq = mq_open("/lotto", O_RDWR | O_CREAT, S_IRWXU, &mqa);
		if (lotto_mq == -1) {
			printf("oops!\n");
			perror("mq_open");
		}

		lotto_msg msg = {0};
		int exit = -1;
		while (1) {
			struct timespec tm;
			clock_gettime(CLOCK_REALTIME, &tm);
			tm.tv_nsec += 1e7;

			int r = mq_timedreceive(lotto_mq, (char*)&msg, sizeof(msg), NULL, &tm);
			if (r > 0) {
				lottery(msg.i);
			}
			if (waitpid(-1, &exit, WNOHANG) != 0) {
				break;
			}
		}

		printf("Child exited with status %d\n", exit);
	}
	return 0;
}
