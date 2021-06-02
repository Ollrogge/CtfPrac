#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>

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

int main(void)
{ 
    printf("%d \n", time_foo((unsigned long)getenv));
    clflush((unsigned long)getenv);
    printf("%d \n", time_foo((unsigned long)getenv));
}
