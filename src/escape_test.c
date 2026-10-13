#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
int main(void) {
    printf("UID=%ld EUID=%ld\n", (long)getuid(), (long)geteuid());
    errno = 0;
    if (setuid(0) == 0) {
        puts("FAIL: setuid(0) unexpectedly succeeded");
        return 2;
    }
    printf("PASS: setuid(0) denied: %s\n", strerror(errno));
    return (getuid() == 65534 && geteuid() == 65534) ? 0 : 3;
}
