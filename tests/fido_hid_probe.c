/* Disposable opaque transport probe. No CTAP commands, credentials or success responses. */
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(void) {
    int fd = open("/dev/userland-fido-hidraw0", O_RDWR | O_NONBLOCK);
    if (fd < 0) return 2;
    unsigned char output[65], input[64];
    memset(output, 0xa5, sizeof output); output[0] = 0;
    if (write(fd, output, sizeof output) != sizeof output) return 3;
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    if (poll(&ready, 1, 5000) != 1 || read(fd, input, sizeof input) != sizeof input) return 4;
    for (unsigned i=0;i<sizeof input;i++) if (input[i] != 0x5a) return 5;
    if (close(fd)) return 6;
    puts("Opaque report traversed preload, backend HTTP and helper WebSocket in both directions.");
    return 0;
}
