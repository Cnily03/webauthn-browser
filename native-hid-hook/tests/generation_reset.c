#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Synthetic bytes only. No browser, authenticator, CTAP, or payload logging. */
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s (errno=%d)\n", __LINE__, #x, errno); exit(2); } } while (0)
#define ERR(x, e) do { errno = 0; CHECK((x) == -1 && errno == (e)); } while (0)
static const char *node = "/dev/userland-fido-hidraw0";

static void check_packet(const unsigned char *packet, unsigned char value) {
    for (size_t i = 0; i < 64; i++) CHECK(packet[i] == value);
}

static void read_old(int fd, unsigned char value, int queued) {
    unsigned char packet[64];
    if (queued) {
        CHECK(read(fd, packet, sizeof packet) == sizeof packet);
        check_packet(packet, value);
    } else {
        ERR(read(fd, packet, sizeof packet), ENODEV);
    }
}

static uint64_t socket_cookie(int fd) {
    uint64_t cookie = 0;
    socklen_t size = sizeof cookie;
    CHECK(getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &size) == 0);
    CHECK(size == sizeof cookie);
    return cookie;
}

static void no_fresh_output(int peer) {
    unsigned char packet[128];
    ERR(recv(peer, packet, sizeof packet, MSG_DONTWAIT), EAGAIN);
}

int main(int argc, char **argv) {
    CHECK(argc == 5);
    int relay = atoi(argv[1]), ready = atoi(argv[2]), proceed = atoi(argv[3]);
    int queued = !strcmp(argv[4], "queued");
    CHECK(queued || !strcmp(argv[4], "empty"));
    CHECK(relay >= 3 && ready >= 3 && proceed >= 3);
    alarm(8);
    setvbuf(stdout, NULL, _IONBF, 0);

    int fd = open(node, O_RDWR | O_CLOEXEC | O_NONBLOCK);
    CHECK(fd >= 0);
    int first = dup(fd), second = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    CHECK(first >= 0 && second >= 0);
    uint64_t original_cookie = socket_cookie(relay);
    CHECK(socket_cookie(first) == original_cookie);
    CHECK(socket_cookie(second) == original_cookie);

    /* Parent queues optional old packets, closes its peer, then acknowledges. */
    CHECK(write(ready, "R", 1) == 1);
    char ack = 0;
    CHECK(read(proceed, &ack, 1) == 1 && ack == 'C');
    CHECK(close(ready) == 0 && close(proceed) == 0);

    read_old(first, 0x31, queued);
    unsigned char output[65] = {0};
    memset(output + 1, 0x71, 64);
    ERR(write(fd, output, sizeof output), EPIPE);
    ERR(write(second, output, sizeof output), EPIPE);
    ERR(open(node, O_RDWR | O_NONBLOCK), EBUSY);
    CHECK(close(fd) == 0 && close(first) == 0 && close(second) == 0);

    /* A peer close alone does not change the original endpoint identity. */
    fd = open(node, O_RDWR | O_NONBLOCK);
    CHECK(fd >= 0);
    CHECK(socket_cookie(fd) == original_cookie);
    read_old(fd, 0x32, queued);
    ERR(write(fd, output, sizeof output), EPIPE);
    first = dup(fd);
    second = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    CHECK(first >= 0 && second >= 0);
    CHECK(close(fd) == 0);
    puts("PASS peer close: old aliases cannot write; same-endpoint reopen retains the old identity");

    int fresh[2];
    CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fresh) == 0);
    CHECK(fresh[0] != relay && fresh[1] != relay);
    uint64_t fresh_cookie = socket_cookie(fresh[0]);
    CHECK(fresh_cookie != original_cookie);

    /* Intentionally violate the dedicated relay-FD contract to test rejection.
       Raw close/dup2 force slot reuse without relying on FD allocation order. */
    CHECK(syscall(SYS_close, relay) == 0);
    CHECK(syscall(SYS_dup2, fresh[0], relay) == relay);
    CHECK(close(fresh[0]) == 0);
    CHECK(socket_cookie(relay) == fresh_cookie);
    CHECK(socket_cookie(first) == original_cookie);
    CHECK(socket_cookie(second) == original_cookie);

    unsigned char packet[64];
    memset(packet, 0x61, sizeof packet);
    CHECK(send(fresh[1], packet, sizeof packet, MSG_NOSIGNAL) == sizeof packet);
    read_old(first, 0x33, queued);
    ERR(read(first, packet, sizeof packet), ENODEV);
    ERR(read(second, packet, sizeof packet), ENODEV);
    ERR(write(first, output, sizeof output), EPIPE);
    no_fresh_output(fresh[1]);
    ERR(write(second, output, sizeof output), EPIPE);
    no_fresh_output(fresh[1]);
    CHECK(recv(relay, packet, sizeof packet, MSG_DONTWAIT | MSG_PEEK) == sizeof packet);
    check_packet(packet, 0x61);
    ERR(open(node, O_RDWR | O_NONBLOCK), EBUSY);
    CHECK(close(first) == 0);
    ERR(open(node, O_RDWR | O_NONBLOCK), EBUSY);
    CHECK(close(second) == 0);
    puts("PASS forced relay FD reuse: old aliases retain the dead endpoint; fresh peer reports remain untouched");

    /* With no aliases left, ENODEV proves identity rejection, not EBUSY. */
    for (int i = 0; i < 4; i++) {
        ERR(open(node, O_RDWR | O_NONBLOCK), ENODEV);
        ERR(open64(node, O_RDWR), ENODEV);
        ERR(openat(AT_FDCWD, node, O_RDWR | O_NONBLOCK), ENODEV);
        ERR(openat64(AT_FDCWD, node, O_RDWR), ENODEV);
    }
    CHECK(fcntl(relay, F_GETFL) & O_NONBLOCK);
    no_fresh_output(fresh[1]);
    CHECK(recv(relay, packet, sizeof packet, MSG_DONTWAIT) == sizeof packet);
    check_packet(packet, 0x61);
    ERR(recv(relay, packet, sizeof packet, MSG_DONTWAIT), EAGAIN);

    /* Positive control: the replacement socket itself is alive in both directions. */
    memset(packet, 0x62, sizeof packet);
    CHECK(send(relay, packet, sizeof packet, MSG_NOSIGNAL) == sizeof packet);
    CHECK(recv(fresh[1], packet, sizeof packet, MSG_DONTWAIT) == sizeof packet);
    check_packet(packet, 0x62);
    CHECK(close(relay) == 0 && close(fresh[1]) == 0);
    puts("PASS 16 new opens reject replacement identity with ENODEV; fresh socket remains usable independently");
    if (queued)
        puts("PASS all three queued old reports survive peer close, including across reopen and relay FD reuse; no queue retraction claimed");
    else
        puts("PASS empty old queue returns ENODEV before and after relay FD reuse");
    puts("PASS endpoint lifetime regression; no reset/reconnect implementation or browser acceptance claimed");
    return 0;
}
