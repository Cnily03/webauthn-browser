#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s (errno=%d)\n", __LINE__, #x, errno); exit(2); } } while (0)
#define ERR(x, e) do { errno = 0; CHECK((x) == -1 && errno == (e)); } while (0)
static const char *node = "/dev/userland-fido-hidraw0";

static uint64_t cookie(int fd) {
    uint64_t value = 0;
    socklen_t size = sizeof value;
    CHECK(syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_COOKIE, &value, &size) == 0);
    CHECK(size == sizeof value);
    return value;
}

static int count_cookie(uint64_t expected) {
    DIR *dir = opendir("/proc/self/fd");
    CHECK(dir);
    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(dir))) {
        char *end;
        long fd = strtol(entry->d_name, &end, 10);
        if (!entry->d_name[0] || *end || fd < 0 || fd > 2147483647L) continue;
        uint64_t value = 0;
        socklen_t size = sizeof value;
        if (syscall(SYS_getsockopt, (int)fd, SOL_SOCKET, SO_COOKIE, &value, &size) == 0 &&
            size == sizeof value && value == expected) count++;
    }
    CHECK(closedir(dir) == 0);
    return count;
}

static void raw_closed(int fd) {
    unsigned char packet[64] = {0};
    ERR(syscall(SYS_fcntl, fd, F_GETFD), EBADF);
    ERR(syscall(SYS_read, fd, packet, sizeof packet), EBADF);
    ERR(syscall(SYS_write, fd, packet, sizeof packet), EBADF);
}

static void wait_child(pid_t pid) {
    int status = 0;
    for (int i = 0; i < 4000; i++) {
        pid_t result = waitpid(pid, &status, WNOHANG);
        CHECK(result >= 0);
        if (result == pid) {
            CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
            return;
        }
        usleep(1000);
    }
    CHECK(kill(pid, SIGKILL) == 0);
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(0 && "child timeout");
}

static void report(int fd) {
    unsigned char out[65] = {0}, in[64];
    memset(out + 1, 0x45, 64);
    CHECK(write(fd, out, sizeof out) == sizeof out);
    struct pollfd pollfd = {.fd = fd, .events = POLLIN};
    CHECK(poll(&pollfd, 1, 2000) == 1 && (pollfd.revents & POLLIN));
    CHECK(read(fd, in, sizeof in) == sizeof in);
    CHECK(!memcmp(out + 1, in, sizeof in));
}

static int duplicate_kind(int source, int kind) {
    int target;
    switch (kind) {
        case 0: return dup(source);
        case 1:
            target = open("/dev/null", O_RDWR);
            CHECK(target >= 0);
            CHECK(dup2(source, target) == target);
            return target;
        case 2:
            target = open("/dev/null", O_RDWR);
            CHECK(target >= 0);
            CHECK(dup3(source, target, O_CLOEXEC) == target);
            return target;
        case 3: return fcntl(source, F_DUPFD, 3);
        case 4: return fcntl(source, F_DUPFD_CLOEXEC, 3);
        case 5: return fcntl64(source, F_DUPFD, 3);
        case 6: return fcntl64(source, F_DUPFD_CLOEXEC, 3);
        default: CHECK(0 && "unknown duplication kind");
    }
    return -1;
}

static void socket_report(int fd, int raw) {
    unsigned char out[64], in[64];
    memset(out, 0x66, sizeof out);
    ssize_t sent = raw ? syscall(SYS_write, fd, out, sizeof out) : write(fd, out, sizeof out);
    CHECK(sent == sizeof out);
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    CHECK(poll(&ready, 1, 2000) == 1 && (ready.revents & POLLIN));
    ssize_t received = raw ? syscall(SYS_read, fd, in, sizeof in) : read(fd, in, sizeof in);
    CHECK(received == sizeof in && !memcmp(out, in, sizeof in));
}

static void capability_aliases(int relay, int virtual_alias, uint64_t owned_cookie) {
    int caps[7], chained[7];
    for (int i = 0; i < 7; i++) {
        caps[i] = duplicate_kind(relay, i);
        CHECK(caps[i] >= 0);
        chained[i] = duplicate_kind(caps[i], i);
        CHECK(chained[i] >= 0);
        CHECK(cookie(caps[i]) == owned_cookie && cookie(chained[i]) == owned_cookie);
        int cloexec = i == 2 || i == 4 || i == 6;
        CHECK(!!(fcntl(caps[i], F_GETFD) & FD_CLOEXEC) == cloexec);
        CHECK(!!(fcntl(chained[i], F_GETFD) & FD_CLOEXEC) == cloexec);
        socket_report(caps[i], 0);
        socket_report(chained[i], 1);
    }

    int overwritten[2], reused[2];
    CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, overwritten) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, reused) == 0);
    uint64_t overwritten_cookie = cookie(overwritten[0]);
    uint64_t reused_cookie = cookie(reused[0]);
    CHECK(dup2(overwritten[0], caps[1]) == caps[1]);
    CHECK(close(overwritten[0]) == 0);
    /* Raw replacement tests identity preservation only, not raw-dup tracking. */
    CHECK(syscall(SYS_close, caps[2]) == 0);
    CHECK(syscall(SYS_dup2, reused[0], caps[2]) == caps[2]);
    CHECK(close(reused[0]) == 0);

    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        raw_closed(relay);
        raw_closed(virtual_alias);
        for (int i = 0; i < 7; i++) {
            if (i != 1 && i != 2) raw_closed(caps[i]);
            raw_closed(chained[i]);
        }
        CHECK(count_cookie(owned_cookie) == 0);
        CHECK(cookie(caps[1]) == overwritten_cookie);
        CHECK(cookie(caps[2]) == reused_cookie);
        CHECK(syscall(SYS_write, caps[1], "o", 1) == 1);
        CHECK(syscall(SYS_write, caps[2], "r", 1) == 1);
        _exit(0);
    }
    wait_child(child);
    char byte = 0;
    CHECK(read(overwritten[1], &byte, 1) == 1 && byte == 'o');
    CHECK(read(reused[1], &byte, 1) == 1 && byte == 'r');
    CHECK(cookie(caps[1]) == overwritten_cookie && cookie(caps[2]) == reused_cookie);
    socket_report(relay, 0);
    for (int i = 0; i < 7; i++) {
        if (i != 1 && i != 2) socket_report(caps[i], 0);
        socket_report(chained[i], 0);
        CHECK(close(caps[i]) == 0 && close(chained[i]) == 0);
    }
    CHECK(close(overwritten[1]) == 0 && close(reused[1]) == 0);
    report(virtual_alias);
    puts("PASS original-relay dup/dup2/dup3/fcntl/fcntl64 and chained aliases retain ordinary 64-byte socket I/O, close in fork child, and preserve parent I/O");
    puts("PASS unrelated descriptors survive capability-alias overwrite and raw close/reuse; no raw-dup tracking claimed");
}

static void basic(int relay, int alias, uint64_t owned_cookie) {
    int pipefd[2], sockets[2];
    CHECK(pipe(pipefd) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) == 0);
    int duplicate = dup(alias);
    CHECK(duplicate >= 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        raw_closed(relay);
        raw_closed(alias);
        raw_closed(duplicate);
        CHECK(count_cookie(owned_cookie) == 0);
        CHECK(syscall(SYS_write, pipefd[1], "p", 1) == 1);
        CHECK(syscall(SYS_write, sockets[0], "s", 1) == 1);
        _exit(0);
    }
    wait_child(child);
    char byte = 0;
    CHECK(read(pipefd[0], &byte, 1) == 1 && byte == 'p');
    CHECK(read(sockets[1], &byte, 1) == 1 && byte == 's');
    CHECK(cookie(relay) == owned_cookie);
    report(alias);
    CHECK(close(duplicate) == 0);
    CHECK(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);
    CHECK(close(sockets[0]) == 0 && close(sockets[1]) == 0);
    puts("PASS fork closes original relay and tracked aliases against raw I/O; ordinary pipe/socket and parent report I/O survive");
}

static void reused(int relay, int alias, uint64_t owned_cookie, int reuse_relay) {
    int sockets[2];
    CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) == 0);
    uint64_t unrelated_cookie = cookie(sockets[0]);
    CHECK(unrelated_cookie != owned_cookie);
    int live_alias = dup(alias);
    CHECK(live_alias >= 0);
    int target = reuse_relay ? relay : alias;
    CHECK(syscall(SYS_close, target) == 0);
    CHECK(syscall(SYS_dup2, sockets[0], target) == target);
    CHECK(close(sockets[0]) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        raw_closed(live_alias);
        raw_closed(reuse_relay ? alias : relay);
        CHECK(count_cookie(owned_cookie) == 0);
        CHECK(cookie(target) == unrelated_cookie);
        CHECK(syscall(SYS_write, target, "u", 1) == 1);
        _exit(0);
    }
    wait_child(child);
    char byte = 0;
    CHECK(read(sockets[1], &byte, 1) == 1 && byte == 'u');
    CHECK(cookie(target) == unrelated_cookie);
    report(live_alias);
    CHECK(close(live_alias) == 0);
    CHECK(close(sockets[1]) == 0);
    puts(reuse_relay ?
         "PASS fork preserves unrelated socket raw-reused at original relay FD; old owned aliases close only in child" :
         "PASS fork preserves unrelated socket raw-reused at tracked alias FD; original relay/live aliases close only in child");
}

struct reader {
    int fd;
    atomic_int started;
    atomic_int done;
    ssize_t result;
    unsigned char packet[64];
};

static void *blocked_reader(void *arg) {
    struct reader *reader = arg;
    atomic_store(&reader->started, 1);
    reader->result = read(reader->fd, reader->packet, sizeof reader->packet);
    atomic_store(&reader->done, 1);
    return NULL;
}

static void blocked_pin(int relay, int alias, uint64_t owned_cookie) {
    CHECK(count_cookie(owned_cookie) == 2);
    struct reader reader = {.fd = alias};
    atomic_init(&reader.started, 0);
    atomic_init(&reader.done, 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, blocked_reader, &reader) == 0);
    int pinned = 0;
    for (int i = 0; i < 2000; i++) {
        CHECK(!atomic_load(&reader.done));
        if (atomic_load(&reader.started) && count_cookie(owned_cookie) > 2) {
            pinned = 1;
            break;
        }
        usleep(1000);
    }
    CHECK(pinned && !atomic_load(&reader.done));
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        raw_closed(relay);
        raw_closed(alias);
        CHECK(count_cookie(owned_cookie) == 0);
        _exit(0);
    }
    wait_child(child);
    CHECK(!atomic_load(&reader.done));
    unsigned char output[65] = {0};
    memset(output + 1, 0x54, 64);
    CHECK(write(alias, output, sizeof output) == sizeof output);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(reader.result == sizeof reader.packet);
    CHECK(!memcmp(reader.packet, output + 1, sizeof reader.packet));
    CHECK(count_cookie(owned_cookie) == 2);
    report(alias);
    puts("PASS blocked virtual read exposes an internal pin before fork; child inherits zero matching endpoint cookies; parent read resumes");
}

static int exec_child(int argc, char **argv) {
    CHECK(argc == 5);
    int fresh = atoi(argv[2]), peer = atoi(argv[3]);
    const char *owner = getenv("UHF_OWNER_PID");
    CHECK(owner && !strcmp(owner, argv[4]));
    CHECK(atoi(owner) != getpid());
    CHECK(getenv("UHF_ENABLE") && !strcmp(getenv("UHF_ENABLE"), "1"));
    CHECK(getenv("UHF_RELAY_FD") && atoi(getenv("UHF_RELAY_FD")) == fresh);
    CHECK(!(fcntl(fresh, F_GETFD) & FD_CLOEXEC));
    ERR(open(node, O_RDWR | O_NONBLOCK), ENOENT);
    const char *descriptor = "/sys/devices/virtual/userland-fido/usb0/hid0/report_descriptor";
    ERR(open(descriptor, O_RDONLY), ENOENT);
    CHECK(syscall(SYS_write, fresh, "f", 1) == 1);
    char byte = 0;
    CHECK(syscall(SYS_read, peer, &byte, 1) == 1 && byte == 'f');
    CHECK(syscall(SYS_write, peer, "r", 1) == 1);
    CHECK(syscall(SYS_read, fresh, &byte, 1) == 1 && byte == 'r');
    puts("PASS inherited owner marker disables fresh-endpoint virtual opens after exec while preserving unrelated raw socket access");
    return 0;
}

static int inactive_owner(int argc, char **argv) {
    CHECK(argc == 4);
    int relay = atoi(argv[2]);
    CHECK(relay >= 3);
    const char *owner = getenv("UHF_OWNER_PID");
    CHECK(owner && !strcmp(owner, argv[3]));
    CHECK(getenv("UHF_ENABLE") && !strcmp(getenv("UHF_ENABLE"), "1"));
    CHECK(getenv("UHF_RELAY_FD") && atoi(getenv("UHF_RELAY_FD")) == relay);
    int initial_flags = fcntl(relay, F_GETFD);
    CHECK(initial_flags >= 0 && !(initial_flags & FD_CLOEXEC));
    ERR(open(node, O_RDWR | O_NONBLOCK), ENOENT);
    const char *descriptor = "/sys/devices/virtual/userland-fido/usb0/hid0/report_descriptor";
    ERR(open(descriptor, O_RDONLY), ENOENT);
    unsigned char out[64], in[64];
    memset(out, 0x56, sizeof out);
    CHECK(syscall(SYS_write, relay, out, sizeof out) == sizeof out);
    struct pollfd ready = {.fd = relay, .events = POLLIN};
    CHECK(poll(&ready, 1, 2000) == 1 && (ready.revents & POLLIN));
    CHECK(syscall(SYS_read, relay, in, sizeof in) == sizeof in);
    CHECK(!memcmp(out, in, sizeof in));
    CHECK(fcntl(relay, F_GETFD) == initial_flags);
    owner = getenv("UHF_OWNER_PID");
    CHECK(owner && !strcmp(owner, argv[3]));
    CHECK(close(relay) == 0);
    puts("PASS invalid/mismatched owner marker stays unchanged; virtual opens absent; raw socket and descriptor flags preserved");
    return 0;
}

static void fork_exec(int relay, int alias, uint64_t owned_cookie) {
    int fresh[2];
    CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fresh) == 0);
    CHECK(cookie(fresh[0]) != owned_cookie);
    const char *marker = getenv("UHF_OWNER_PID");
    CHECK(marker && atoi(marker) == getpid());
    char owner[32], fd_arg[32], peer_arg[32];
    CHECK(snprintf(owner, sizeof owner, "%ld", (long)getpid()) > 0);
    CHECK(snprintf(fd_arg, sizeof fd_arg, "%d", fresh[0]) > 0);
    CHECK(snprintf(peer_arg, sizeof peer_arg, "%d", fresh[1]) > 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        raw_closed(relay);
        raw_closed(alias);
        CHECK(count_cookie(owned_cookie) == 0);
        CHECK(setenv("UHF_RELAY_FD", fd_arg, 1) == 0);
        execl("/proc/self/exe", "fork-isolation", "exec-child", fd_arg, peer_arg, owner, (char *)NULL);
        _exit(90);
    }
    wait_child(child);
    report(alias);
    CHECK(close(fresh[0]) == 0 && close(fresh[1]) == 0);
    puts("PASS parent retains report I/O after fork-plus-exec child opt-out");
}

int main(int argc, char **argv) {
    alarm(12);
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1 && !strcmp(argv[1], "exec-child")) return exec_child(argc, argv);
    if (argc > 1 && !strcmp(argv[1], "inactive-owner")) return inactive_owner(argc, argv);
    CHECK(argc == 3);
    int relay = atoi(argv[2]);
    CHECK(relay >= 3);
    CHECK(fcntl(relay, F_GETFD) & FD_CLOEXEC);
    const char *owner = getenv("UHF_OWNER_PID");
    CHECK(owner && atoi(owner) == getpid());
    int alias = open(node, O_RDWR);
    CHECK(alias >= 0);
    uint64_t owned_cookie = cookie(relay);
    CHECK(cookie(alias) == owned_cookie);
    if (!strcmp(argv[1], "basic")) basic(relay, alias, owned_cookie);
    else if (!strcmp(argv[1], "relay-reuse")) reused(relay, alias, owned_cookie, 1);
    else if (!strcmp(argv[1], "alias-reuse")) reused(relay, alias, owned_cookie, 0);
    else if (!strcmp(argv[1], "blocked-pin")) blocked_pin(relay, alias, owned_cookie);
    else if (!strcmp(argv[1], "fork-exec")) fork_exec(relay, alias, owned_cookie);
    else if (!strcmp(argv[1], "capability-aliases")) capability_aliases(relay, alias, owned_cookie);
    else CHECK(0 && "unknown mode");
    CHECK(close(alias) == 0);
    CHECK(close(relay) == 0);
    puts("PASS isolated standard-libc-fork lifecycle test; synthetic reports only");
    return 0;
}
