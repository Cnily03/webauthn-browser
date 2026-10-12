#define _GNU_SOURCE
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>

extern int uh_open(const char *, int, mode_t, int, int);
static mode_t mode_arg(int flags, va_list args) {
    return ((flags & O_CREAT) || ((flags & O_TMPFILE) == O_TMPFILE))
        ? (mode_t)va_arg(args, unsigned int) : 0;
}
int uh_c_open(const char *path, int flags, ...) {
    va_list args; va_start(args, flags); mode_t mode = mode_arg(flags, args); va_end(args);
    return uh_open(path, flags, mode, AT_FDCWD, 0);
}
int uh_c_open64(const char *path, int flags, ...) {
    va_list args; va_start(args, flags); mode_t mode = mode_arg(flags, args); va_end(args);
    return uh_open(path, flags, mode, AT_FDCWD, 1);
}
int uh_c_openat(int dirfd, const char *path, int flags, ...) {
    va_list args; va_start(args, flags); mode_t mode = mode_arg(flags, args); va_end(args);
    return uh_open(path, flags, mode, dirfd, 2);
}
int uh_c_openat64(int dirfd, const char *path, int flags, ...) {
    va_list args; va_start(args, flags); mode_t mode = mode_arg(flags, args); va_end(args);
    return uh_open(path, flags, mode, dirfd, 3);
}
/* fcntl/ioctl trampolines preserve the incoming machine argument register.
 * On x86_64 this also preserves calls without an optional argument without
 * executing va_arg on a missing argument. Interpretation is request-specific
 * in Rust; foreign calls are forwarded with that register unchanged. */
