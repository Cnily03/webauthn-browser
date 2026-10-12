/* Explicit ABI harness, NOT Chromium. Stdin/stdout carry 64-byte reports. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/hidraw.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
static void fail(const char *message) { perror(message); exit(2); }
static void output(const unsigned char *bytes, size_t length) {
    while (length) { ssize_t n=write(STDOUT_FILENO,bytes,length); if(n<0 && errno==EINTR)continue; if(n<=0)fail("stdout");bytes+=n;length-=n; }
}
int main(void) {
    int fd=open("/dev/userland-fido-hidraw0",O_RDWR|O_NONBLOCK|O_CLOEXEC);
    if(fd<0)fail("virtual FIDO open");
    int size=0;
    if(ioctl(fd,HIDIOCGRDESCSIZE,&size)<0 || size!=34)fail("fixed descriptor size");
    struct hidraw_report_descriptor descriptor={.size=34};
    if(ioctl(fd,HIDIOCGRDESC,&descriptor)<0)fail("FIDO descriptor");
    const unsigned char prefix[]={0x06,0xd0,0xf1,0x09,0x01,0xa1,0x01};
    if(memcmp(descriptor.value,prefix,sizeof prefix))fail("FIDO collection");
    unsigned char outgoing[65]={0},incoming[64];size_t buffered=0;
    for(;;) {
        struct pollfd waiters[2]={{.fd=STDIN_FILENO,.events=POLLIN},{.fd=fd,.events=POLLIN}};
        int result=poll(waiters,2,5000);if(result<0 && errno==EINTR)continue;if(result<=0)fail("poll deadline");
        if(waiters[0].revents&(POLLIN|POLLHUP)) {
            ssize_t n=read(STDIN_FILENO,outgoing+1+buffered,64-buffered);
            if(n==0){if(buffered)fail("truncated stdin report");break;}
            if(n<0)fail("stdin");
            buffered+=(size_t)n;
            if(buffered==64) {
                ssize_t written=write(fd,outgoing,sizeof outgoing);
                if(written!=65)fail("65-byte hidraw write");
                buffered=0;
            }
        }
        if(waiters[1].revents&POLLIN) {
            ssize_t n=read(fd,incoming,sizeof incoming);
            if(n!=64)fail("64-byte hidraw read");
            output(incoming,64);
        }
        if(waiters[1].revents&(POLLERR|POLLHUP|POLLNVAL))fail("FIDO channel closed");
    }
    if(close(fd))fail("virtual close");
    return 0;
}
