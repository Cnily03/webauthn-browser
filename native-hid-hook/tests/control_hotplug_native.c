#define _GNU_SOURCE
#include "udev_abi.h"
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
extern struct udev_device *udev_monitor_receive_device(struct udev_monitor *);
extern const char *udev_device_get_action(struct udev_device *);
static struct udev_device *devices[64];
static char *nodes[64], *paths[64];
static int handles[64];
int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(handles, -1, sizeof(handles));
    struct udev *ctx = udev_new(); assert(ctx);
    struct udev_monitor *(*sim)(struct udev *) = dlsym(RTLD_DEFAULT, "uhf_simulation_monitor_new");
    assert(sim);
    struct udev_monitor *m = sim(ctx); assert(m);
    assert(udev_monitor_enable_receiving(m) == 0);
    int mfd = udev_monitor_get_fd(m); assert(mfd >= 0);
    puts("MONITOR");
    char line[512], command[64], action[64]; int slot;
    while (fgets(line, sizeof(line), stdin)) {
        slot=0; action[0]=0;
        assert(sscanf(line,"%63s %d %63s",command,&slot,action)>=1);
        assert(slot>=0 && slot<64);
        if (!strcmp(command,"event")) {
            struct pollfd p={.fd=mfd,.events=POLLIN}; assert(poll(&p,1,3000)==1);
            struct udev_device *d=udev_monitor_receive_device(m); assert(d);
            assert(!strcmp(udev_device_get_action(d),action));
            if(devices[slot]) udev_device_unref(devices[slot]);
            free(nodes[slot]);free(paths[slot]); devices[slot]=d;
            nodes[slot]=strdup(udev_device_get_devnode(d)); paths[slot]=strdup(udev_device_get_syspath(d));
            assert(nodes[slot] && paths[slot]);
            printf("EVENT %d %s %s\n",slot,nodes[slot],paths[slot]);
        } else if (!strcmp(command,"open")) {
            assert(nodes[slot]); handles[slot]=open(nodes[slot],O_RDWR|O_NONBLOCK|O_CLOEXEC); assert(handles[slot]>=0);
            printf("OPEN %d\n",slot);
        } else if (!strcmp(command,"io")) {
            unsigned char b[65]={0}; memset(b+1,0x51,64);
            assert(write(handles[slot],b,65)==65);
            puts("WROTE");
        } else if (!strcmp(command,"read")) {
            unsigned char b[64]; struct pollfd p={.fd=handles[slot],.events=POLLIN}; assert(poll(&p,1,3000)==1);
            assert(read(handles[slot],b,64)==64); for(int i=0;i<64;i++)assert(b[i]==0x51);
            puts("READ");
        } else if (!strcmp(command,"dead")) {
            unsigned char b[65]={0}; int size=0;
            errno=0; assert(read(handles[slot],b,64)==-1 && errno==ENODEV);
            errno=0; assert(write(handles[slot],b,65)==-1 && errno==ENODEV);
            errno=0; assert(ioctl(handles[slot],0x80044801,&size)==-1 && errno==ENODEV);
            errno=0; assert(open(nodes[slot],O_RDWR|O_NONBLOCK)==-1 && errno==ENODEV);
            errno=0; assert(!udev_device_new_from_syspath(ctx,paths[slot]) && errno==ENODEV);
            assert(!strcmp(udev_device_get_devnode(devices[slot]),nodes[slot]));
            puts("DEAD");
        } else if (!strcmp(command,"hidden")) {
            struct udev_enumerate *e=udev_enumerate_new(ctx);assert(e);
            assert(!udev_enumerate_add_match_subsystem(e,"hidraw")); assert(!udev_enumerate_scan_devices(e));
            for(struct udev_list_entry *l=udev_enumerate_get_list_entry(e);l;l=udev_list_entry_get_next(l)) {
                assert(!strstr(udev_list_entry_get_name(l),"userland-fido"));
            }
            udev_enumerate_unref(e); puts("HIDDEN");
        } else if (!strcmp(command,"fork") || !strcmp(command,"forkrace")) {
          for(int pass=0;pass<(!strcmp(command,"forkrace") ? 128 : 1);pass++) {
            pid_t child=fork();assert(child>=0);
            if(!child) {
                assert(fcntl(atoi(getenv("UHF_CONTROL_FD")),F_GETFD)==-1 && errno==EBADF);
                assert(fcntl(mfd,F_GETFD)==-1 && errno==EBADF);
                assert(udev_monitor_get_fd(m)==-1 && errno==ENODEV);
                if(handles[slot]>=0) assert(fcntl(handles[slot],F_GETFD)==-1 && (errno==ENODEV || errno==EBADF));
                for(int fd=3;fd<512;fd++) {
                    int kind=0;socklen_t len=sizeof(kind);
                    assert(syscall(SYS_getsockopt,fd,SOL_SOCKET,SO_TYPE,&kind,&len)<0 || kind!=SOCK_SEQPACKET);
                }
                _exit(0);
            }
            int status;assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
          } puts("FORK");
        } else if(!strcmp(command,"quit")) { break; }
        else abort();
    }
    for(int i=0;i<64;i++) {if(handles[i]>=0)close(handles[i]);if(devices[i])udev_device_unref(devices[i]);free(nodes[i]);free(paths[i]);}
    udev_monitor_unref(m);udev_unref(ctx); puts("DONE");return 0;
}
