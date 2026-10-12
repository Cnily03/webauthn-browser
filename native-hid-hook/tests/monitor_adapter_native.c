#define _GNU_SOURCE
#include "udev_abi.h"
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/hidraw.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
extern struct udev_device *udev_monitor_receive_device(struct udev_monitor *);
extern const char *udev_device_get_action(struct udev_device *);
extern int udev_monitor_filter_add_match_subsystem_devtype(struct udev_monitor *,const char *,const char *);
extern int udev_monitor_filter_add_match_tag(struct udev_monitor *,const char *);
extern int udev_monitor_filter_remove(struct udev_monitor *);
extern int udev_monitor_filter_update(struct udev_monitor *);
extern struct udev_monitor *udev_monitor_ref(struct udev_monitor *);
static struct udev_device *devices[64];
static char *nodes[64], *paths[64];
static int handles[64];
struct monitor_activity {struct udev_monitor *monitor;atomic_int stop;atomic_uint calls;};
static void *monitor_ref_worker(void *pointer) {
    struct monitor_activity *activity=pointer;
    while(!atomic_load(&activity->stop)) {
        assert(udev_monitor_ref(activity->monitor)==activity->monitor);
        udev_monitor_unref(activity->monitor);
        atomic_fetch_add(&activity->calls,1);
    }
    return NULL;
}
static const unsigned char descriptor[]={
    0x06,0xd0,0xf1,0x09,0x01,0xa1,0x01,0x09,0x20,0x15,0x00,0x26,0xff,0x00,
    0x75,0x08,0x95,0x40,0x81,0x02,0x09,0x21,0x15,0x00,0x26,0xff,0x00,
    0x75,0x08,0x95,0x40,0x91,0x02,0xc0
};
static void descriptor_path(struct udev_device *device,char *path,size_t size) {
    struct udev_device *hid=udev_device_get_parent(device);assert(hid);
    int n=snprintf(path,size,"%s/report_descriptor",udev_device_get_syspath(hid));
    assert(n>0 && (size_t)n<size);
}
static void check_metadata(struct udev *ctx,struct udev_device *device,int slot) {
    assert(!strcmp(udev_device_get_subsystem(device),"hidraw"));
    assert(!strcmp(udev_device_get_devnode(device),nodes[slot]));
    assert(!strcmp(udev_device_get_syspath(device),paths[slot]));
    assert(udev_device_get_udev(device)==ctx);
    struct udev_device *hid=udev_device_get_parent(device);assert(hid);
    assert(!strcmp(udev_device_get_subsystem(hid),"hid"));
    assert(!strcmp(udev_device_get_property_value(hid,"HID_ID"),"0003:00001209:0000F1D0"));
    const char *name=udev_device_get_property_value(hid,"HID_NAME");assert(name && *name);
    const char *unique=udev_device_get_property_value(hid,"HID_UNIQ");assert(unique && *unique);
    assert(!udev_device_get_property_value(device,"HID_ID"));
    struct udev_device *usb=udev_device_get_parent_with_subsystem_devtype(hid,"usb","usb_device");assert(usb);
    assert(usb==udev_device_get_parent(hid));
    assert(!strcmp(udev_device_get_subsystem(usb),"usb"));
    assert(!strcmp(udev_device_get_devtype(usb),"usb_device"));
    assert(!strcmp(udev_device_get_sysattr_value(usb,"product"),name));
    assert(!udev_device_get_sysattr_value(hid,"product"));
    assert(!udev_device_get_parent(usb));
    assert(udev_device_get_syspath(usb) && *udev_device_get_syspath(usb));
    char path[512];descriptor_path(device,path,sizeof(path));
    unsigned char bytes[sizeof(descriptor)+1];
    int fd=open64(path,O_RDONLY|O_CLOEXEC);assert(fd>=0);
    struct stat st;assert(!fstat(fd,&st) && st.st_size==(off_t)sizeof(descriptor));
    assert((fcntl(fd,F_GETFL)&O_ACCMODE)==O_RDONLY);
    assert(fcntl(fd,F_GET_SEALS)==(F_SEAL_SEAL|F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW));
    errno=0;assert(write(fd,"x",1)==-1 && errno==EBADF);
    assert(read(fd,bytes,sizeof(bytes))==(ssize_t)sizeof(descriptor));
    assert(!memcmp(bytes,descriptor,sizeof(descriptor)));
    assert(read(fd,bytes,sizeof(bytes))==0);assert(!close(fd));
    FILE *stream=fopen64(path,"re");assert(stream);
    assert(fread(bytes,1,sizeof(bytes),stream)==sizeof(descriptor));
    assert(!memcmp(bytes,descriptor,sizeof(descriptor)));assert(!fclose(stream));
    int size=0;assert(!ioctl(handles[slot],HIDIOCGRDESCSIZE,&size) && size==(int)sizeof(descriptor));
    struct hidraw_report_descriptor report={.size=HID_MAX_DESCRIPTOR_SIZE};
    assert(!ioctl(handles[slot],HIDIOCGRDESC,&report));
    assert(!memcmp(report.value,descriptor,sizeof(descriptor)));
    struct hidraw_devinfo identity;
    assert(!ioctl(handles[slot],HIDIOCGRAWINFO,&identity));
    assert(identity.bustype==3 && identity.vendor==0x1209 && (unsigned short)identity.product==0xf1d0);
}
int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(handles, -1, sizeof(handles));
    struct udev *ctx = udev_new(); assert(ctx);
    struct udev_enumerate *early=NULL;
    struct udev_monitor *m=NULL;
    int mfd=-1;
    puts("WAITING");
    char line[512], command[64], action[64]; int slot;
    while (fgets(line, sizeof(line), stdin)) {
        slot=0; action[0]=0;
        assert(sscanf(line,"%63s %d %63s",command,&slot,action)>=1);
        assert(slot>=0 && slot<64);
        if (!strcmp(command,"new")) {
            assert(!m); assert(setenv("UHF_MOCK_FAIL",action,1)==0);
            errno=0;m=udev_monitor_new_from_netlink(ctx,"udev");
            if(!strcmp(action,"new")){assert(!m && errno==EPERM);puts("NEW_ERROR");continue;}
            assert(m);
            errno=0;int filtered=slot==2 ? 0 : udev_monitor_filter_add_match_subsystem_devtype(m,slot ? "input" : "hidraw",NULL);
            if(!strcmp(action,"filter")){assert(filtered==-EIO && errno==EIO);puts("FILTER_ERROR");continue;}
            assert(!filtered);errno=0;int enabled=udev_monitor_enable_receiving(m);
            if(!strcmp(action,"enable")){assert(enabled==-EPERM && errno==EPERM);puts("ENABLE_ERROR");continue;}
            if(!strcmp(action,"update")){assert(enabled==-EIO && errno==EIO);puts("UPDATE_ERROR");continue;}
            assert(!enabled);errno=0;mfd=udev_monitor_get_fd(m);
            if(!strcmp(action,"getfd")){assert(mfd==-EBADF && errno==EBADF);puts("FD_ERROR");continue;}
            assert(mfd>=0);puts("MONITOR");
        } else if(!strcmp(command,"changed")) {
            assert(!setenv("UHF_MOCK_FAIL","changedfd",1));errno=0;
            assert(udev_monitor_get_fd(m)==-1 && errno==ENODEV);puts("CHANGED");
        } else if(!strcmp(command,"reuse")) {
            int pair[2];assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair));
            assert(!syscall(SYS_close,mfd));assert(dup2(pair[0],mfd)==mfd);
            assert(send(pair[1],"X",1,0)==1);
            errno=0;assert(udev_monitor_get_fd(m)==-1 && errno==ENODEV);
            errno=0;assert(!udev_monitor_receive_device(m) && errno==ENODEV);
            assert(!udev_monitor_unref(m));m=NULL;
            char b;assert(recv(mfd,&b,1,MSG_DONTWAIT)==1 && b=='X');
            close(mfd);close(pair[0]);close(pair[1]);mfd=-1;puts("REUSE");
        } else if(!strcmp(command,"replace")) {
            int oldfd=mfd;struct udev_monitor *old=m;
            assert(!syscall(SYS_close,oldfd));
            m=udev_monitor_new_from_netlink(ctx,"udev");assert(m);
            assert(!udev_monitor_filter_add_match_subsystem_devtype(m,"hidraw",NULL));
            assert(!udev_monitor_enable_receiving(m));mfd=udev_monitor_get_fd(m);assert(mfd==oldfd);
            errno=0;assert(udev_monitor_get_fd(old)==-1 && errno==ENODEV);
            assert(!udev_monitor_unref(old));
            // Allow old worker resource cleanup to run before checking identity.
            usleep(10000);assert(udev_monitor_get_fd(m)==mfd);puts("REPLACED");
        } else if(!strcmp(command,"drop")) {
            assert(m);assert(!udev_monitor_unref(m));m=NULL;mfd=-1;puts("DROPPED");
        } else if(!strcmp(command,"ref")) {
            assert(udev_monitor_ref(m)==m);udev_monitor_unref(m);puts("REF");
        } else if(!strcmp(command,"update")) {
            assert(!setenv("UHF_MOCK_FAIL","update",1));errno=0;
            assert(udev_monitor_filter_update(m)==-EIO && errno==EIO);
            assert(!setenv("UHF_MOCK_FAIL","okay",1));errno=ECHILD;
            assert(!udev_monitor_filter_update(m) && errno==ECHILD);puts("UPDATE");
        } else if(!strcmp(command,"refthreads")) {
            // The caller keeps its owner reference throughout. No unsupported
            // race between final unref and a concurrent genuine operation.
            struct monitor_activity activity={.monitor=m};
            atomic_init(&activity.stop,0);atomic_init(&activity.calls,0);
            pthread_t threads[4];
            for(int i=0;i<4;i++)assert(!pthread_create(&threads[i],NULL,monitor_ref_worker,&activity));
            while(atomic_load(&activity.calls)<16)usleep(1000);
            for(int i=0;i<16;i++) {
                pid_t child=fork();assert(child>=0);
                if(!child) {
                    errno=0;assert(udev_monitor_filter_update(m)==-1 && errno==ENODEV);
                    _exit(0);
                }
                int status;assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
            }
            atomic_store(&activity.stop,1);
            for(int i=0;i<4;i++)assert(!pthread_join(threads[i],NULL));
            assert(udev_monitor_get_fd(m)==mfd);puts("REFTHREADS");
        } else if(!strcmp(command,"real")) {
            struct pollfd p={.fd=mfd,.events=POLLIN};assert(poll(&p,1,3000)==1);
            struct udev_device *d=udev_monitor_receive_device(m);assert(d);
            assert(!strcmp(udev_device_get_subsystem(d),"mem"));
            assert(!strcmp(udev_device_get_action(d),"change"));udev_device_unref(d);puts("REAL");
        } else if(!strcmp(command,"idle")) {
            struct pollfd p={.fd=mfd,.events=POLLIN};
            // One stale genuine-ready token is allowed if a receive raced the
            // worker's poll; draining it cannot consume or synthesize an event.
            if(poll(&p,1,20)==1){assert(!udev_monitor_receive_device(m));}
            assert(poll(&p,1,20)==0);puts("IDLE");
        } else if(!strcmp(command,"all")) {
            assert(!udev_monitor_filter_remove(m));puts("ALL");
        } else if(!strcmp(command,"tag")) {
            assert(!udev_monitor_filter_add_match_tag(m,"unrelated"));puts("TAG");
        } else if (!strcmp(command,"event")) {
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
            char path[512];descriptor_path(devices[slot],path,sizeof(path));
            errno=0;assert(open64(path,O_RDONLY)==-1 && errno==ENODEV);
            errno=0;assert(!fopen64(path,"re") && errno==ENODEV);
            puts("DEAD");
        } else if (!strcmp(command,"enumerator")) {
            assert(!early);early=udev_enumerate_new(ctx);assert(early);
            assert(!udev_enumerate_scan_devices(early));puts("ENUMERATOR");
        } else if (!strcmp(command,"enumerated")) {
            assert(early);assert(!udev_enumerate_scan_devices(early));
            int found=0;
            for(struct udev_list_entry *l=udev_enumerate_get_list_entry(early);l;l=udev_list_entry_get_next(l)) {
                const char *name=udev_list_entry_get_name(l);assert(name);
                if(!strstr(name,"userland-fido"))continue;
                found++;assert(!strcmp(action,"visible"));assert(!strcmp(name,paths[slot]));
                assert(!udev_list_entry_get_value(l));assert(udev_list_entry_get_by_name(l,name)==l);
                struct udev_device *device=udev_device_new_from_syspath(ctx,name);assert(device);
                check_metadata(ctx,device,slot);udev_device_unref(device);
            }
            assert(found==(!strcmp(action,"visible") ? 1 : 0));puts("ENUMERATED");
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
                assert(udev_monitor_filter_update(m)==-1 && errno==ENODEV);
                if(handles[slot]>=0) assert(fcntl(handles[slot],F_GETFD)==-1 && (errno==ENODEV || errno==EBADF));
                for(int fd=3;fd<512;fd++) {
                    int kind=0;socklen_t len=sizeof(kind);
                    if(syscall(SYS_getsockopt,fd,SOL_SOCKET,SO_TYPE,&kind,&len)==0 && kind==SOCK_SEQPACKET){
                        unsigned long long cookie=0,real_cookie=0;socklen_t n=sizeof(cookie);
                        assert(!getsockopt(fd,SOL_SOCKET,SO_COOKIE,&cookie,&n));
                        n=sizeof(real_cookie);assert(!getsockopt(atoi(getenv("UHF_MOCK_REAL_FD")),SOL_SOCKET,SO_COOKIE,&real_cookie,&n));
                        assert(cookie==real_cookie); // unrelated genuine-source fixture only
                    }
                }
                _exit(0);
            }
            int status;assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
          } puts("FORK");
        } else if(!strcmp(command,"quit")) { break; }
        else abort();
    }
    for(int i=0;i<64;i++) {if(handles[i]>=0)close(handles[i]);if(devices[i])udev_device_unref(devices[i]);free(nodes[i]);free(paths[i]);}
    if(m){udev_monitor_unref(m);}
    if(early)udev_enumerate_unref(early);
    udev_unref(ctx); puts("DONE");return 0;
}
