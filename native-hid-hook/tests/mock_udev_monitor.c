#define _GNU_SOURCE
#include "udev_abi.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <unistd.h>
extern struct udev *udev_ref(struct udev *);
extern int udev_monitor_filter_update(struct udev_monitor *);
struct udev_monitor {struct udev *context;int fd;int refs;};
static int failing(const char *what){const char *s=getenv("UHF_MOCK_FAIL");return s&&!strcmp(s,what);}
struct udev_monitor *udev_monitor_new_from_netlink(struct udev *ctx,const char *name){
    (void)name;
    if(failing("new")){errno=EPERM;return NULL;}
    struct udev_monitor *m=calloc(1,sizeof(*m));assert(m);
    m->fd=fcntl(atoi(getenv("UHF_MOCK_REAL_FD")),F_DUPFD_CLOEXEC,100);assert(m->fd>=0);
    assert(fcntl(m->fd,F_SETFL,O_NONBLOCK)==0);m->context=udev_ref(ctx);m->refs=1;return m;
}
struct udev_monitor *udev_monitor_ref(struct udev_monitor *m){m->refs++;return m;}
struct udev_monitor *udev_monitor_unref(struct udev_monitor *m){if(!--m->refs){close(m->fd);udev_unref(m->context);free(m);}return NULL;}
/* Match libudev's preemptible enable -> filter_update call. A mock that simply
 * returns success hides recursive interposition deadlocks in the normal hook. */
int udev_monitor_enable_receiving(struct udev_monitor *m){if(failing("enable")){errno=EPERM;return -EPERM;}return udev_monitor_filter_update(m);}
int udev_monitor_get_fd(struct udev_monitor *m){if(failing("getfd")){errno=EBADF;return -EBADF;}if(failing("changedfd"))return atoi(getenv("UHF_MOCK_REAL_FD"));return m->fd;}
struct mock_device {struct udev *context;int refs;};
static struct mock_device *devices[128];
static int find_device(struct udev_device *p){for(int i=0;i<128;i++)if(devices[i]==(void*)p)return i;return -1;}
struct udev_device *udev_monitor_receive_device(struct udev_monitor *m){
    unsigned char b;if(recv(m->fd,&b,1,MSG_DONTWAIT)!=1)return NULL;
    for(int i=0;i<128;i++)if(!devices[i]){devices[i]=calloc(1,sizeof(*devices[i]));assert(devices[i]);devices[i]->context=udev_ref(m->context);devices[i]->refs=1;return (void*)devices[i];}
    errno=ENOSPC;return NULL;
}
struct udev_device *udev_device_ref(struct udev_device *p){int i=find_device(p);if(i>=0){devices[i]->refs++;return p;}struct udev_device *(*f)(struct udev_device*)=dlsym(RTLD_NEXT,"udev_device_ref");return f(p);}
struct udev_device *udev_device_unref(struct udev_device *p){int i=find_device(p);if(i>=0){if(!--devices[i]->refs){udev_unref(devices[i]->context);free(devices[i]);devices[i]=NULL;}return NULL;}struct udev_device *(*f)(struct udev_device*)=dlsym(RTLD_NEXT,"udev_device_unref");return f(p);}
#define GETTER(name,value) const char *name(struct udev_device *p){if(find_device(p)>=0)return value;const char *(*f)(struct udev_device*)=dlsym(RTLD_NEXT,#name);return f(p);}
GETTER(udev_device_get_subsystem,"mem")
GETTER(udev_device_get_action,"change")
GETTER(udev_device_get_syspath,"/sys/devices/mock-unrelated/mem0")
GETTER(udev_device_get_devnode,"/dev/mock-unrelated-mem0")

int udev_monitor_filter_add_match_subsystem_devtype(struct udev_monitor *m,const char *sub,const char *typ){(void)m;(void)sub;(void)typ;if(failing("filter")){errno=EIO;return -EIO;}return 0;}
int udev_monitor_filter_add_match_tag(struct udev_monitor *m,const char *tag){(void)m;(void)tag;return 0;}
int udev_monitor_filter_remove(struct udev_monitor *m){(void)m;return 0;}
int udev_monitor_filter_update(struct udev_monitor *m){(void)m;if(failing("update")){errno=EIO;return -EIO;}return 0;}
