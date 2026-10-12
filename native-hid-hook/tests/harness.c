#define _GNU_SOURCE
#include "udev_abi.h"
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/hidraw.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdatomic.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d: %s (errno=%d)\n",__LINE__,#x,errno); exit(2); } } while(0)
#define ERR(x,e) do { errno=0; CHECK((x)==-1 && errno==(e)); } while(0)
static int inherited_relay=-1;
static const char *node="/dev/userland-fido-hidraw0";
static const char *raw="/sys/devices/virtual/userland-fido/usb0/hid0/hidraw0";
static const char *desc="/sys/devices/virtual/userland-fido/usb0/hid0/report_descriptor";
static const unsigned char expected[]={0x06,0xd0,0xf1,0x09,0x01,0xa1,0x01,0x09,0x20,0x15,0x00,0x26,0xff,0x00,0x75,0x08,0x95,0x40,0x81,0x02,0x09,0x21,0x15,0x00,0x26,0xff,0x00,0x75,0x08,0x95,0x40,0x91,0x02,0xc0};
static void pass_through(void) {
 int p[2]; CHECK(pipe(p)==0); CHECK(write(p[1],"hello",5)==5); int n=0; CHECK(ioctl(p[0],FIONREAD,&n)==0 && n==5);
 CHECK(ioctl(p[0],FIOCLEX)==0); CHECK(fcntl(p[0],F_GETFD)&FD_CLOEXEC);
 char buf[10]={0}; CHECK(read(p[0],buf,5)==5 && !strcmp(buf,"hello"));
 struct iovec vec[2]={{.iov_base="ab",.iov_len=2},{.iov_base="cd",.iov_len=2}};
 CHECK(writev(p[1],vec,2)==4); CHECK(read(p[0],buf,4)==4 && !memcmp(buf,"abcd",4));
 CHECK(close(p[0])==0);CHECK(close(p[1])==0);
 int fd=open("/dev/null",O_RDWR);CHECK(fd>=0);CHECK(write(fd,"x",1)==1);CHECK(read(fd,buf,1)==0);CHECK(close(fd)==0);
 char path[]="/tmp/uhf-harness-XXXXXX"; fd=mkstemp(path);CHECK(fd>=0);CHECK(close(fd)==0);
 fd=open(path,O_CREAT|O_TRUNC|O_RDWR,0600);CHECK(fd>=0); struct stat st;CHECK(fstat(fd,&st)==0 && (st.st_mode&0777)==0600);
 struct flock lock={.l_type=F_WRLCK,.l_whence=SEEK_SET};CHECK(fcntl(fd,F_SETLK,&lock)==0);CHECK(fcntl(fd,F_GETLK,&lock)==0);
 CHECK(close(fd)==0);CHECK(unlink(path)==0);puts("PASS ordinary files, pipe I/O, ioctl with/without arg, writev, fcntl int/pointer/no-arg pass-through");
}
static int enumerate(struct udev *u,const char *sub,int deny,int property) {
 struct udev_enumerate *e=udev_enumerate_new(u);CHECK(e);CHECK(udev_enumerate_ref(e)==e);udev_enumerate_unref(e);
 if(sub)CHECK(udev_enumerate_add_match_subsystem(e,sub)==0);
 if(deny)CHECK(udev_enumerate_add_nomatch_subsystem(e,"hidraw")==0);
 if(property)CHECK(udev_enumerate_add_match_property(e,"IMPOSSIBLE_UHF_PROPERTY","value")==0);
 CHECK(udev_enumerate_scan_devices(e)==0);
 int found=0;unsigned count=0;uint64_t hash=1469598103934665603ULL;
 for(struct udev_list_entry *i=udev_enumerate_get_list_entry(e);i;i=udev_list_entry_get_next(i)) {
  const char *name=udev_list_entry_get_name(i);CHECK(name);CHECK(++count<500000);
  if(!strcmp(name,raw)) {found++;CHECK(udev_list_entry_get_value(i)==NULL);CHECK(udev_list_entry_get_by_name(i,raw)==i);}
  else for(const unsigned char *b=(const unsigned char *)name;*b;b++){hash^=*b;hash*=1099511628211ULL;}
 }
 if(sub && !strcmp(sub,"input"))printf("INPUT_REAL count=%u hash=%llu\n",count,(unsigned long long)hash);
 udev_enumerate_unref(e);return found;
}
static void monitor(struct udev *u) {
 struct udev_monitor *m=udev_monitor_new_from_netlink(u,"udev");
 if(!m){printf("BLOCKED real libudev monitor_new errno=%d; Chromium watcher prerequisite not established\n",errno);return;}
 int enable=udev_monitor_enable_receiving(m), saved=errno, fd=udev_monitor_get_fd(m);
 if(enable==0 && fd>=0)puts("PASS exact Chromium prerequisite: real udev monitor create/enable/get_fd");
 else printf("BLOCKED real libudev monitor enable=%d fd=%d errno=%d; Chromium watcher prerequisite not established\n",enable,fd,saved);
 udev_monitor_unref(m);
}
static void descriptors(struct udev *u) {
 struct udev_device *d=udev_device_new_from_syspath(u,raw);CHECK(d);
 CHECK(!strcmp(udev_device_get_subsystem(d),"hidraw"));CHECK(!strcmp(udev_device_get_devnode(d),node));CHECK(udev_device_get_udev(d)==u);
 struct udev_device *hid=udev_device_get_parent(d);CHECK(hid);CHECK(!strcmp(udev_device_get_subsystem(hid),"hid"));
 CHECK(!strcmp(udev_device_get_property_value(hid,"HID_ID"),"0003:00001209:0000F1D0"));
 struct udev_device *usb=udev_device_get_parent_with_subsystem_devtype(hid,"usb","usb_device");CHECK(usb);CHECK(!strcmp(udev_device_get_devtype(usb),"usb_device"));CHECK(udev_device_get_sysattr_value(usb,"product"));
 CHECK(udev_device_ref(hid)==hid);udev_device_unref(d);CHECK(!strcmp(udev_device_get_subsystem(hid),"hid"));udev_device_unref(hid);
 for(int i=0;i<512;i++){d=udev_device_new_from_syspath(u,raw);CHECK(d);udev_device_unref(d);}
 // An independent real object exercises foreign-pointer delegation.
 CHECK(setenv("DEVPATH","/devices/virtual/mem/null",1)==0);CHECK(setenv("SUBSYSTEM","mem",1)==0);CHECK(setenv("ACTION","change",1)==0);CHECK(setenv("SEQNUM","1",1)==0);CHECK(setenv("MAJOR","1",1)==0);CHECK(setenv("MINOR","3",1)==0);
 d=udev_device_new_from_environment(u);CHECK(d);CHECK(!strcmp(udev_device_get_subsystem(d),"mem"));udev_device_unref(d);
 puts("PASS foreign libudev object from environment fixture; actual sysfs devices unavailable in this container");
 int fd=open64(desc,O_RDONLY|O_CLOEXEC);CHECK(fd>=0);unsigned char b[4096]={0};CHECK(read(fd,b,sizeof b)==sizeof expected);CHECK(!memcmp(b,expected,sizeof expected));CHECK(read(fd,b,sizeof b)==0);
 CHECK(fcntl(fd,F_GET_SEALS)==(F_SEAL_SEAL|F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW));ERR(write(fd,"x",1),EBADF);
 struct stat st;CHECK(fstat(fd,&st)==0 && st.st_size==(off_t)sizeof expected);CHECK(lseek(fd,0,SEEK_SET)==0);CHECK(read(fd,b,sizeof expected)==sizeof expected);CHECK(close(fd)==0);
 fd=openat64(AT_FDCWD,desc,O_RDONLY);CHECK(fd>=0);CHECK(close(fd)==0);
 typedef int (*open2_t)(const char *,int);open2_t o2=(open2_t)dlsym(RTLD_DEFAULT,"__open64_2");CHECK(o2);fd=o2(desc,O_RDONLY);CHECK(fd>=0);CHECK(close(fd)==0);
 typedef int (*openat2_t)(int,const char *,int);openat2_t oa2=(openat2_t)dlsym(RTLD_DEFAULT,"__openat64_2");CHECK(oa2);fd=oa2(AT_FDCWD,desc,O_RDONLY);CHECK(fd>=0);CHECK(close(fd)==0);
 FILE *f=fopen64(desc,"re");CHECK(f);CHECK(fread(b,1,sizeof b,f)==sizeof expected && !memcmp(b,expected,sizeof expected));CHECK(fclose(f)==0);
 ERR(open(desc,O_WRONLY),EACCES);ERR(open(desc,O_RDONLY|O_CREAT,0600),EACCES);
 puts("PASS virtual udev graph/ref lifetimes, foreign libudev object, sealed FIDO-only descriptor, open64/openat64/fortified/fopen64 ABI");
}
static void report(int fd,unsigned char marker) {
 unsigned char out[65]={0},in[64]={0};for(int i=1;i<65;i++)out[i]=(unsigned char)(i+marker);out[1]=marker;
 CHECK(write(fd,out,sizeof out)==sizeof out);
 struct pollfd p={.fd=fd,.events=POLLIN};CHECK(poll(&p,1,2000)==1 && (p.revents&POLLIN));
 CHECK(read(fd,in,sizeof in)==sizeof in);CHECK(!memcmp(out+1,in,64));
}
static void *duplicate_worker(void *arg) {
 int fd=*(int *)arg;
 for(int i=0;i<500;i++){int copy=dup(fd);CHECK(copy>=0);CHECK(fcntl(copy,F_GETFL)>=0);CHECK(close(copy)==0);}
 return NULL;
}
struct fork_activity { int fd; atomic_int stop; atomic_ulong operations; };
static void *fork_worker(void *arg) {
 struct fork_activity *activity=arg;
 while(!atomic_load(&activity->stop)) {int copy=dup(activity->fd);CHECK(copy>=0);CHECK(close(copy)==0);atomic_fetch_add(&activity->operations,1);}
 return NULL;
}
static void await_activity(struct fork_activity *activity,unsigned long before) {
 for(int i=0;i<2000;i++){if(atomic_load(&activity->operations)>before)return;usleep(1000);}
 CHECK(0 && "fork stress worker stopped making progress");
}
static void fork_checks(int fd) {
 int inherited=inherited_relay;CHECK(inherited>=3);int ordinary_pipe[2];CHECK(pipe(ordinary_pipe)==0);
 int ordinary_socket[2];CHECK(socketpair(AF_UNIX,SOCK_SEQPACKET,0,ordinary_socket)==0);
 CHECK(fcntl(inherited,F_GETFD)&FD_CLOEXEC);
 struct fork_activity activity={.fd=fd};atomic_init(&activity.stop,0);atomic_init(&activity.operations,0);
 pthread_t threads[2];for(int i=0;i<2;i++)CHECK(pthread_create(&threads[i],NULL,fork_worker,&activity)==0);
 for(int i=0;i<30;i++) {
  unsigned long before=atomic_load(&activity.operations);await_activity(&activity,before);
  pid_t pid=fork();CHECK(pid>=0);
  if(pid==0){errno=0;if(close(-1)!=-1||errno!=EBADF)_exit(41);char report[65]={0};errno=0;if(syscall(SYS_write,fd,report,sizeof report)!=-1||errno!=EBADF)_exit(42);if(write(ordinary_pipe[1],"p",1)!=1)_exit(43);errno=0;if(syscall(SYS_fcntl,inherited,F_GETFD)!=-1||errno!=EBADF)_exit(44);errno=0;if(syscall(SYS_read,inherited,report,64)!=-1||errno!=EBADF)_exit(45);if(write(ordinary_socket[0],"s",1)!=1)_exit(46);_exit(0);}
  int status=0,finished=0;
  for(int wait=0;wait<2000;wait++){pid_t result=waitpid(pid,&status,WNOHANG);CHECK(result>=0);if(result==pid){finished=1;break;}usleep(1000);}
  if(!finished){kill(pid,SIGKILL);waitpid(pid,&status,0);}
  CHECK(finished && WIFEXITED(status) && WEXITSTATUS(status)==0);
  char byte=0;CHECK(read(ordinary_pipe[0],&byte,1)==1 && byte=='p');
  CHECK(read(ordinary_socket[1],&byte,1)==1 && byte=='s');
  before=atomic_load(&activity.operations);await_activity(&activity,before);
 }
 atomic_store(&activity.stop,1);for(int i=0;i<2;i++)CHECK(pthread_join(threads[i],NULL)==0);
 CHECK(close(ordinary_pipe[0])==0);CHECK(close(ordinary_pipe[1])==0);
 CHECK(close(ordinary_socket[0])==0);CHECK(close(ordinary_socket[1])==0);
 puts("PASS ordinary inherited pipe and unrelated socket pass through in fork child; original relay and virtual aliases are physically closed");
 printf("PASS 30 libc-fork children with activity verified before/after each fork (%lu extra dup/close operations); raw child HID I/O fails EBADF\n",atomic_load(&activity.operations));
}
static void transport(void) {
 int fd=open64(node,O_RDWR|O_CLOEXEC|O_NONBLOCK);CHECK(fd>=0);CHECK(fcntl(fd,F_GETFL)&O_NONBLOCK);
 ERR(open(node,O_RDWR),EBUSY);ERR(open(node,O_RDWR|O_CREAT,0600),EINVAL);
 unsigned char out[66]={0},in[128]={0};ERR(read(fd,in,64),EAGAIN);ERR(write(fd,out,64),EMSGSIZE);ERR(write(fd,out,66),EMSGSIZE);out[0]=1;ERR(write(fd,out,65),EINVAL);out[0]=0;ERR(read(fd,in,63),EMSGSIZE);
 int n=0;CHECK(ioctl(fd,HIDIOCGRDESCSIZE,&n)==0 && n==(int)sizeof expected);
 unsigned char unaligned[8]={0};CHECK(ioctl(fd,HIDIOCGRDESCSIZE,unaligned+1)==0);int unaligned_size=0;memcpy(&unaligned_size,unaligned+1,4);CHECK(unaligned_size==(int)sizeof expected);
 ERR(ioctl(fd,HIDIOCGRDESCSIZE,(void *)(uintptr_t)1),EFAULT);
 struct hidraw_report_descriptor r={.size=4096};CHECK(ioctl(fd,HIDIOCGRDESC,&r)==0 && !memcmp(r.value,expected,sizeof expected));r.size=4097;ERR(ioctl(fd,HIDIOCGRDESC,&r),EINVAL);
 struct hidraw_devinfo info;CHECK(ioctl(fd,HIDIOCGRAWINFO,&info)==0 && info.bustype==3 && info.vendor==0x1209 && (uint16_t)info.product==0xf1d0);
 ERR(ioctl(fd,HIDIOCGFEATURE(65),out),ENOTTY);ERR(ioctl(fd,FIONREAD,&n),ENOTTY);
 struct iovec v={.iov_base=out,.iov_len=65};ERR(writev(fd,&v,1),EOPNOTSUPP);
 fork_checks(fd);
 report(fd,0x20);
 int ep=epoll_create1(EPOLL_CLOEXEC);CHECK(ep>=0);struct epoll_event ev={.events=EPOLLIN,.data.fd=fd};CHECK(epoll_ctl(ep,EPOLL_CTL_ADD,fd,&ev)==0);CHECK(write(fd,out,65)==65);CHECK(epoll_wait(ep,&ev,1,2000)==1);CHECK(read(fd,in,64)==64);CHECK(close(ep)==0);
 // Invalid incoming packet sizes are rejected and consumed, never truncated into reports.
 for(int marker=0xe1;marker<=0xe2;marker++){out[1]=(unsigned char)marker;CHECK(write(fd,out,65)==65);struct pollfd p={.fd=fd,.events=POLLIN};CHECK(poll(&p,1,2000)==1);ERR(read(fd,in,64),EPROTO);ERR(read(fd,in,64),EAGAIN);}
 report(fd,0x21);
 int a=dup(fd);CHECK(a>=0);int b=fcntl64(fd,F_DUPFD_CLOEXEC,3);CHECK(b>=0);CHECK(fcntl(b,F_GETFD)&FD_CLOEXEC);
 ERR(dup2(-1,fd),EBADF);report(fd,0x22);
 CHECK(close(fd)==0);ERR(open(node,O_RDWR),EBUSY);report(a,0x23);
 CHECK(dup2(a,b)==b);report(b,0x24);
 int c=open("/dev/null",O_RDWR);CHECK(c>=0);CHECK(dup3(a,c,O_CLOEXEC)==c);report(c,0x25);
 pthread_t threads[4];for(int i=0;i<4;i++)CHECK(pthread_create(&threads[i],NULL,duplicate_worker,&a)==0);for(int i=0;i<4;i++)CHECK(pthread_join(threads[i],NULL)==0);
 int aliases[253];for(int i=0;i<253;i++){aliases[i]=dup(a);CHECK(aliases[i]>=0);} // a,b,c + 253 = 256
 ERR(dup(a),EMFILE);CHECK(dup2(a,b)==b);CHECK(dup3(a,c,O_CLOEXEC)==c);ERR(dup3(a,a,0),EINVAL);ERR(fcntl(a,F_DUPFD,-1),EINVAL);
 for(int i=0;i<253;i++)CHECK(close(aliases[i])==0);
 CHECK(close(a)==0);CHECK(close(b)==0);CHECK(close(c)==0);
 // Raw close bypasses the interposer. Reuse must be detected before applying bounds.
 for(int i=0;i<100;i++) {
  fd=open(node,O_RDWR|O_NONBLOCK);CHECK(fd>=0);CHECK(syscall(SYS_close,fd)==0);
  int nullfd=open("/dev/null",O_RDWR);CHECK(nullfd>=0);
  if(nullfd!=fd){CHECK(syscall(SYS_dup2,nullfd,fd)==fd);CHECK(close(nullfd)==0);}
  CHECK(write(fd,"x",1)==1);CHECK(read(fd,in,1)==0);CHECK(close(fd)==0);
 }
 fd=open(node,O_RDONLY|O_NONBLOCK);CHECK(fd>=0);ERR(write(fd,out,65),EBADF);CHECK(close(fd)==0);
 fd=open(node,O_RDWR|O_NONBLOCK);CHECK(fd>=0);report(fd,0x26);
 int nullfd=open("/dev/null",O_RDWR);CHECK(nullfd>=0);CHECK(dup2(nullfd,fd)==fd);CHECK(write(fd,"x",1)==1);CHECK(close(nullfd)==0);CHECK(close(fd)==0);
 fd=open(node,O_RDWR|O_NONBLOCK);CHECK(fd>=0);out[1]=0xe3;CHECK(write(fd,out,65)==65);struct pollfd p={.fd=fd,.events=POLLIN};CHECK(poll(&p,1,2000)==1);ERR(read(fd,in,64),ENODEV);ERR(write(fd,out,65),EPIPE);CHECK(close(fd)==0);
 puts("PASS real packet I/O, poll/epoll, 65->64 output/64-byte input, bounded errors, malformed input, disconnect, no SIGPIPE");
 puts("PASS one-session EBUSY, dup/dup2/dup3/fcntl64 aliases, 2000 threaded dup/close operations, 100 direct-SYS_close/reuse cycles");
}
int main(int argc,char **argv) {
 setvbuf(stdout,NULL,_IONBF,0);
 int active=argc>1&&!strcmp(argv[1],"active");
 if(active){CHECK(argc>2);inherited_relay=atoi(argv[2]);CHECK(inherited_relay>=3);}
 typedef int (*unchecked_open_t)(const char *,int);unchecked_open_t unchecked_open=(unchecked_open_t)dlsym(RTLD_DEFAULT,"open");CHECK(unchecked_open);ERR(unchecked_open((const char *)(uintptr_t)1,O_RDONLY),EFAULT);
 pass_through();struct udev *u=udev_new();CHECK(u);monitor(u);
 CHECK(enumerate(u,NULL,0,0)==active);CHECK(enumerate(u,"hidraw",0,0)==active);
 CHECK(enumerate(u,"input",0,0)==0);CHECK(enumerate(u,NULL,1,0)==0);CHECK(enumerate(u,NULL,0,1)==0);
 if(active){descriptors(u);transport();}else{ERR(open(node,O_RDWR),ENOENT);ERR(open(desc,O_RDONLY),ENOENT);puts("PASS opt-out / invalid relay: no synthetic entry, device, or descriptor");}
 udev_unref(u);puts("PASS native ABI harness completed; this is not a browser or WebAuthn test");return 0;
}
