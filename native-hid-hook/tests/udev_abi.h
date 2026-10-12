#ifndef UHF_TEST_UDEV_ABI_H
#define UHF_TEST_UDEV_ABI_H
struct udev; struct udev_monitor; struct udev_enumerate; struct udev_list_entry; struct udev_device;
extern struct udev *udev_new(void);
extern struct udev *udev_unref(struct udev *);
extern struct udev_monitor *udev_monitor_new_from_netlink(struct udev *, const char *);
extern int udev_monitor_enable_receiving(struct udev_monitor *);
extern int udev_monitor_get_fd(struct udev_monitor *);
extern struct udev_monitor *udev_monitor_unref(struct udev_monitor *);
extern struct udev_enumerate *udev_enumerate_new(struct udev *);
extern struct udev_enumerate *udev_enumerate_ref(struct udev_enumerate *);
extern struct udev_enumerate *udev_enumerate_unref(struct udev_enumerate *);
extern int udev_enumerate_scan_devices(struct udev_enumerate *);
extern int udev_enumerate_add_match_subsystem(struct udev_enumerate *, const char *);
extern int udev_enumerate_add_nomatch_subsystem(struct udev_enumerate *, const char *);
extern int udev_enumerate_add_match_property(struct udev_enumerate *, const char *,const char *);
extern struct udev_list_entry *udev_enumerate_get_list_entry(struct udev_enumerate *);
extern struct udev_list_entry *udev_list_entry_get_next(struct udev_list_entry *);
extern struct udev_list_entry *udev_list_entry_get_by_name(struct udev_list_entry *, const char *);
extern const char *udev_list_entry_get_name(struct udev_list_entry *);
extern const char *udev_list_entry_get_value(struct udev_list_entry *);
extern struct udev_device *udev_device_new_from_environment(struct udev *);
extern struct udev_device *udev_device_new_from_syspath(struct udev *, const char *);
extern struct udev_device *udev_device_ref(struct udev_device *);
extern struct udev_device *udev_device_unref(struct udev_device *);
extern const char *udev_device_get_subsystem(struct udev_device *);
extern const char *udev_device_get_syspath(struct udev_device *);
extern const char *udev_device_get_devnode(struct udev_device *);
extern const char *udev_device_get_devtype(struct udev_device *);
extern const char *udev_device_get_property_value(struct udev_device *, const char *);
extern const char *udev_device_get_sysattr_value(struct udev_device *, const char *);
extern struct udev_device *udev_device_get_parent(struct udev_device *);
extern struct udev_device *udev_device_get_parent_with_subsystem_devtype(struct udev_device *, const char *,const char *);
extern struct udev *udev_device_get_udev(struct udev_device *);
#endif
