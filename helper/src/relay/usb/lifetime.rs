//! Process-local parent-death protection; never changes host permissions/policy.
#[cfg(windows)]
pub(super) struct Guard(std::os::windows::io::OwnedHandle);
#[cfg(not(windows))]
pub(super) struct Guard;

pub(super) fn prepare(command: &mut tokio::process::Command) -> Result<Guard, ()> {
    #[cfg(target_os = "linux")]
    {
        let parent = unsafe { libc::getpid() };
        // Only async-signal-safe syscalls between fork and exec. Fail closed if
        // the parent changed before the death signal was installed.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
                }
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::System::JobObjects::*;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW; no breakaway flag.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(());
        }
        let job = unsafe { OwnedHandle::from_raw_handle(job) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err(());
        }
        Ok(Guard(job))
    }
    #[cfg(not(windows))]
    {
        let _ = command;
        Ok(Guard)
    }
}
impl Guard {
    pub(super) fn attach(&self, child: &tokio::process::Child) -> Result<(), ()> {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
            let process = child.raw_handle().ok_or(())?;
            if unsafe { AssignProcessToJobObject(self.0.as_raw_handle(), process) } == 0 {
                return Err(());
            }
        }
        let _ = child;
        Ok(())
    }
}
