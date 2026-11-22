//! Best-effort process hardening for frontends.
//!
//! Passwords and derived keys live in process memory while an operation runs.
//! A core dump would write them to disk, where they outlive the process, so the
//! frontends switch dumps off at startup.

/// Stops the OS from writing a core dump if the process crashes.
///
/// Sets the core-file size limit to zero. Failure is ignored: this is a
/// hardening measure, not something an encryption run should depend on.
#[cfg(unix)]
pub fn disable_core_dumps() {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, fully initialised rlimit that outlives the call.
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
}

/// Stops the OS from writing a core dump if the process crashes.
#[cfg(not(unix))]
pub fn disable_core_dumps() {}

/// Marks the process as non-dumpable, which also stops other processes of the
/// same user from attaching to it with a debugger or reading its memory.
///
/// Meant for the command-line tool. Not used by the GUI: sandbox portals
/// identify a Flatpak app through `/proc/<pid>`, which a non-dumpable process
/// makes unreadable.
#[cfg(target_os = "linux")]
pub fn disable_memory_inspection() {
    // SAFETY: PR_SET_DUMPABLE takes a plain integer argument.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// Marks the process as non-dumpable. Only implemented on Linux.
#[cfg(not(target_os = "linux"))]
pub fn disable_memory_inspection() {}
