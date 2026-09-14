#![cfg(target_os = "linux")]

use crate::pipeline::{is_skill_file, Pipeline};
use libc::{
    fanotify_event_metadata, fanotify_init, fanotify_mark, fanotify_response, FAN_ALLOW,
    FAN_CLASS_CONTENT, FAN_CLOEXEC, FAN_DENY, FAN_MARK_ADD, FAN_OPEN_PERM, O_CLOEXEC, O_RDONLY,
    AT_FDCWD,
};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info, warn};

pub fn run_fanotify_daemon(
    pipeline: Arc<Pipeline>,
    watch_paths: Vec<PathBuf>,
) -> anyhow::Result<()> {
    unsafe {
        let fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, O_RDONLY | O_CLOEXEC);
        if fan_fd < 0 {
            return Err(io::Error::last_os_error().into());
        }

        for path in &watch_paths {
            if !path.exists() {
                std::fs::create_dir_all(path)?;
            }
            let cpath = CString::new(path.to_string_lossy().as_bytes())?;
            let rc = fanotify_mark(
                fan_fd,
                FAN_MARK_ADD,
                FAN_OPEN_PERM as u64,
                AT_FDCWD,
                cpath.as_ptr(),
            );
            if rc < 0 {
                return Err(io::Error::last_os_error().into());
            }
            info!(path = %path.display(), "fanotify mark added");
        }

        info!("phylor fanotify daemon active (requires CAP_SYS_ADMIN)");

        let mut fan_file = File::from_raw_fd(fan_fd);
        let meta_len = mem::size_of::<fanotify_event_metadata>();
        let mut buf = vec![0u8; meta_len * 32];
        let self_pid = std::process::id() as u32;

        loop {
            let n = fan_file.read(&mut buf)?;
            if n == 0 {
                continue;
            }

            let mut offset = 0usize;
            while offset + meta_len <= n {
                let meta = &*(buf.as_ptr().add(offset) as *const fanotify_event_metadata);
                let event_len = meta.event_len as usize;
                if event_len == 0 {
                    break;
                }

                if (meta.mask & FAN_OPEN_PERM as u64) != 0 {
                    handle_open_perm(&mut fan_file, meta, &pipeline, self_pid);
                }

                offset += event_len;
            }
        }
    }
}

unsafe fn handle_open_perm(
    fan_file: &mut File,
    meta: &fanotify_event_metadata,
    pipeline: &Pipeline,
    self_pid: u32,
) {
    // Avoid self-deadlock when Phylor quarantines / writes honeypots.
    if meta.pid as u32 == self_pid {
        let _ = reply(fan_file, meta.fd, true);
        libc::close(meta.fd);
        return;
    }

    let path = resolve_path(meta.fd);
    if let Some(ref p) = path {
        if !is_skill_file(p) {
            let _ = reply(fan_file, meta.fd, true);
            libc::close(meta.fd);
            return;
        }
    }

    let content = match read_from_fd(meta.fd) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to read fanotify fd; denying");
            let _ = reply(fan_file, meta.fd, false);
            libc::close(meta.fd);
            return;
        }
    };

    // Fast path only: never call the LLM while the opener is blocked in the kernel.
    let result = match pipeline.scan_text_fast(&content) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "fast scan failed; denying");
            let _ = reply(fan_file, meta.fd, false);
            libc::close(meta.fd);
            return;
        }
    };

    let allow = !result.is_block();
    if let Err(e) = reply(fan_file, meta.fd, allow) {
        error!(error = %e, "failed to write fanotify response");
    }
    libc::close(meta.fd);

    // Honeypot is installed after DENY. The blocked open never sees this inode;
    // the IDE's subsequent open (after mtime bump) loads the honeypot.
    if !allow {
        if let Some(ref p) = path {
            if let Err(e) = pipeline.enforce_block(p, &result) {
                warn!(path = %p.display(), error = %e, "post-deny honeypot failed");
            }
        }
    }
}

fn reply(fan_file: &mut File, fd: RawFd, allow: bool) -> io::Result<()> {
    let response = fanotify_response {
        fd,
        response: if allow { FAN_ALLOW } else { FAN_DENY },
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            &response as *const _ as *const u8,
            mem::size_of::<fanotify_response>(),
        )
    };
    fan_file.write_all(bytes)
}

fn read_from_fd(fd: RawFd) -> io::Result<String> {
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut content = String::new();
    let result = file.read_to_string(&mut content);
    let _ = file.into_raw_fd();
    result.map(|_| content)
}

fn resolve_path(fd: RawFd) -> Option<PathBuf> {
    let link = format!("/proc/self/fd/{fd}");
    std::fs::read_link(Path::new(&link)).ok()
}
