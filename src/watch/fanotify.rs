#![cfg(target_os = "linux")]

use crate::pipeline::Pipeline;
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
use std::path::Path;
use std::sync::Arc;
use tracing::{error, info, warn};

pub fn run_fanotify_daemon(
    pipeline: Arc<Pipeline>,
    watch_paths: Vec<std::path::PathBuf>,
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
                    let allow = match analyze_fd(meta.fd, &pipeline) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(error = %e, "analysis failed; denying open");
                            false
                        }
                    };

                    let response = fanotify_response {
                        fd: meta.fd,
                        response: if allow { FAN_ALLOW } else { FAN_DENY },
                    };
                    let bytes = std::slice::from_raw_parts(
                        &response as *const _ as *const u8,
                        mem::size_of::<fanotify_response>(),
                    );
                    if let Err(e) = fan_file.write_all(bytes) {
                        error!(error = %e, "failed to write fanotify response");
                    }
                    libc::close(meta.fd);
                }

                offset += event_len;
            }
        }
    }
}

fn analyze_fd(fd: RawFd, pipeline: &Pipeline) -> anyhow::Result<bool> {
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    let _ = file.into_raw_fd();

    let link = format!("/proc/self/fd/{fd}");
    if let Ok(resolved) = std::fs::read_link(Path::new(&link)) {
        if !crate::pipeline::is_skill_file(&resolved) {
            return Ok(true);
        }
    }

    let result = pipeline.scan_text(&content)?;
    if result.is_block() {
        info!(verdict = %result.verdict, reason = %result.reason, "fanotify deny");
        Ok(false)
    } else {
        Ok(true)
    }
}
