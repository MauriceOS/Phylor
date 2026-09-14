#[cfg(target_os = "linux")]
pub mod fanotify;
pub mod notify_watch;

pub use notify_watch::run_notify_daemon;

#[cfg(all(target_os = "linux", feature = "fanotify"))]
pub use fanotify::run_fanotify_daemon;
