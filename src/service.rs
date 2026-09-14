use crate::config::Config;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

pub fn install_user_service(kernel: bool) -> anyhow::Result<PathBuf> {
    if kernel {
        anyhow::bail!(
            "--kernel is not implemented for automatic install; \
             on Linux, build with --features fanotify and run: sudo phylor daemon --fanotify"
        );
    }

    let exe = std::env::current_exe()?;
    let home = Config::phylor_home();
    fs::create_dir_all(&home)?;

    #[cfg(target_os = "linux")]
    {
        return install_systemd_user(&exe);
    }

    #[cfg(target_os = "macos")]
    {
        return install_launch_agent(&exe);
    }

    #[cfg(target_os = "windows")]
    {
        return install_windows_task(&exe);
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = exe;
        anyhow::bail!("service install not supported on this OS");
    }
}

#[cfg(target_os = "linux")]
fn install_systemd_user(exe: &std::path::Path) -> anyhow::Result<PathBuf> {
    let dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("systemd")
        .join("user");
    fs::create_dir_all(&dir)?;
    let unit = dir.join("phylor.service");
    let body = format!(
        r#"[Unit]
Description=Phylor AI skill guardrail
After=default.target

[Service]
Type=simple
ExecStart={exe} daemon
Restart=on-failure
RestartSec=3
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
"#,
        exe = exe.display()
    );
    fs::write(&unit, body)?;
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    let _ = Command::new("systemctl")
        .args(["--user", "enable", "--now", "phylor.service"])
        .status();
    Ok(unit)
}

#[cfg(target_os = "macos")]
fn install_launch_agent(exe: &std::path::Path) -> anyhow::Result<PathBuf> {
    let dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Library")
        .join("LaunchAgents");
    fs::create_dir_all(&dir)?;
    let plist = dir.join("com.phylor.daemon.plist");
    let log = Config::phylor_home().join("daemon.log");
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.phylor.daemon</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>daemon</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#,
        exe = exe.display(),
        log = log.display()
    );
    fs::write(&plist, body)?;
    let _ = Command::new("launchctl")
        .args(["unload", &plist.to_string_lossy()])
        .status();
    let status = Command::new("launchctl")
        .args(["load", &plist.to_string_lossy()])
        .status()?;
    if !status.success() {
        anyhow::bail!("launchctl load failed");
    }
    Ok(plist)
}

#[cfg(target_os = "windows")]
fn install_windows_task(exe: &std::path::Path) -> anyhow::Result<PathBuf> {
    let home = Config::phylor_home();
    let marker = home.join("windows-task.txt");
    let exe_str = exe.to_string_lossy().replace('/', "\\");

    // Remove prior task if present, then create a logon-triggered user task.
    let _ = Command::new("schtasks")
        .args(["/Delete", "/TN", "PhylorDaemon", "/F"])
        .status();

    let status = Command::new("schtasks")
        .args([
            "/Create",
            "/TN",
            "PhylorDaemon",
            "/SC",
            "ONLOGON",
            "/RL",
            "LIMITED",
            "/TR",
            &format!("\"{}\" daemon", exe_str),
            "/F",
        ])
        .status()?;

    if !status.success() {
        anyhow::bail!("schtasks create failed");
    }

    fs::write(
        &marker,
        format!("Registered Scheduled Task: PhylorDaemon\nCommand: {exe_str} daemon\n"),
    )?;
    Ok(marker)
}
