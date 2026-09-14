use std::fs;
use std::io;
use std::path::Path;

/// Returns true if `path` is a symbolic link (not followed).
pub fn is_symlink(path: &Path) -> io::Result<bool> {
    Ok(fs::symlink_metadata(path)?.file_type().is_symlink())
}

/// Ensure the path exists, is a regular file, and is not a symlink.
pub fn require_regular_file(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to modify symlink (possible TOCTOU hijack): {}",
                path.display()
            ),
        ));
    }
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a regular file: {}", path.display()),
        ));
    }
    Ok(())
}
