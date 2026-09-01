//! Filesystem primitives used before persistence operations report success.

use std::fs;
#[cfg(any(unix, test))]
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// Create a directory tree and persist every newly created directory entry.
pub(crate) fn create_dir_all(path: &Path) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut candidate = Some(path);
    while let Some(current) = candidate {
        if current.exists() {
            break;
        }
        missing.push(current.to_owned());
        candidate = current.parent();
    }

    fs::create_dir_all(path)?;
    for created in missing.iter().rev() {
        sync_parent_directory(created)?;
    }
    Ok(())
}

/// Persist the directory entry for a newly created file.
pub(crate) fn sync_parent_directory(path: &Path) -> io::Result<()> {
    path.parent().map_or(Ok(()), sync_directory)
}

/// Replace or move a file and persist the source and destination directories.
pub(crate) fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    let source_parent = source.parent().map(PathBuf::from);
    let destination_parent = destination.parent().map(PathBuf::from);

    replace_file_inner(source, destination)?;

    if let Some(parent) = destination_parent.as_deref() {
        sync_directory(parent)?;
    }
    if source_parent != destination_parent {
        if let Some(parent) = source_parent.as_deref() {
            sync_directory(parent)?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn replace_file_inner(source: &Path, destination: &Path) -> io::Result<()> {
    if destination.exists() {
        fs::remove_file(destination)?;
    }
    fs::rename(source, destination)
}

#[cfg(not(windows))]
fn replace_file_inner(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

// Rust's standard library cannot portably open and flush a directory handle on
// Windows. File contents are still flushed before promotion, and the rename is
// completed before success; Unix additionally receives the required parent
// directory fsync that makes the directory entry power-loss durable.
#[cfg(not(unix))]
fn sync_directory(path: &Path) -> io::Result<()> {
    if fs::metadata(path)?.is_dir() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "durable entry parent is not a directory",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::tempdir;

    #[test]
    fn created_directories_and_promoted_files_can_be_synchronized() {
        let root = tempdir().unwrap();
        let nested = root.path().join("state").join("representation");
        create_dir_all(&nested).unwrap();

        let temporary = nested.join("slot.tmp");
        let durable = nested.join("slot.json");
        let mut file = File::create(&temporary).unwrap();
        file.write_all(b"durable state\n").unwrap();
        file.sync_all().unwrap();
        sync_parent_directory(&temporary).unwrap();
        replace_file(&temporary, &durable).unwrap();

        assert!(!temporary.exists());
        assert_eq!(fs::read(durable).unwrap(), b"durable state\n");
    }
}
