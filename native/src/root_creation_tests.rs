use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
use std::os::fd::AsRawFd;
use std::os::unix::fs::symlink;
use crate::unix::{mkdir_child_beneath, open_owned_beneath};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fs-safe-root-create-{}-{}", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(path.join("parent")).unwrap();
        fs::create_dir_all(path.join("outside")).unwrap();
        Self(path)
    }
    fn before_final(&self) {
        fs::rename(self.0.join("parent"), self.0.join("held")).unwrap();
        symlink("outside", self.0.join("parent")).unwrap();
    }
}
impl Drop for Fixture { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }

#[test]
fn mkdir_pins_parent_and_reports_only_its_exclusive_creation() {
    let fixture = Fixture::new();
    let parent = fs::File::open(fixture.0.join("parent")).unwrap();
    fixture.before_final();
    assert!(mkdir_child_beneath(parent.as_raw_fd(), "child", 0o700).unwrap());
    assert!(!mkdir_child_beneath(parent.as_raw_fd(), "child", 0o700).unwrap());
    assert!(fixture.0.join("held/child").is_dir());
    assert!(!fixture.0.join("outside/child").exists());
}

#[test]
fn append_creation_pins_parent_and_does_not_follow_a_final_symlink() {
    let fixture = Fixture::new();
    let parent = fs::File::open(fixture.0.join("parent")).unwrap();
    fixture.before_final();
    let flags = libc::O_RDWR | libc::O_APPEND | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW;
    let fd = open_owned_beneath(parent.as_raw_fd(), "created", flags).unwrap();
    use std::io::Write;
    let mut file = fs::File::from(fd);
    file.write_all(b"inside").unwrap();
    assert_eq!(fs::read(fixture.0.join("held/created")).unwrap(), b"inside");
    assert!(!fixture.0.join("outside/created").exists());
    fs::write(fixture.0.join("outside/value"), b"preserve").unwrap();
    symlink("../outside/value", fixture.0.join("held/link")).unwrap();
    assert!(open_owned_beneath(parent.as_raw_fd(), "link", flags).is_err());
    assert_eq!(fs::read(fixture.0.join("outside/value")).unwrap(), b"preserve");
}
