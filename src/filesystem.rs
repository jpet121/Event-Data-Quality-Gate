use crate::contract::Code;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File},
    io::{self, Read, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
};

fn c_path(path: &[u8], error: Code) -> Result<CString, Code> {
    CString::new(path).map_err(|_| error)
}

fn open(dir: RawFd, path: &Path, flags: i32, mode: u32) -> Result<File, Code> {
    let path = c_path(path.as_os_str().as_bytes(), Code::PathRejected)?;
    // Reject symlinks in every component, including Linux magic links.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (flags | libc::O_CLOEXEC) as u64;
    how.mode = mode.into();
    how.resolve = libc::RESOLVE_NO_SYMLINKS;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir,
            path.as_ptr(),
            &how,
            size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return Err(map_error(io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

fn map_error(err: io::Error) -> Code {
    match err.raw_os_error() {
        Some(libc::ELOOP | libc::EXDEV | libc::ENOTDIR | libc::ENOSYS) => Code::PathRejected,
        _ => Code::IoFailure,
    }
}

fn local(file: &File) -> Result<(), Code> {
    let mut info = MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(file.as_raw_fd(), info.as_mut_ptr()) } < 0 {
        return Err(Code::IoFailure);
    }
    match unsafe { info.assume_init() }.f_type {
        libc::EXT4_SUPER_MAGIC
        | libc::XFS_SUPER_MAGIC
        | libc::BTRFS_SUPER_MAGIC
        | libc::TMPFS_MAGIC => Ok(()),
        _ => Err(Code::PathRejected),
    }
}

pub(crate) struct Directory(File);

/// Prevent in-place writes to a staged inode while its publication is decided.
pub(crate) struct PublicationLease(File);

impl PublicationLease {
    pub(crate) fn acquire(file: File) -> Result<Self, Code> {
        let fd = file.as_raw_fd();
        if unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_RDLCK) } < 0 {
            return Err(match io::Error::last_os_error().raw_os_error() {
                Some(libc::EAGAIN) => Code::ArtifactInvalid,
                _ => Code::IoFailure,
            });
        }
        Ok(Self(file))
    }

    pub(crate) fn version(&self) -> Result<FileVersion, Code> {
        file_version(&self.0)
    }

    pub(crate) fn check(&self) -> Result<(), Code> {
        let current = self.0.metadata().map_err(|_| Code::IoFailure)?.mode();
        if current & 0o222 != 0 {
            return Err(Code::ArtifactInvalid);
        }
        match unsafe { libc::fcntl(self.0.as_raw_fd(), libc::F_GETLEASE) } {
            libc::F_RDLCK => Ok(()),
            libc::F_UNLCK => Err(Code::ArtifactInvalid),
            _ => Err(Code::IoFailure),
        }
    }

    pub(crate) fn watch(&self, watch: &PublicationWatch) -> Result<(), Code> {
        watch.watch_file(&self.0)
    }
}

/// Make a write conflict an operational decision, never a fatal signal.
pub(crate) struct IgnoreLeaseNotifications(libc::sigaction);

impl IgnoreLeaseNotifications {
    pub(crate) fn install() -> Result<Self, Code> {
        let mut previous = MaybeUninit::uninit();
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = libc::SIG_IGN;
        // The zeroed Linux sigset_t is the empty mask.
        if unsafe { libc::sigaction(libc::SIGIO, &action, previous.as_mut_ptr()) } != 0 {
            return Err(Code::IoFailure);
        }
        Ok(Self(unsafe { previous.assume_init() }))
    }
}

impl Drop for IgnoreLeaseNotifications {
    fn drop(&mut self) {
        unsafe { libc::sigaction(libc::SIGIO, &self.0, std::ptr::null_mut()) };
    }
}

/// The kernel checks the caller's physical UID/GID on files. Map only the
/// existing identity in a child user namespace; the supervisor gets no
/// capabilities in the host namespace or over other users' entries.
pub(crate) struct PublisherAuthority;

pub(crate) fn isolate_publisher() -> Result<PublisherAuthority, Code> {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        return Err(Code::IoFailure);
    }
    fs::write("/proc/self/setgroups", "deny").map_err(|_| Code::IoFailure)?;
    fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n")).map_err(|_| Code::IoFailure)?;
    fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n")).map_err(|_| Code::IoFailure)?;
    set_rename_capability(true)?;
    Ok(PublisherAuthority)
}

impl Drop for PublisherAuthority {
    fn drop(&mut self) {
        let _ = set_rename_capability(false);
    }
}

fn set_rename_capability(enable: bool) -> Result<(), Code> {
    // linux/capability.h, _LINUX_CAPABILITY_VERSION_3 and CAP_DAC_OVERRIDE.
    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    struct Capabilities {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let override_bit = if enable { 1 << 1 } else { 0 };
    let capabilities = [
        Capabilities {
            effective: override_bit,
            permitted: override_bit,
            inheritable: 0,
        },
        Capabilities {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    if unsafe { libc::syscall(libc::SYS_capset, &header, capabilities.as_ptr()) } != 0 {
        return Err(Code::IoFailure);
    }
    Ok(())
}

/// A process without the publisher's scoped capability cannot change this
/// entry by ordinary writes. Keep the original access mode for caller cleanup.
pub(crate) struct WriteFence<'a> {
    file: &'a File,
    original: libc::mode_t,
    restricted: libc::mode_t,
    restore: bool,
}

impl<'a> WriteFence<'a> {
    fn new(file: &'a File, restricted: libc::mode_t) -> Result<Self, Code> {
        let original = file.metadata().map_err(|_| Code::IoFailure)?.mode() & 0o7777;
        if unsafe { libc::fchmod(file.as_raw_fd(), restricted) } != 0 {
            return Err(Code::IoFailure);
        }
        Ok(Self {
            file,
            original,
            restricted,
            restore: true,
        })
    }

    pub(crate) fn check(&self) -> Result<(), Code> {
        let current = self.file.metadata().map_err(|_| Code::IoFailure)?.mode() & 0o7777;
        if current != self.restricted {
            return Err(Code::ArtifactInvalid);
        }
        Ok(())
    }

    pub(crate) fn leave_restricted(mut self) {
        self.restore = false;
    }
}

impl Drop for WriteFence<'_> {
    fn drop(&mut self) {
        // Metadata restoration does not determine the result of a commit.
        if self.restore {
            unsafe { libc::fchmod(self.file.as_raw_fd(), self.original) };
        }
    }
}

impl Directory {
    pub(crate) fn create_run(&self, name: &str) -> Result<Self, Code> {
        let dir = self.create_dir(name)?;
        let fd = dir.0.as_raw_fd();
        let meta = dir.0.metadata().map_err(|_| Code::IoFailure)?;
        let gid = unsafe { libc::getegid() };
        // An SGID output parent can hand the new directory a different group.
        // The publisher maps only its own group; normalize the new run, never
        // its parent. This also prevents inheritance by the staged files.
        if meta.gid() != gid && unsafe { libc::fchown(fd, libc::uid_t::MAX, gid) } != 0 {
            return Err(Code::IoFailure);
        }
        let access = meta.mode() & 0o7777 & !libc::S_ISGID;
        if meta.mode() & libc::S_ISGID != 0 && unsafe { libc::fchmod(fd, access) } != 0 {
            return Err(Code::IoFailure);
        }
        Ok(dir)
    }

    pub(crate) fn restrict(&self) -> Result<WriteFence<'_>, Code> {
        WriteFence::new(&self.0, 0o500)
    }

    pub(crate) fn version(&self) -> Result<FileVersion, Code> {
        file_version(&self.0)
    }

    pub(crate) fn open(path: &Path) -> Result<Self, Code> {
        let dir = open(libc::AT_FDCWD, path, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        local(&dir)?;
        Ok(Self(dir))
    }

    pub(crate) fn parent(path: &str) -> Result<(Self, String), Code> {
        let path = Path::new(path);
        let parent = path.parent().ok_or(Code::PathRejected)?;
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(Code::PathRejected)?;
        Ok((Self::open(parent)?, name.into()))
    }

    pub(crate) fn create_dir(&self, name: &str) -> Result<Self, Code> {
        let entry = basename(name)?;
        let uid = unsafe { libc::geteuid() };
        let parent = self.0.metadata().map_err(|_| Code::IoFailure)?;
        if !matches!(parent.uid(), 0) && parent.uid() != uid
            || parent.mode() & 0o022 != 0 && parent.mode() & 0o1000 == 0
        {
            return Err(Code::PathRejected);
        }
        if unsafe { libc::mkdirat(self.0.as_raw_fd(), entry.as_ptr(), 0o700) } < 0 {
            let error = io::Error::last_os_error();
            return Err(if error.kind() == io::ErrorKind::AlreadyExists {
                Code::OutputCollision
            } else {
                map_error(error)
            });
        }
        let file = open(
            self.0.as_raw_fd(),
            Path::new(name),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        local(&file)?;
        let created = file.metadata().map_err(|_| Code::IoFailure)?;
        if created.uid() != uid || created.mode() & 0o077 != 0 {
            return Err(Code::PathRejected);
        }
        Ok(Self(file))
    }

    pub(crate) fn file(&self, name: &str) -> Result<File, Code> {
        basename(name)?;
        let file = open(
            self.0.as_raw_fd(),
            Path::new(name),
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        )?;
        if !file.metadata().map_err(|_| Code::IoFailure)?.is_file() {
            return Err(Code::PathRejected);
        }
        local(&file)?;
        Ok(file)
    }

    pub(crate) fn new_file(&self, name: &str) -> Result<File, Code> {
        self.create_file(name, 0o600)
    }

    // Write through the creating descriptor. Later ordinary write-opens
    // cannot pass the permission check even before the lease is acquired.
    pub(crate) fn new_artifact(&self, name: &str) -> Result<File, Code> {
        self.create_file(name, 0o400)
    }

    fn create_file(&self, name: &str, mode: libc::mode_t) -> Result<File, Code> {
        basename(name)?;
        open(
            self.0.as_raw_fd(),
            Path::new(name),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NONBLOCK,
            mode,
        )
    }

    pub(crate) fn entries(&self, limit: usize) -> Result<Vec<std::ffi::OsString>, Code> {
        let path = PathBuf::from(format!("/proc/self/fd/{}", self.0.as_raw_fd()));
        fs::read_dir(path)
            .map_err(|_| Code::IoFailure)?
            .take(limit)
            .map(|entry| entry.map(|e| e.file_name()).map_err(|_| Code::IoFailure))
            .collect()
    }

    pub(crate) fn publish(&self, temporary: &str, final_name: &str) -> Result<(), Code> {
        let from = basename(temporary)?;
        let to = basename(final_name)?;
        let fd = self.0.as_raw_fd();
        if unsafe { libc::renameat2(fd, from.as_ptr(), fd, to.as_ptr(), libc::RENAME_NOREPLACE) }
            < 0
        {
            return Err(Code::IoFailure);
        }
        Ok(())
    }

    pub(crate) fn unlink(&self, name: &str) {
        if let Ok(entry) = basename(name) {
            unsafe { libc::unlinkat(self.0.as_raw_fd(), entry.as_ptr(), 0) };
        }
    }
}

/// Track writes and directory mutations after the worker finishes staging.
pub(crate) struct PublicationWatch(File);

impl PublicationWatch {
    pub(crate) fn new() -> Result<Self, Code> {
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if fd < 0 {
            return Err(Code::IoFailure);
        }
        Ok(Self(unsafe { File::from_raw_fd(fd) }))
    }

    pub(crate) fn arm(&self, dir: &Directory) -> Result<(), Code> {
        self.watch_entries(dir, libc::IN_ATTRIB)
    }

    pub(crate) fn watch_entries(&self, dir: &Directory, extra: u32) -> Result<(), Code> {
        let mask = libc::IN_MODIFY
            | extra
            | libc::IN_CLOSE_WRITE
            | libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_DELETE_SELF
            | libc::IN_MOVE_SELF
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO
            | libc::IN_ONLYDIR;
        self.add(&dir.0, mask)
    }

    pub(crate) fn watch_file(&self, file: &File) -> Result<(), Code> {
        // A directory watch alone cannot see a write through a hard link
        // in a different directory.
        self.add(
            file,
            libc::IN_MODIFY | libc::IN_ATTRIB | libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF,
        )
    }

    fn add(&self, file: &File, mask: u32) -> Result<(), Code> {
        // The fixed prefix and decimal descriptor cannot contain a NUL.
        let path = format!("/proc/self/fd/{}\0", file.as_raw_fd());
        if unsafe { libc::inotify_add_watch(self.0.as_raw_fd(), path.as_ptr().cast(), mask) } < 0 {
            return Err(Code::IoFailure);
        }
        Ok(())
    }

    pub(crate) fn check_clean(&self) -> Result<(), Code> {
        // No mutations are expected up to the commit. One event is enough
        // to refuse publication, including an inotify queue overflow event.
        match (&self.0).read(&mut [0; 4096]) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Ok(n) if n > 0 => Err(Code::ArtifactInvalid),
            _ => Err(Code::IoFailure),
        }
    }
}

fn basename(name: &str) -> Result<CString, Code> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(Code::PathRejected);
    }
    c_path(name.as_bytes(), Code::PathRejected)
}

pub(crate) fn read_path(path: &str, limit: usize, code: Code) -> Result<Vec<u8>, Code> {
    let (dir, name) = Directory::parent(path)?;
    stable_read(dir.file(&name)?, limit, code)
}

pub(crate) fn stable_read(mut file: File, limit: usize, exceeded: Code) -> Result<Vec<u8>, Code> {
    let mut bytes = Vec::new();
    copy_checked(
        &mut file,
        &mut bytes,
        limit as u64,
        exceeded,
        Code::InputChanged,
    )?;
    Ok(bytes)
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct FileVersion {
    #[serde(deserialize_with = "crate::contract::required_field")]
    device: u64,
    #[serde(deserialize_with = "crate::contract::required_field")]
    inode: u64,
    #[serde(deserialize_with = "crate::contract::required_field")]
    length: u64,
    #[serde(deserialize_with = "crate::contract::required_field")]
    modified: (i64, i64),
    #[serde(deserialize_with = "crate::contract::required_field")]
    changed: (i64, i64),
}

impl FileVersion {
    pub(crate) fn length(&self) -> u64 {
        self.length
    }
}

pub(crate) fn file_version(file: &File) -> Result<FileVersion, Code> {
    let metadata = file.metadata().map_err(|_| Code::IoFailure)?;
    Ok(signature(&metadata))
}

fn signature(meta: &fs::Metadata) -> FileVersion {
    FileVersion {
        device: meta.dev(),
        inode: meta.ino(),
        length: meta.size(),
        modified: (meta.mtime(), meta.mtime_nsec()),
        changed: (meta.ctime(), meta.ctime_nsec()),
    }
}

pub(crate) fn copy_checked(
    source: &mut File,
    out: &mut impl Write,
    limit: u64,
    exceeded: Code,
    changed: Code,
) -> Result<Fingerprint, Code> {
    let start = source.metadata().map_err(|_| Code::IoFailure)?;
    if start.len() > limit {
        return Err(exceeded);
    }
    let fingerprint = transfer(source, out, limit, exceeded)?;
    let end = source.metadata().map_err(|_| Code::IoFailure)?;
    if signature(&start) != signature(&end) || start.len() != fingerprint.bytes {
        return Err(changed);
    }
    out.flush().map_err(|_| Code::IoFailure)?;
    Ok(fingerprint)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Fingerprint {
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
}

pub(crate) fn transfer(
    source: &mut impl Read,
    out: &mut impl Write,
    limit: u64,
    exceeded: Code,
) -> Result<Fingerprint, Code> {
    let mut digest = Sha256::new();
    let mut bytes = 0;
    let mut buffer = [0; 64 * 1024];
    loop {
        let available = ((limit - bytes).saturating_add(1)).min(buffer.len() as u64) as usize;
        let size = source
            .read(&mut buffer[..available])
            .map_err(|_| Code::IoFailure)?;
        if size == 0 {
            break;
        }
        if size as u64 > limit - bytes {
            return Err(exceeded);
        }
        digest.update(&buffer[..size]);
        out.write_all(&buffer[..size])
            .map_err(|_| Code::IoFailure)?;
        bytes += size as u64;
    }
    Ok(Fingerprint {
        bytes,
        sha256: format!("{:x}", digest.finalize()),
    })
}

pub(crate) struct Staging {
    root: Directory,
    pub(crate) directory: Directory,
    name: String,
}

impl Staging {
    pub(crate) fn create(id: &str) -> Result<Self, Code> {
        let root = Directory::open(Path::new("/tmp"))?;
        let name = format!("sesv-{id}");
        let directory = root.create_dir(&name)?;
        let staging = Self {
            directory,
            root,
            name,
        };
        let mut marker = staging.directory.new_file("OWNER.json")?;
        serde_json::to_writer(
            &mut marker,
            &serde_json::json!({"application":"sesv","run_id":id}),
        )
        .map_err(|_| Code::IoFailure)?;
        // This is an unbuffered File. Its Write::flush is a no-op on Linux.
        Ok(staging)
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        // Clean the known staging names relative to the original directory handle.
        for n in [
            "OWNER.json",
            "source",
            "valid.ndjson",
            "results.ndjson",
            "manifest.json",
            "COMPLETE.json",
        ] {
            self.directory.unlink(n);
        }
        let same = |other: File| {
            self.directory
                .0
                .metadata()
                .ok()
                .zip(other.metadata().ok())
                .is_some_and(|(a, b)| {
                    a.dev() == b.dev() && a.ino() == b.ino() && a.uid() == b.uid()
                })
        };
        if open(
            self.root.0.as_raw_fd(),
            Path::new(&self.name),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )
        .is_ok_and(same)
            && let Ok(name) = basename(&self.name)
        {
            unsafe { libc::unlinkat(self.root.0.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
        }
    }
}

pub(crate) fn run_id() -> Result<String, Code> {
    let mut bytes = [0; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|_| Code::IoFailure)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let base: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &base[..8],
        &base[8..12],
        &base[12..16],
        &base[16..20],
        &base[20..]
    ))
}

pub(crate) fn timestamp() -> Result<String, Code> {
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    let mut tm = MaybeUninit::<libc::tm>::uninit();
    if unsafe { libc::gmtime_r(&now, tm.as_mut_ptr()) }.is_null() {
        return Err(Code::InternalFailure);
    }
    let tm = unsafe { tm.assume_init() };
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    ))
}
