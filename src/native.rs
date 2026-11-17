use crate::artifact::{self, Prepared};
use crate::contract::{Code, Format, INPUT_LIMIT, MEMORY_LIMIT, Operation, Outcome, RUN_LIMIT_MS};
use crate::engine::{ALLOWLIST_LIMIT, Policy};
use crate::filesystem::{
    Directory, PublicationWatch, Staging, copy_checked, read_path, run_id, stable_read, timestamp,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const WORKER_OOM_EXIT: i32 = 71;
const REPLY_LIMIT: usize = 4096;
static WORKER_MEMORY_GUARD: AtomicBool = AtomicBool::new(false);
static CANCELED: AtomicBool = AtomicBool::new(false);

#[derive(Deserialize, Serialize)]
enum Reply {
    Prepared(Prepared),
    Failed(Code),
}

/// Run the native validation command in the CLI process.
///
/// # Safety
/// Call once in a dedicated single-threaded CLI process. This command forks a
/// worker, controls SIGINT, and moves the publisher into a child user namespace.
pub unsafe fn validate(
    input: &str,
    format: Format,
    bundle: &str,
    allowlist: &str,
    out: String,
) -> Outcome {
    let start = Instant::now();
    let id = match run_id() {
        Ok(id) => id,
        Err(code) => return Outcome::failed(Operation::Validate, Some(out), code),
    };
    let validate_run = || {
        let staging = Staging::create(&id)?;
        let (root, name) = Directory::parent(&out)?;
        let dir = root.create_run(&name)?;
        let watch = PublicationWatch::new()?;
        let prepare = || {
            let prepared = prepare_validation(
                input,
                format,
                bundle,
                allowlist,
                &dir,
                &staging.directory,
                &id,
            )?;
            artifact::seal(&dir, &prepared, &watch)?;
            Ok(prepared)
        };
        // This CLI process has one thread as required by validate's caller.
        unsafe { supervise(prepare, start) }.and_then(|prepared| {
            let checked = artifact::check_prepared(&dir, &prepared);
            terminal(start, || {
                checked?;
                artifact::publish(&dir, &prepared, &watch)?;
                Ok(prepared)
            })
        })
    };
    match validate_run() {
        Ok(prepared) => done(Operation::Validate, out, prepared),
        Err(code) => {
            let mut failure = Outcome::failed(Operation::Validate, Some(out), code);
            failure.run_id = Some(id);
            failure
        }
    }
}

fn prepare_validation(
    input: &str,
    format: Format,
    bundle: &str,
    allowlist: &str,
    dir: &Directory,
    staging: &Directory,
    id: &str,
) -> Result<Prepared, Code> {
    let started = timestamp()?;
    let allow = read_path(allowlist, ALLOWLIST_LIMIT, Code::BundleInvalid)?;
    let (base, name) = Directory::parent(bundle)?;
    let manifest = stable_read(base.file(&name)?, 5_242_880, Code::LimitBundle)?;
    let policy = Policy::admit(&manifest, &allow, |name, remaining| {
        stable_read(base.file(name)?, remaining, Code::LimitBundle)
    })?;
    let (parent, name) = Directory::parent(input)?;
    let digest = {
        let mut target = staging.new_file("source")?;
        copy_checked(
            &mut parent.file(&name)?,
            &mut target,
            INPUT_LIMIT as u64,
            Code::LimitInput,
            Code::InputChanged,
        )?
    };
    let mut data = Vec::new();
    staging
        .file("source")?
        .read_to_end(&mut data)
        .map_err(|_| Code::IoFailure)?;
    artifact::prepare(dir, &policy, format, &data, digest, id, started)
}

/// Run the native verification command in the CLI process.
///
/// # Safety
/// Call only from the single-threaded CLI. This command forks a worker and
/// temporarily controls SIGINT for the process.
pub unsafe fn verify(run: String) -> Outcome {
    let start = Instant::now();
    let verify_run = || {
        let src = Directory::open(Path::new(&run))?;
        let staging = Staging::create(&run_id()?)?;
        // This CLI process has one thread as required by verify's caller.
        let prepared = unsafe { supervise(|| artifact::verify(&src, &staging.directory), start) }?;
        terminal(start, || Ok(prepared))
    };
    match verify_run() {
        Ok(prepared) => done(Operation::Verify, run, prepared),
        Err(code) => Outcome::failed(Operation::Verify, Some(run), code),
    }
}

fn done(operation: Operation, parent: String, prepared: Prepared) -> Outcome {
    Outcome::completed(
        operation,
        parent,
        prepared.id,
        prepared.counts.records,
        prepared.counts.valid,
    )
}

extern "C" fn cancel(_: libc::c_int) {
    CANCELED.store(true, Ordering::Relaxed);
}

pub struct CancelHandler(libc::sigaction);

impl CancelHandler {
    /// # Safety
    /// The caller is the single-threaded CLI and holds this guard through its outcome.
    pub unsafe fn register() -> Result<Self, Code> {
        CANCELED.store(false, Ordering::Relaxed);
        // The signal handler only changes a lock-free flag.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = cancel as *const () as libc::sighandler_t;
        let mut previous = std::mem::MaybeUninit::uninit();
        unsafe {
            if libc::sigemptyset(&mut action.sa_mask) != 0
                || libc::sigaction(libc::SIGINT, &action, previous.as_mut_ptr()) != 0
            {
                return Err(Code::InternalFailure);
            }
            Ok(Self(previous.assume_init()))
        }
    }
}

impl Drop for CancelHandler {
    fn drop(&mut self) {
        unsafe { libc::sigaction(libc::SIGINT, &self.0, std::ptr::null_mut()) };
    }
}

fn pending(start: Instant) -> Result<(), Code> {
    if CANCELED.load(Ordering::Relaxed) {
        Err(Code::Canceled)
    } else if start.elapsed() >= Duration::from_millis(RUN_LIMIT_MS) {
        Err(Code::LimitTime)
    } else {
        Ok(())
    }
}

struct BlockedInterrupt(libc::sigset_t);

impl Drop for BlockedInterrupt {
    fn drop(&mut self) {
        unsafe { libc::sigprocmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut()) };
    }
}

fn terminal<T>(start: Instant, commit: impl FnOnce() -> Result<T, Code>) -> Result<T, Code> {
    pending(start)?;
    let mut signals = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    let mut previous = std::mem::MaybeUninit::uninit();
    // This process has one thread. Block delivery at the terminal decision so
    // a later interrupt cannot undo the successful publication or verify result.
    unsafe {
        if libc::sigemptyset(signals.as_mut_ptr()) != 0 {
            return Err(Code::InternalFailure);
        }
        let mut signals = signals.assume_init();
        if libc::sigaddset(&mut signals, libc::SIGINT) != 0
            || libc::sigprocmask(libc::SIG_BLOCK, &signals, previous.as_mut_ptr()) != 0
        {
            return Err(Code::InternalFailure);
        }
        let _blocked = BlockedInterrupt(previous.assume_init());
        if libc::sigpending(&mut signals) != 0 {
            return Err(Code::InternalFailure);
        }
        if libc::sigismember(&signals, libc::SIGINT) == 1 {
            return Err(Code::Canceled);
        }
        pending(start)?;
        commit()
    }
}

/// Fork only from the single-threaded native CLI and wait for a bounded reply.
unsafe fn supervise(
    operate: impl FnOnce() -> Result<Prepared, Code>,
    start: Instant,
) -> Result<Prepared, Code> {
    pending(start)?;
    let (parent, mut report) = UnixStream::pair().map_err(|_| Code::InternalFailure)?;
    let supervisor = std::process::id();
    let worker = unsafe { libc::fork() };
    match worker {
        -1 => return Err(Code::InternalFailure),
        0 => {
            drop(parent);
            let reply = match configure_worker(supervisor).and_then(|()| operate()) {
                Ok(prepared) => Reply::Prepared(prepared),
                Err(code) => Reply::Failed(code),
            };
            // The supervisor reaps before reading. Send one bounded frame so
            // serialization cannot fill the socket with many tiny writes.
            let sent = send_reply(&mut report, &reply);
            let status = if sent { 0 } else { 3 };
            // The worker inherited supervisor-owned RAII values. Exit here
            // without unwinding them or running process-wide destructors.
            unsafe { libc::_exit(status) }
        }
        _ => drop(report),
    }

    loop {
        if let Err(code) = pending(start) {
            stop_and_reap(worker);
            return Err(code);
        }
        let mut status = 0;
        match unsafe { libc::waitpid(worker, &mut status, libc::WNOHANG) } {
            0 => std::thread::sleep(Duration::from_millis(5)),
            -1 if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
            -1 => return Err(Code::InternalFailure),
            _ => {
                if !libc::WIFEXITED(status) {
                    return Err(Code::InternalFailure);
                }
                match libc::WEXITSTATUS(status) {
                    WORKER_OOM_EXIT => return Err(Code::LimitMemory),
                    0 => (),
                    _ => return Err(Code::InternalFailure),
                }
                let response: Reply = serde_json::from_reader(parent.take(REPLY_LIMIT as u64))
                    .map_err(|_| Code::InternalFailure)?;
                return match response {
                    Reply::Prepared(prepared) => Ok(prepared),
                    Reply::Failed(code) => Err(code),
                };
            }
        }
    }
}

fn send_reply(report: &mut UnixStream, reply: &Reply) -> bool {
    serde_json::to_vec(reply)
        .is_ok_and(|frame| frame.len() <= REPLY_LIMIT && report.write_all(&frame).is_ok())
}

fn configure_worker(supervisor: u32) -> Result<(), Code> {
    let budget = libc::rlimit {
        rlim_cur: MEMORY_LIMIT,
        rlim_max: MEMORY_LIMIT,
    };
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
            return Err(Code::InternalFailure);
        }
        if libc::getppid() as u32 != supervisor {
            libc::_exit(3);
        }
        if libc::setrlimit(libc::RLIMIT_AS, &budget) != 0
            || libc::setrlimit(libc::RLIMIT_CORE, &no_core) != 0
            || libc::signal(libc::SIGINT, libc::SIG_IGN) == libc::SIG_ERR
        {
            return Err(Code::InternalFailure);
        }
    }
    WORKER_MEMORY_GUARD.store(true, Ordering::Relaxed);
    // Avoid reporting panic text, pathnames or raw input from the worker.
    std::panic::set_hook(Box::new(|_| unsafe { libc::_exit(3) }));
    Ok(())
}

fn stop_and_reap(worker: libc::pid_t) {
    unsafe {
        libc::kill(worker, libc::SIGKILL);
        while libc::waitpid(worker, std::ptr::null_mut(), 0) < 0
            && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
        {}
    }
}

/// Convert a null allocation only in the supervised worker into its fixed exit code.
pub fn guard_allocation(pointer: *mut u8) -> *mut u8 {
    if pointer.is_null() && WORKER_MEMORY_GUARD.load(Ordering::Relaxed) {
        unsafe { libc::_exit(WORKER_OOM_EXIT) }
    }
    pointer
}
