use sesv::contract::{Code, Format, Operation, Outcome};
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

struct Allocator;

// Report worker allocation refusal to its supervisor without allocating
// an error message or conflating it with a different process failure.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        sesv::native::guard_allocation(unsafe { System.alloc(layout) })
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        sesv::native::guard_allocation(unsafe { System.alloc_zeroed(layout) })
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        sesv::native::guard_allocation(unsafe { System.realloc(ptr, layout, size) })
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

enum Command {
    Validate {
        input: String,
        format: Format,
        bundle: String,
        allowlist: String,
        out: String,
    },
    Verify {
        run: String,
    },
}

fn parse(operation: Operation, arguments: &[OsString]) -> Result<Command, (Code, Option<String>)> {
    let names: &[&str] = match operation {
        Operation::Validate => &["--input", "--format", "--bundle", "--allowlist", "--out"],
        Operation::Verify => &["--run"],
    };
    let invalid = || (Code::ArgumentInvalid, None);
    if arguments.len() != 2 * names.len() {
        return Err(invalid());
    }
    let mut values = BTreeMap::new();
    for [name, value] in arguments.as_chunks::<2>().0 {
        let name = name.to_str().ok_or_else(invalid)?;
        let value = value.to_str().ok_or_else(invalid)?;
        if !names.contains(&name)
            || value.is_empty()
            || value.starts_with("--")
            || values.insert(name, value.to_owned()).is_some()
        {
            return Err(invalid());
        }
    }
    if operation == Operation::Verify {
        return Ok(Command::Verify {
            run: values.remove("--run").unwrap(),
        });
    }
    let out = values.remove("--out").unwrap();
    let format = Format::select(&values["--format"]).map_err(|code| (code, Some(out.clone())))?;
    Ok(Command::Validate {
        input: values.remove("--input").unwrap(),
        format,
        bundle: values.remove("--bundle").unwrap(),
        allowlist: values.remove("--allowlist").unwrap(),
        out,
    })
}

fn emit(outcome: Outcome) -> ExitCode {
    let mut out = io::stdout().lock();
    if serde_json::to_writer(&mut out, &outcome).is_ok() && out.write_all(b"\n").is_ok() {
        ExitCode::from(outcome.exit_code)
    } else {
        ExitCode::from(3)
    }
}

fn help(operation: Option<Operation>) {
    if operation != Some(Operation::Verify) {
        println!(
            "sesv validate --input PATH --format FORMAT --bundle PATH --allowlist PATH --out NEW_DIRECTORY"
        );
        println!("Formats: json, ndjson, cloudevents-json.");
    }
    if operation != Some(Operation::Validate) {
        println!("sesv verify --run DIRECTORY");
        println!("Verify checks the internal integrity of a completed run directory.");
    }
    println!(
        "The local operator selects the bundle and allowlist. Formal policy approval happens outside SESV."
    );
    println!(
        "Validation checks the selected policy. Delivery, source authentication, deduplication, state reconciliation, and business permission are outside its scope."
    );
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args == ["--help"] {
        help(None);
        return ExitCode::SUCCESS;
    }
    let operation = match args.first().and_then(|arg| arg.to_str()) {
        Some("validate") => Operation::Validate,
        Some("verify") => Operation::Verify,
        _ => {
            eprintln!("{}", Code::ArgumentInvalid.message());
            return ExitCode::from(4);
        }
    };
    if args[1..] == ["--help"] {
        help(Some(operation));
        return ExitCode::SUCCESS;
    }
    let command = match parse(operation, &args[1..]) {
        Ok(command) => command,
        Err((code, out)) => return emit(Outcome::failed(operation, out, code)),
    };
    // The CLI owns SIGINT and keeps this guard through the outcome.
    let _cancel = match unsafe { sesv::native::CancelHandler::register() } {
        Ok(handler) => handler,
        Err(code) => return emit(Outcome::failed(operation, None, code)),
    };
    // The CLI runs this native adapter before spawning any threads.
    let result = unsafe {
        match command {
            Command::Validate {
                input,
                format,
                bundle,
                allowlist,
                out,
            } => sesv::native::validate(&input, format, &bundle, &allowlist, out),
            Command::Verify { run } => sesv::native::verify(run),
        }
    };
    emit(result)
}
