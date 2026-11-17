//! Deterministic byte mutation through the production Policy interface.
use sesv::contract::{Code, ERROR_LIMIT, Format, RECORD_LIMIT};
use sesv::engine::{Policy, Status, sha256};
use std::{
    env, fs,
    io::{self, Write},
    os::fd::AsRawFd,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    ptr::NonNull,
    sync::atomic::{AtomicU8, Ordering},
    time::{Duration, Instant},
};

const SEED: u64 = 0xe327_35e7_89ad_42ac;
const MARKER: &str = "NEVER_COPY_PRIVATE_FUZZ_FIELD";
const SLOT: usize = 8192;

// Keep the current input in a shared file before invoking the parser. Two
// slots keep the previous complete case recoverable even if recording stops.
struct Checkpoint {
    mapping: NonNull<u8>,
    slot: usize,
}

impl Checkpoint {
    const LENGTH: usize = 1 + 2 * SLOT;

    fn create(path: &Path) -> io::Result<Self> {
        let file = fs::File::options()
            .write(true)
            .read(true)
            .create_new(true)
            .open(path)?;
        file.set_len(Self::LENGTH as u64)?;
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                Self::LENGTH,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let mapping =
            NonNull::new(mapped.cast()).ok_or_else(|| io::Error::other("null mapping"))?;
        Ok(Self { mapping, slot: 0 })
    }

    fn current(&mut self, index: u64, format: usize, sample: &[u8]) {
        let slot = self.slot ^ 1;
        let size = sample.len();
        assert!(size <= SLOT - 13);
        // Header: u64le index, u32le byte length, u8 format, then input.
        let data = unsafe {
            std::slice::from_raw_parts_mut(self.mapping.as_ptr().add(1 + slot * SLOT), 13 + size)
        };
        data[..8].copy_from_slice(&index.to_le_bytes());
        data[8..12].copy_from_slice(&(size as u32).to_le_bytes());
        data[12] = format as u8;
        data[13..].copy_from_slice(sample);
        unsafe { &*self.mapping.as_ptr().cast::<AtomicU8>() }.store(slot as u8, Ordering::Release);
        self.slot = slot;
    }
}

impl Drop for Checkpoint {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.mapping.as_ptr().cast(), Self::LENGTH) };
    }
}

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, end: usize) -> usize {
        (self.next() as usize) % end
    }
}

fn mutate(mut bytes: Vec<u8>, random: &mut Random) -> Vec<u8> {
    const TOKENS: &[&[u8]] = &[
        b"\xff",
        b"\xef\xbb\xbf",
        br#"\uD800"#,
        br#"\uDC00"#,
        br#"\uD83D\uDE00"#,
        br#"\u12q0"#,
        b"\r\n",
        b"\n",
        b"0e19999999999999",
        b"-0.000e-999",
        b"9007199254740993.0",
        b"\n{}\n",
        b"[",
        b"\"",
        b"{}",
        b"null",
    ];
    for _ in 0..=random.below(7) {
        let offset = random.below(bytes.len() + 1);
        let count = random.below(35);
        let end = (offset + count).min(bytes.len());
        match random.below(5) {
            0 => bytes.truncate(offset),
            1 => {
                bytes.drain(offset..end);
            }
            2 => {
                let replacement = vec![random.next() as u8; count];
                bytes.splice(offset..end, replacement);
            }
            3 => {
                bytes.splice(
                    offset..offset,
                    TOKENS[random.below(TOKENS.len())].iter().copied(),
                );
            }
            _ => {
                let copy = bytes[offset..end].to_vec();
                bytes.splice(offset..offset, copy);
            }
        }
    }
    bytes
}

fn exercise(policy: &Policy, input: &[u8], format: Format) -> String {
    let mut records = 0;
    let mut valid = 0;
    let mut previous_end = 0;
    let mut transcript = Vec::new();
    let result = policy.validate(input, format, |row, export| {
        records += 1;
        assert_eq!(row.record_index, records);
        assert_eq!(
            row.source_line,
            (format == Format::Ndjson).then_some(records)
        );
        assert!(previous_end <= row.record_byte_start);
        assert!(row.record_byte_length <= RECORD_LIMIT);
        let end = row.record_byte_start + row.record_byte_length;
        assert!(end <= input.len());
        previous_end = end;
        assert!(row.errors.len() <= ERROR_LIMIT);
        for error in &row.errors {
            assert_eq!(error.message, error.code.message());
            if let Some(offset) = error.location.byte_offset {
                assert!((row.record_byte_start..=end).contains(&offset));
            }
        }
        let row_bytes = serde_json::to_vec(&row).unwrap();
        assert!(
            !row_bytes
                .windows(MARKER.len())
                .any(|part| part == MARKER.as_bytes())
        );
        transcript.extend(row_bytes);
        if let Some(bytes) = export {
            valid += 1;
            assert_eq!(row.status, Status::Valid);
            assert!(row.errors.is_empty());
            assert_eq!(row.valid_output_index, Some(valid));
            let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            assert!(value.is_object());
            assert_eq!(bytes.last(), Some(&b'\n'));
            transcript.extend(bytes);
        } else {
            assert_eq!(row.status, Status::Invalid);
            assert!(row.valid_output_index.is_none());
            assert!(!row.errors.is_empty());
        }
        Ok(())
    });
    match result {
        Ok(counts) => assert_eq!((counts.records, counts.valid), (records, valid)),
        Err(code) => assert!(matches!(
            code,
            Code::EmptyInput | Code::LimitDepth | Code::LimitCount | Code::LimitRecord
        )),
    }
    format!("{:?} {}", result.map(|_| ()), sha256(&transcript))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    let [fixture, seconds, report] = arguments.as_slice() else {
        return Err("expected FIXTURE SECONDS NEW_REPORT_DIRECTORY".into());
    };
    let fixture = Path::new(fixture);
    let report = Path::new(report);
    let runtime = Duration::from_secs(seconds.parse()?);
    fs::create_dir(report)?;
    let manifest = fs::read(fixture.join("bundle.json"))?;
    let allowance = fs::read(fixture.join("allowlist.json"))?;
    let policy = Policy::admit(&manifest, &allowance, |name, _| {
        fs::read(fixture.join(name)).map_err(|_| Code::IoFailure)
    })
    .map_err(|code| code.message())?;
    let native = fs::read(fixture.join("events.ndjson"))?;
    let cloud = fs::read(fixture.join("cloud.json"))?;
    let mut seeds: Vec<_> = native
        .split(|byte| *byte == b'\n')
        .map(|row| row.to_vec())
        .collect();
    seeds.extend([native, cloud]);
    seeds.push(format!(r#"{{"{MARKER}":"redaction canary"}}"#).into_bytes());
    seeds.push([b"[".repeat(65), b"0".to_vec(), b"]".repeat(65)].concat());
    seeds.push(br#"{"a":"first","\u0061":"second"}"#.to_vec());
    seeds.push(vec![0xf0, 0x80, 0x80, 0x80]);
    for (index, bytes) in seeds.iter().enumerate() {
        fs::write(report.join(format!("seed-{index:02}.bin")), bytes)?;
    }
    let stdout = io::stdout();
    let mut log = stdout.lock();
    writeln!(
        log,
        "seed={SEED:016x} bundle_sha256={} duration_seconds={seconds}",
        sha256(&manifest)
    )?;
    log.flush()?;
    let start = Instant::now();
    let mut random = Random(SEED);
    let mut count = 0_u64;
    let mut checkpoint = 0;
    let mut current_case = Checkpoint::create(&report.join("last-input-checkpoint.bin"))?;
    let mut formats = [0_u64; 3];
    let supported = [Format::Json, Format::Ndjson, Format::CloudEvents];
    while start.elapsed() < runtime {
        let which = random.below(seeds.len());
        let sample = mutate(seeds[which].clone(), &mut random);
        let selected = random.below(3);
        formats[selected] += 1;
        current_case.current(count, selected, &sample);
        let attempt = catch_unwind(AssertUnwindSafe(|| {
            let initial = exercise(&policy, &sample, supported[selected]);
            if count.is_multiple_of(1024) {
                assert_eq!(initial, exercise(&policy, &sample, supported[selected]));
            }
        }));
        if attempt.is_err() {
            fs::write(report.join("failure.bin"), &sample)?;
            return Err(
                format!("failure at input {count}, format {:?}", supported[selected]).into(),
            );
        }
        count += 1;
        if start.elapsed().as_secs() >= checkpoint + 60 {
            checkpoint = start.elapsed().as_secs();
            writeln!(
                log,
                "elapsed_seconds={checkpoint} inputs={count} formats={formats:?} prng={:016x}",
                random.0
            )?;
            log.flush()?;
        }
    }
    writeln!(
        log,
        "PASS elapsed_ms={} inputs={count} formats={formats:?}",
        start.elapsed().as_millis()
    )?;
    Ok(())
}
