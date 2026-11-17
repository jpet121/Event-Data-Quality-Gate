use crate::contract::*;
use crate::engine::{self, Contract, Counts, Policy, Record, Status};
use crate::filesystem::{
    Directory, FileVersion, Fingerprint, IgnoreLeaseNotifications, PublicationLease,
    PublicationWatch, copy_checked, file_version, isolate_publisher, transfer,
};
use crate::json::{self, Encode, ObjectEncoder};
use crate::schema::is_urn;
use serde::{Deserialize, Serialize, de};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
};

pub(crate) const FILES: [&str; 4] = [
    "valid.ndjson",
    "results.ndjson",
    "manifest.json",
    "COMPLETE.json",
];
pub(crate) const PENDING_MARKER: &str = ".completion-pending";
const COMPLETE_MARKER: &str = FILES[3];
const STAGED: [&str; 4] = [FILES[0], FILES[1], FILES[2], PENDING_MARKER];

#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Configuration {
    #[serde(deserialize_with = "crate::contract::required_field")]
    format: Format,
    #[serde(deserialize_with = "crate::contract::required_field")]
    bundle_sha256: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    input_limit_bytes: usize,
    #[serde(deserialize_with = "crate::contract::required_field")]
    record_limit_bytes: usize,
    #[serde(deserialize_with = "crate::contract::required_field")]
    record_limit_count: usize,
    #[serde(deserialize_with = "crate::contract::required_field")]
    depth_limit: usize,
    #[serde(deserialize_with = "crate::contract::required_field")]
    error_limit: usize,
    #[serde(deserialize_with = "crate::contract::required_field")]
    output_limit_bytes: u64,
    #[serde(deserialize_with = "crate::contract::required_field")]
    run_limit_ms: u64,
    #[serde(deserialize_with = "present_option")]
    worker_memory_limit_bytes: Option<u64>,
    #[serde(deserialize_with = "crate::contract::required_field")]
    result_version: String,
}

impl Configuration {
    fn new(format: Format, bundle: &str, memory: Option<u64>) -> Self {
        Self {
            format,
            bundle_sha256: bundle.into(),
            input_limit_bytes: INPUT_LIMIT,
            record_limit_bytes: RECORD_LIMIT,
            record_limit_count: COUNT_LIMIT,
            depth_limit: DEPTH_LIMIT,
            error_limit: ERROR_LIMIT,
            output_limit_bytes: OUTPUT_LIMIT,
            run_limit_ms: RUN_LIMIT_MS,
            worker_memory_limit_bytes: memory,
            result_version: RESULT_VERSION.into(),
        }
    }

    fn digest(&self) -> String {
        let mut bytes = Vec::new();
        self.encode(&mut bytes);
        engine::sha256(&bytes)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputFile {
    #[serde(deserialize_with = "crate::contract::required_field")]
    file: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    bytes: u64,
    #[serde(deserialize_with = "crate::contract::required_field")]
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    #[serde(deserialize_with = "crate::contract::required_field")]
    result_version: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    run_id: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    application_version: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    build_sha256: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    core_sha256: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    input_sha256: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    input_bytes: u64,
    #[serde(deserialize_with = "crate::contract::required_field")]
    format: Format,
    #[serde(deserialize_with = "crate::contract::required_field")]
    bundle_id: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    bundle_version: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    bundle_sha256: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    configuration: Configuration,
    #[serde(deserialize_with = "crate::contract::required_field")]
    configuration_sha256: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    started_at: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    finished_at: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    record_count: usize,
    #[serde(deserialize_with = "crate::contract::required_field")]
    valid_count: usize,
    #[serde(deserialize_with = "crate::contract::required_field")]
    invalid_count: usize,
    #[serde(deserialize_with = "crate::contract::required_field")]
    deduplication_performed: bool,
    #[serde(deserialize_with = "crate::contract::required_field")]
    delivery_authorized: bool,
    #[serde(deserialize_with = "crate::contract::required_field")]
    complete: bool,
    #[serde(deserialize_with = "crate::contract::required_field")]
    contracts: Vec<Contract>,
    #[serde(deserialize_with = "crate::contract::required_field")]
    outputs: Vec<OutputFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    #[serde(deserialize_with = "crate::contract::required_field")]
    result_version: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    manifest_sha256: String,
}

// The format fixes the field names and the configuration digest fixes their order.
macro_rules! encode_fields {
    ($type:ident { $($field:ident),+ $(,)? }) => {
        impl Encode for $type {
            fn encode(&self, out: &mut Vec<u8>) {
                let mut object = ObjectEncoder::new(out);
                $(object.field(stringify!($field), &self.$field);)+
                object.finish();
            }
        }
    };
}

impl Encode for Format {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Json => "json",
            Self::Ndjson => "ndjson",
            Self::CloudEvents => "cloudevents-json",
        }
        .encode(out);
    }
}

encode_fields!(Configuration {
    format,
    bundle_sha256,
    input_limit_bytes,
    record_limit_bytes,
    record_limit_count,
    depth_limit,
    error_limit,
    output_limit_bytes,
    run_limit_ms,
    worker_memory_limit_bytes,
    result_version,
});
encode_fields!(OutputFile {
    file,
    bytes,
    sha256
});
encode_fields!(Contract {
    event_type,
    schema_id,
    schema_version,
    module_id,
    module_version,
    module_sha256
});
encode_fields!(Manifest {
    result_version,
    run_id,
    application_version,
    build_sha256,
    core_sha256,
    input_sha256,
    input_bytes,
    format,
    bundle_id,
    bundle_version,
    bundle_sha256,
    configuration,
    configuration_sha256,
    started_at,
    finished_at,
    record_count,
    valid_count,
    invalid_count,
    deduplication_performed,
    delivery_authorized,
    complete,
    contracts,
    outputs,
});
encode_fields!(Marker {
    result_version,
    manifest_sha256
});

fn json_line(value: &impl Encode) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.encode(&mut bytes);
    bytes.push(b'\n');
    bytes
}

fn json_doc<T: de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Code> {
    if bytes.last() != Some(&b'\n') || json::parse(bytes).is_err() {
        return Err(Code::ArtifactInvalid);
    }
    serde_json::from_slice(bytes).map_err(|_| Code::ArtifactInvalid)
}

#[derive(Serialize)]
pub(crate) struct Prepared {
    pub(crate) id: String,
    pub(crate) counts: Counts,
    publication: Option<Box<Publication>>,
}

impl<'de> Deserialize<'de> for Prepared {
    fn deserialize<D: de::Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        const FIELDS: &[&str] = &["id", "counts", "publication"];

        struct PreparedVisitor;

        impl<'de> de::Visitor<'de> for PreparedVisitor {
            type Value = Prepared;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct Prepared")
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Prepared, A::Error> {
                // Sequences require an explicit third element, including null.
                const EXPECTED: &str = "struct Prepared with 3 elements";
                Ok(Prepared {
                    id: seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(0, &EXPECTED))?,
                    counts: seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(1, &EXPECTED))?,
                    publication: seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(2, &EXPECTED))?,
                })
            }

            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Prepared, A::Error> {
                #[derive(Deserialize)]
                #[serde(field_identifier, rename_all = "snake_case")]
                enum Field {
                    Id,
                    Counts,
                    Publication,
                    #[serde(other)]
                    Unknown,
                }

                fn read<'de, A: de::MapAccess<'de>, T: Deserialize<'de>>(
                    map: &mut A,
                    slot: &mut Option<T>,
                    name: &'static str,
                ) -> Result<(), A::Error> {
                    if slot.is_some() {
                        return Err(de::Error::duplicate_field(name));
                    }
                    *slot = Some(map.next_value()?);
                    Ok(())
                }

                let (mut id, mut counts, mut publication) = (None, None, None);
                while let Some(field) = map.next_key()? {
                    match field {
                        Field::Id => read(&mut map, &mut id, "id")?,
                        Field::Counts => read(&mut map, &mut counts, "counts")?,
                        Field::Publication => read(&mut map, &mut publication, "publication")?,
                        Field::Unknown => {
                            map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(Prepared {
                    id: id.ok_or_else(|| de::Error::missing_field("id"))?,
                    counts: counts.ok_or_else(|| de::Error::missing_field("counts"))?,
                    publication: publication.unwrap_or(None),
                })
            }
        }

        input.deserialize_struct("Prepared", FIELDS, PreparedVisitor)
    }
}

#[derive(Deserialize, Serialize)]
struct Publication {
    #[serde(deserialize_with = "crate::contract::required_field")]
    versions: [FileVersion; STAGED.len()],
    #[serde(deserialize_with = "crate::contract::required_field")]
    digests: [String; STAGED.len()],
}

pub(crate) fn seal(
    dir: &Directory,
    prepared: &Prepared,
    watch: &PublicationWatch,
) -> Result<(), Code> {
    let publication = prepared
        .publication
        .as_deref()
        .ok_or(Code::InternalFailure)?;
    watch.arm(dir)?;
    check_staged(dir, publication, Some(watch))?;
    watch.check_clean()
}

pub(crate) fn check_prepared(dir: &Directory, prepared: &Prepared) -> Result<(), Code> {
    let publication = prepared
        .publication
        .as_deref()
        .ok_or(Code::InternalFailure)?;
    check_staged(dir, publication, None)
}

pub(crate) fn publish(
    dir: &Directory,
    prepared: &Prepared,
    watch: &PublicationWatch,
) -> Result<(), Code> {
    let publication = prepared
        .publication
        .as_deref()
        .ok_or(Code::InternalFailure)?;
    watch.check_clean()?;
    let _notifications = IgnoreLeaseNotifications::install()?;
    let fenced_watch = PublicationWatch::new()?;
    fenced_watch.watch_entries(dir, 0)?;
    let mut leases = Vec::with_capacity(STAGED.len());
    for (index, &name) in STAGED.iter().enumerate() {
        let lease = PublicationLease::acquire(staged_file(dir, name)?)?;
        if lease.version()? != publication.versions[index] {
            return Err(Code::ArtifactInvalid);
        }
        lease.watch(&fenced_watch)?;
        leases.push(lease);
    }
    watch.check_clean()?;
    let directory_fence = dir.restrict()?;
    // The original watch also caught metadata changes before the fences. The
    // second watch spans fchmod, omitting only directory attribute events.
    for lease in &leases {
        lease.check()?;
    }
    directory_fence.check()?;
    fenced_watch.check_clean()?;
    // The directory and all inodes remain fenced through the atomic rename.
    let authority = isolate_publisher()?;
    let committed = dir.publish(PENDING_MARKER, COMPLETE_MARKER);
    drop(authority);
    if committed.is_ok() {
        // The artifact is now available to a verifier. Do not change its
        // metadata behind that verifier or require it to share a lock.
        directory_fence.leave_restricted();
    }
    committed
}

fn check_staged(
    dir: &Directory,
    publication: &Publication,
    watch: Option<&PublicationWatch>,
) -> Result<(), Code> {
    let directory_version = dir.version()?;
    let listed = dir.entries(5)?.into_iter().collect::<BTreeSet<_>>();
    if listed
        != STAGED
            .iter()
            .copied()
            .map(std::ffi::OsString::from)
            .collect()
    {
        return Err(Code::ArtifactInvalid);
    }
    for (index, &name) in STAGED.iter().enumerate() {
        let mut file = staged_file(dir, name)?;
        let before = file_version(&file)?;
        let expected = &publication.versions[index];
        if before != *expected {
            return Err(Code::ArtifactInvalid);
        }
        // An equal timestamp is not proof of equal bytes. Recheck the
        // contents against the worker's readback, with the original bound.
        if let Some(watch) = watch {
            watch.watch_file(&file)?;
            let actual = readback(&mut file, expected.length())?;
            if actual.sha256 != publication.digests[index] || before != file_version(&file)? {
                return Err(Code::ArtifactInvalid);
            }
        }
    }
    if dir.version()? != directory_version {
        return Err(Code::ArtifactInvalid);
    }
    Ok(())
}

fn readback(file: &mut File, limit: u64) -> Result<Fingerprint, Code> {
    copy_checked(
        file,
        &mut io::sink(),
        limit,
        Code::ArtifactInvalid,
        Code::ArtifactInvalid,
    )
}

fn staged_file(dir: &Directory, name: &str) -> Result<File, Code> {
    dir.file(name).map_err(artifact_path_error)
}

fn artifact_path_error(code: Code) -> Code {
    match code {
        Code::PathRejected => Code::ArtifactInvalid,
        other => other,
    }
}

struct Budget {
    left: u64,
    exceeded: bool,
}

impl Budget {
    fn check_readback(&self, bytes: u64) -> Result<(), Code> {
        if bytes != OUTPUT_LIMIT - self.left {
            return Err(Code::ArtifactInvalid);
        }
        Ok(())
    }

    fn reserve(&mut self, size: usize) -> Result<(), Code> {
        if size as u64 > self.left {
            self.exceeded = true;
            return Err(Code::LimitOutput);
        }
        self.left -= size as u64;
        Ok(())
    }

    fn bytes(&mut self, file: &mut impl Write, bytes: &[u8]) -> Result<(), Code> {
        self.reserve(bytes.len())?;
        file.write_all(bytes).map_err(|_| Code::IoFailure)
    }
}

struct OutputWriter {
    file: BufWriter<File>,
    digest: Sha256,
}

impl OutputWriter {
    fn new(file: File) -> Self {
        Self {
            file: BufWriter::with_capacity(64 * 1024, file),
            digest: Sha256::new(),
        }
    }

    fn close(self) -> Result<String, Code> {
        self.file
            .into_inner()
            .map_err(|_| Code::IoFailure)?
            .sync_all()
            .map_err(|_| Code::IoFailure)?;
        Ok(format!("{:x}", self.digest.finalize()))
    }
}

impl Write for OutputWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.file.write(buf)?;
        self.digest.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

struct Meter<'a>(&'a mut Budget, &'a mut OutputWriter);

impl Write for Meter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .reserve(buf.len())
            .map_err(|_| io::Error::other("output budget"))?;
        self.1.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.1.flush()
    }
}

pub(crate) fn prepare(
    dir: &Directory,
    policy: &Policy,
    format: Format,
    source: &[u8],
    input: Fingerprint,
    id: &str,
    started_at: String,
) -> Result<Prepared, Code> {
    let mut valid = OutputWriter::new(dir.new_artifact(FILES[0])?);
    let mut results = OutputWriter::new(dir.new_artifact(FILES[1])?);
    let mut budget = Budget {
        left: OUTPUT_LIMIT,
        exceeded: false,
    };
    let mut contracts: BTreeMap<_, Contract> = BTreeMap::new();
    let counts = policy.validate(source, format, |row, export| {
        if let Some(contract) = policy.contract(&row) {
            contracts
                .entry((contract.event_type.clone(), contract.schema_version.clone()))
                .or_insert_with(|| contract.clone());
        }
        if let Some(bytes) = export {
            budget.bytes(&mut valid, bytes)?;
        }
        serde_json::to_writer(Meter(&mut budget, &mut results), &row).map_err(|_| {
            if budget.exceeded {
                Code::LimitOutput
            } else {
                Code::IoFailure
            }
        })?;
        budget.bytes(&mut results, b"\n")
    })?;
    let written = [valid.close()?, results.close()?];
    let configuration = Configuration::new(format, &policy.digest, Some(MEMORY_LIMIT));
    let mut exe = File::open("/proc/self/exe").map_err(|_| Code::InternalFailure)?;
    let build = transfer(&mut exe, &mut io::sink(), u64::MAX, Code::InternalFailure)?;
    let mut manifest = Manifest {
        result_version: RESULT_VERSION.into(),
        run_id: id.into(),
        application_version: env!("CARGO_PKG_VERSION").into(),
        build_sha256: build.sha256,
        core_sha256: engine::core_digest(),
        input_sha256: input.sha256,
        input_bytes: input.bytes,
        format,
        bundle_id: policy.id.clone(),
        bundle_version: policy.version.clone(),
        bundle_sha256: policy.digest.clone(),
        configuration_sha256: configuration.digest(),
        configuration,
        started_at,
        finished_at: crate::filesystem::timestamp()?,
        record_count: counts.records,
        valid_count: counts.valid,
        invalid_count: counts.records - counts.valid,
        deduplication_performed: false,
        delivery_authorized: false,
        complete: true,
        contracts: contracts.into_values().collect(),
        outputs: Vec::new(),
    };
    let mut total = 0;
    let mut inspect_output =
        |name: &str, written_hash: String, final_budget: Option<&Budget>| -> Result<_, Code> {
            let mut file = staged_file(dir, name)?;
            let before = file_version(&file)?;
            let fp = readback(&mut file, OUTPUT_LIMIT - total)?;
            if let Some(budget) = final_budget {
                budget.check_readback(total + fp.bytes)?;
            }
            if fp.sha256 != written_hash || before != file_version(&file)? {
                return Err(Code::ArtifactInvalid);
            }
            total += fp.bytes;
            manifest.outputs.push(OutputFile {
                file: name.into(),
                bytes: fp.bytes,
                sha256: fp.sha256.clone(),
            });
            Ok((before, fp.sha256))
        };
    let [valid_hash, results_hash] = written;
    let (valid_version, valid_digest) = inspect_output(FILES[0], valid_hash, None)?;
    let (results_version, results_digest) = inspect_output(FILES[1], results_hash, Some(&budget))?;

    inspect_rows(dir, &manifest)?;
    let manifest_bytes = json_line(&manifest);
    budget.reserve(manifest_bytes.len())?;
    let marker_bytes = json_line(&Marker {
        result_version: RESULT_VERSION.into(),
        manifest_sha256: engine::sha256(&manifest_bytes),
    });
    budget.reserve(marker_bytes.len())?;
    let write_metadata = |name: &str, bytes: &[u8]| -> Result<_, Code> {
        {
            let mut f = dir.new_artifact(name)?;
            f.write_all(bytes)
                .and_then(|_| f.sync_all())
                .map_err(|_| Code::IoFailure)?;
        }
        let mut file = staged_file(dir, name)?;
        let before = file_version(&file)?;
        let expected = engine::sha256(bytes);
        let actual = readback(&mut file, bytes.len() as u64)?;
        if actual.sha256 != expected || before != file_version(&file)? {
            return Err(Code::ArtifactInvalid);
        }
        Ok((before, expected))
    };
    let (manifest_version, manifest_digest) = write_metadata(FILES[2], &manifest_bytes)?;
    let (marker_version, marker_digest) = write_metadata(PENDING_MARKER, &marker_bytes)?;
    Ok(Prepared {
        id: id.into(),
        counts,
        publication: Some(Box::new(Publication {
            versions: [
                valid_version,
                results_version,
                manifest_version,
                marker_version,
            ],
            digests: [valid_digest, results_digest, manifest_digest, marker_digest],
        })),
    })
}

pub(crate) fn verify(src: &Directory, snapshot: &Directory) -> Result<Prepared, Code> {
    let directory_version = src.version()?;
    let acquired = acquire_artifact(src, snapshot);
    // A failed reopen can itself be caused by a concurrent directory edit.
    // Compare the directory even when acquisition could not finish.
    if src.version()? != directory_version {
        return Err(Code::ArtifactInvalid);
    }
    let files = acquired?;
    let marker: Marker = read_doc(snapshot, "COMPLETE.json")?;
    if marker.result_version != RESULT_VERSION
        || marker.manifest_sha256 != files["manifest.json"].sha256
    {
        return Err(Code::ArtifactInvalid);
    }
    let manifest: Manifest = read_doc(snapshot, "manifest.json")?;
    check_manifest(&manifest, &files)?;
    inspect_rows(snapshot, &manifest)?;
    Ok(Prepared {
        id: manifest.run_id,
        counts: Counts {
            records: manifest.record_count,
            valid: manifest.valid_count,
        },
        publication: None,
    })
}

fn acquire_artifact(
    src: &Directory,
    snapshot: &Directory,
) -> Result<BTreeMap<&'static str, Fingerprint>, Code> {
    let expected: BTreeSet<_> = FILES.into_iter().map(std::ffi::OsString::from).collect();
    let listed: BTreeSet<_> = src.entries(5)?.into_iter().collect();
    if listed != expected {
        return Err(Code::ArtifactInvalid);
    }
    let mut limit = OUTPUT_LIMIT;
    let mut files = BTreeMap::new();
    let mut copied_versions = Vec::with_capacity(FILES.len());
    for name in FILES {
        let mut source = src.file(name)?;
        let mut dest = snapshot.new_file(name)?;
        let before = file_version(&source)?;
        let fp = copy_checked(
            &mut source,
            &mut dest,
            limit,
            Code::ArtifactInvalid,
            Code::ArtifactInvalid,
        )?;
        limit -= fp.bytes;
        copied_versions.push(before);
        files.insert(name, fp);
    }
    if src.entries(5)?.into_iter().collect::<BTreeSet<_>>() != expected {
        return Err(Code::ArtifactInvalid);
    }
    for (name, version) in FILES.iter().zip(copied_versions) {
        if file_version(&staged_file(src, name)?)? != version {
            return Err(Code::ArtifactInvalid);
        }
    }
    Ok(files)
}

fn read_doc<T: de::DeserializeOwned>(dir: &Directory, name: &str) -> Result<T, Code> {
    let mut bytes = Vec::new();
    dir.file(name)?
        .read_to_end(&mut bytes)
        .map_err(|_| Code::IoFailure)?;
    json_doc(&bytes)
}

fn uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

fn check_manifest(m: &Manifest, files: &BTreeMap<&str, Fingerprint>) -> Result<(), Code> {
    let memory = m.configuration.worker_memory_limit_bytes;
    if m.result_version != RESULT_VERSION
        || !uuid(&m.run_id)
        || !engine::version_text(&m.application_version)
        || !engine::version_text(&m.bundle_version)
        || m.bundle_id.is_empty()
        || [
            m.build_sha256.as_str(),
            &m.core_sha256,
            &m.input_sha256,
            &m.bundle_sha256,
        ]
        .iter()
        .any(|h| !engine::hash_text(h))
        || !engine::utc_timestamp(&m.started_at)
        || !engine::utc_timestamp(&m.finished_at)
        || !(1..=INPUT_LIMIT as u64).contains(&m.input_bytes)
        || !(1..=COUNT_LIMIT).contains(&m.record_count)
        || m.valid_count.checked_add(m.invalid_count) != Some(m.record_count)
        || m.deduplication_performed
        || m.delivery_authorized
        || !m.complete
        || memory.is_some_and(|x| x != MEMORY_LIMIT)
        || m.configuration != Configuration::new(m.format, &m.bundle_sha256, memory)
        || m.configuration_sha256 != m.configuration.digest()
        || m.outputs.len() != 2
    {
        return Err(Code::ArtifactInvalid);
    }
    for (output, name) in m.outputs.iter().zip(FILES) {
        let fp = &files[name];
        if output.file != name || output.bytes != fp.bytes || output.sha256 != fp.sha256 {
            return Err(Code::ArtifactInvalid);
        }
    }
    Ok(())
}

fn inspect_rows(dir: &Directory, manifest: &Manifest) -> Result<(), Code> {
    let mut contracts = BTreeMap::new();
    let mut last_key = None;
    for contract in &manifest.contracts {
        let key = (
            contract.event_type.as_str(),
            contract.schema_version.as_str(),
        );
        if !contract.verify_fields() || last_key.is_some_and(|last| last >= key) {
            return Err(Code::ArtifactInvalid);
        }
        last_key = Some(key);
        contracts.insert(key, contract);
    }
    let mut used = BTreeSet::new();
    let mut results = BufReader::new(dir.file("results.ndjson")?);
    let mut exports = BufReader::new(dir.file("valid.ndjson")?);
    let mut result_buf = Vec::new();
    let mut export_buf = Vec::new();
    let mut valid = 0;
    let mut end = 0;
    for index in 1..=manifest.record_count {
        let row: Record = json_doc(line(&mut results, &mut result_buf)?)?;
        if row.result_version != RESULT_VERSION
            || row.record_index != index
            || row.source_line != (manifest.format == Format::Ndjson).then_some(index)
            || row.record_byte_length > RECORD_LIMIT
            || row.record_byte_start < end
            || (manifest.format != Format::Ndjson
                && (index != 1
                    || row.record_byte_start != 0
                    || row.record_byte_length as u64 != manifest.input_bytes))
        {
            return Err(Code::ArtifactInvalid);
        }
        end = row
            .record_byte_start
            .checked_add(row.record_byte_length)
            .ok_or(Code::ArtifactInvalid)?;
        if end as u64 > manifest.input_bytes {
            return Err(Code::ArtifactInvalid);
        }
        let linked = match (
            &row.event_type,
            &row.schema_version,
            &row.schema_id,
            &row.module_id,
            &row.module_version,
        ) {
            (Some(event), Some(version), Some(schema), Some(module), Some(module_version)) => {
                let key = (event.as_str(), version.as_str());
                let c = contracts.get(&key).ok_or(Code::ArtifactInvalid)?;
                if *schema != c.schema_id
                    || *module != c.module_id
                    || *module_version != c.module_version
                {
                    return Err(Code::ArtifactInvalid);
                }
                used.insert((c.event_type.as_str(), c.schema_version.as_str()));
                true
            }
            (None, None, None, None, None) => false,
            _ => return Err(Code::ArtifactInvalid),
        };
        if row.status == Status::Valid {
            valid += 1;
            if !linked
                || !row.business_rules_evaluated
                || !row.errors.is_empty()
                || row.errors_truncated
                || row.valid_output_index != Some(valid)
            {
                return Err(Code::ArtifactInvalid);
            }
            let export = json::parse(line(&mut exports, &mut export_buf)?)
                .map_err(|_| Code::ArtifactInvalid)?;
            let envelope = export.object().ok_or(Code::ArtifactInvalid)?;
            if envelope.get("type").and_then(json::Value::string) != row.event_type.as_deref()
                || !engine::envelope_errors(envelope, manifest.format).is_empty()
                || (manifest.format != Format::CloudEvents
                    && envelope.get("schema_version").and_then(json::Value::string)
                        != row.schema_version.as_deref())
            {
                return Err(Code::ArtifactInvalid);
            }
        } else if row.valid_output_index.is_some()
            || row.errors.is_empty()
            || row.errors.len() > ERROR_LIMIT
            || (row.errors_truncated && row.errors.len() != ERROR_LIMIT)
            || !errors_valid(&row, linked, manifest.format)
        {
            return Err(Code::ArtifactInvalid);
        }
    }
    if !line(&mut results, &mut result_buf)?.is_empty()
        || !line(&mut exports, &mut export_buf)?.is_empty()
        || used.len() != contracts.len()
        || valid != manifest.valid_count
    {
        return Err(Code::ArtifactInvalid);
    }
    Ok(())
}

fn line<'a>(reader: &mut impl BufRead, buffer: &'a mut Vec<u8>) -> Result<&'a [u8], Code> {
    buffer.clear();
    reader
        .read_until(b'\n', buffer)
        .map_err(|_| Code::IoFailure)?;
    if !buffer.is_empty() && buffer.last() != Some(&b'\n') {
        return Err(Code::ArtifactInvalid);
    }
    Ok(buffer)
}

fn is_pointer(path: &str) -> bool {
    if !path.is_empty() && !path.starts_with('/') {
        return false;
    }
    let mut bytes = path.bytes();
    while let Some(value) = bytes.next() {
        if value == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return false;
        }
    }
    true
}

fn errors_valid(row: &Record, linked: bool, format: Format) -> bool {
    let stage = row.errors[0].stage;
    if linked != matches!(stage, Stage::Schema | Stage::Rule)
        || row.business_rules_evaluated != (stage == Stage::Rule)
        || (matches!(stage, Stage::Parse | Stage::Routing) && row.errors.len() != 1)
    {
        return false;
    }
    let mut distinct = HashSet::new();
    row.errors.iter().all(|e| {
        let path = e.instance_path.as_deref();
        let schema = e.schema_id.as_deref();
        let schema_path = e.schema_path.as_deref();
        let rule = e.rule_id.as_deref();
        let loc = &e.location;
        let has_loc = loc.byte_offset.is_some_and(|o| {
            o >= row.record_byte_start && o <= row.record_byte_start + row.record_byte_length
        }) && loc
            .line
            .is_some_and(|l| l > 0 && row.source_line.is_none_or(|source| source == l))
            && loc.byte_column.is_some_and(|c| {
                c > 0
                    && (format != Format::Ndjson
                        || loc.byte_offset == row.record_byte_start.checked_add(c - 1))
            });
        let no_loc = loc.byte_offset.is_none() && loc.line.is_none() && loc.byte_column.is_none();
        e.stage == stage
            && e.message == e.code.message()
            && distinct.insert(e.identity())
            && match stage {
                Stage::Parse => {
                    let code = matches!(
                        e.code,
                        Code::InvalidJson | Code::InvalidUtf8 | Code::DuplicateKey
                    ) || (e.code == Code::EmptyRecord
                        && format == Format::Ndjson
                        && loc.byte_offset == Some(row.record_byte_start));
                    code && has_loc
                        && path.is_none()
                        && schema.is_none()
                        && schema_path.is_none()
                        && rule.is_none()
                }
                Stage::Envelope | Stage::Routing => {
                    let expected_path = match (stage, e.code, path) {
                        (Stage::Routing, Code::UnknownContract, Some(path)) => {
                            path == if format == Format::CloudEvents {
                                "/dataschema"
                            } else {
                                "/schema_version"
                            }
                        }
                        (Stage::Envelope, Code::TopLevelType | Code::UnknownField, Some("")) => {
                            true
                        }
                        (Stage::Envelope, Code::EnvelopeInvalid, Some(path)) => path
                            .strip_prefix('/')
                            .is_some_and(|field| engine::envelope_fields(format).contains(&field)),
                        _ => false,
                    };
                    expected_path
                        && schema.is_none()
                        && schema_path.is_none()
                        && rule.is_none()
                        && (no_loc || has_loc)
                }
                Stage::Schema => {
                    matches!(
                        e.code,
                        Code::RequiredField
                            | Code::UnknownField
                            | Code::TypeMismatch
                            | Code::SchemaViolation
                    ) && path.is_some_and(is_pointer)
                        && schema.is_some_and(is_urn)
                        && schema_path.is_some_and(is_pointer)
                        && rule.is_none()
                        && (no_loc || has_loc)
                }
                Stage::Rule => {
                    e.code == Code::RuleViolation
                        && path.is_some_and(is_pointer)
                        && schema == row.schema_id.as_deref()
                        && schema_path.is_none()
                        && rule.is_some_and(|s| !s.is_empty())
                        && (no_loc || has_loc)
                }
            }
    })
}
