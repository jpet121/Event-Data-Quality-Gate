use crate::contract::*;
use crate::json::{self, Encode, Object, Value, pointer};
use crate::schema::{Graph, is_urn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::OnceLock;

const DIALECT_ABI: &str = "sesv-rule-abi/1";
const POLICY_LIMIT: usize = 5_242_880;
pub const ALLOWLIST_LIMIT: usize = 1_048_576;

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn hash_text(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| matches!(c,b'0'..=b'9'|b'a'..=b'f'))
}

pub(crate) fn version_text(s: &str) -> bool {
    let mut parts = s.split('.');
    for _ in 0..3 {
        let Some(part) = parts.next() else {
            return false;
        };
        if part.is_empty()
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|c| c.is_ascii_digit())
        {
            return false;
        }
    }
    parts.next().is_none()
}

fn string_limit(s: &str) -> bool {
    !s.is_empty() && s.chars().take(257).count() <= 256
}

fn portable_name(name: &str) -> bool {
    if name.is_empty()
        || name.len() > 64
        || name.ends_with('.')
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
    {
        return false;
    }
    let basename = name.split('.').next().unwrap().to_ascii_uppercase();
    let device = basename
        .strip_prefix("COM")
        .or_else(|| basename.strip_prefix("LPT"))
        .is_some_and(|s| s.len() == 1 && s.as_bytes()[0].is_ascii_digit());
    !device && !matches!(basename.as_str(), "CON" | "PRN" | "AUX" | "NUL")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Allowlist {
    #[serde(deserialize_with = "crate::contract::required_field")]
    allowed_manifest_sha256: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Resource {
    #[serde(deserialize_with = "crate::contract::required_field")]
    schema_id: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    file: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    #[serde(deserialize_with = "crate::contract::required_field")]
    event_type: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    schema_version: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    dataschema: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    root_schema_id: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    module_id: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    module_version: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    module_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    #[serde(deserialize_with = "crate::contract::required_field")]
    bundle_format: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    bundle_id: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    bundle_version: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    rule_abi: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    resources: Vec<Resource>,
    #[serde(deserialize_with = "crate::contract::required_field")]
    contracts: Vec<Registration>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub event_type: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub schema_id: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub schema_version: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub module_id: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub module_version: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub module_sha256: String,
}

impl Contract {
    pub(crate) fn verify_fields(&self) -> bool {
        string_limit(&self.event_type)
            && string_limit(&self.module_id)
            && string_limit(&self.schema_id)
            && self.schema_version.len() <= 256
            && self.module_version.len() <= 256
            && is_urn(&self.schema_id)
            && version_text(&self.schema_version)
            && version_text(&self.module_version)
            && hash_text(&self.module_sha256)
    }
}

pub struct Policy {
    pub id: String,
    pub version: String,
    pub digest: String,
    contracts: BTreeMap<(String, String), AdmittedContract>,
    events: BTreeMap<String, (String, String)>,
    graph: Graph,
}

#[derive(Clone, Copy)]
enum Module {
    SchemaOnly,
    Order,
}

impl Module {
    fn select(id: &str) -> Option<Self> {
        match id {
            "builtin.schema-only" => Some(Self::SchemaOnly),
            "example.order" => Some(Self::Order),
            _ => None,
        }
    }

    fn for_contract(contract: &Contract) -> Result<Self, Code> {
        let module = Self::select(&contract.module_id).ok_or(Code::ModuleUnavailable)?;
        if contract.module_version != "1.0.0"
            || (matches!(module, Self::Order) && contract.event_type != "order.created")
            || contract.module_sha256 != module.digest()
        {
            return Err(Code::ModuleUnavailable);
        }
        Ok(module)
    }

    fn digest(self) -> &'static str {
        static SCHEMA_ONLY: OnceLock<String> = OnceLock::new();
        static ORDER: OnceLock<String> = OnceLock::new();
        match self {
            Self::SchemaOnly => SCHEMA_ONLY.get_or_init(|| {
                source_digest(&[("src/schema_only.rs", include_str!("schema_only.rs"))])
            }),
            Self::Order => ORDER.get_or_init(|| {
                source_digest(&[
                    ("Cargo.lock", include_str!("../Cargo.lock")),
                    ("src/engine.rs", include_str!("engine.rs")),
                    ("src/json.rs", include_str!("json.rs")),
                    ("src/order.rs", include_str!("order.rs")),
                ])
            }),
        }
    }
}

struct AdmittedContract {
    identity: Contract,
    module: Module,
}

fn parse_policy<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Code> {
    json::parse(bytes).map_err(|_| Code::BundleInvalid)?;
    serde_json::from_slice(bytes).map_err(|_| Code::BundleInvalid)
}

fn check_size(bytes: &[u8], limit: usize, refusal: Code) -> Result<(), Code> {
    if bytes.len() > limit {
        Err(refusal)
    } else {
        Ok(())
    }
}

impl Policy {
    /// Admits immutable policy bytes. The adapter supplies only listed resource names.
    pub fn admit(
        manifest: &[u8],
        allowlist: &[u8],
        mut load_resource: impl FnMut(&str, usize) -> Result<Vec<u8>, Code>,
    ) -> Result<Self, Code> {
        check_size(allowlist, ALLOWLIST_LIMIT, Code::BundleInvalid)?;
        let allow: Allowlist = parse_policy(allowlist)?;
        let mut allowed = BTreeSet::new();
        if !(1..=1000).contains(&allow.allowed_manifest_sha256.len())
            || !allow
                .allowed_manifest_sha256
                .iter()
                .all(|h| hash_text(h) && allowed.insert(h))
        {
            return Err(Code::BundleInvalid);
        }
        check_size(manifest, POLICY_LIMIT, Code::LimitBundle)?;
        let digest = sha256(manifest);
        if !allowed.contains(&digest) {
            return Err(Code::BundleNotAllowed);
        }
        let bundle: Bundle = parse_policy(manifest)?;
        if bundle.bundle_format != "sesv-bundle/1"
            || bundle.bundle_id.is_empty()
            || !version_text(&bundle.bundle_version)
            || bundle.rule_abi != DIALECT_ABI
            || bundle.resources.is_empty()
            || bundle.contracts.is_empty()
        {
            return Err(Code::BundleInvalid);
        }
        if bundle.resources.len() > 100 {
            return Err(Code::LimitBundle);
        }
        let mut names = BTreeSet::new();
        let mut urns = BTreeSet::new();
        for resource in &bundle.resources {
            if !portable_name(&resource.file)
                || !names.insert(resource.file.to_ascii_lowercase())
                || !is_urn(&resource.schema_id)
                || !urns.insert(&resource.schema_id)
                || !hash_text(&resource.sha256)
            {
                return Err(Code::BundleInvalid);
            }
        }
        let mut contracts = BTreeMap::new();
        let mut events = BTreeMap::new();
        for registration in bundle.contracts {
            let route = (
                registration.event_type.clone(),
                registration.schema_version.clone(),
            );
            let contract = Contract {
                event_type: registration.event_type,
                schema_version: registration.schema_version,
                schema_id: registration.root_schema_id,
                module_id: registration.module_id,
                module_version: registration.module_version,
                module_sha256: registration.module_sha256,
            };
            if !contract.verify_fields()
                || !urns.contains(&contract.schema_id)
                || !string_limit(&registration.dataschema)
                || !is_urn(&registration.dataschema)
                || contracts.insert(route.clone(), contract).is_some()
                || events.insert(registration.dataschema, route).is_some()
            {
                return Err(Code::BundleInvalid);
            }
        }
        let contracts = contracts
            .into_iter()
            .map(|(route, identity)| {
                let module = Module::for_contract(&identity)?;
                Ok((route, AdmittedContract { identity, module }))
            })
            .collect::<Result<_, Code>>()?;
        let mut remaining = POLICY_LIMIT - manifest.len();
        let mut resources = BTreeMap::new();
        for resource in bundle.resources {
            let bytes = load_resource(&resource.file, remaining)?;
            remaining = remaining
                .checked_sub(bytes.len())
                .ok_or(Code::LimitBundle)?;
            if sha256(&bytes) != resource.sha256 {
                return Err(Code::BundleIntegrity);
            }
            resources.insert(
                resource.schema_id,
                json::parse(&bytes).map_err(|_| Code::SchemaUnsupported)?,
            );
        }
        Ok(Self {
            id: bundle.bundle_id,
            version: bundle.bundle_version,
            digest,
            contracts,
            events,
            graph: Graph::compile(resources)?,
        })
    }

    /// Visits declared-format record results in scan order. Valid payloads are
    /// available through the visitor as one NDJSON line with exact number tokens.
    pub fn validate(
        &self,
        input: &[u8],
        format: Format,
        mut visit: impl FnMut(Record, Option<&[u8]>) -> Result<(), Code>,
    ) -> Result<Counts, Code> {
        if input.is_empty() {
            return Err(Code::EmptyInput);
        }
        check_size(input, INPUT_LIMIT, Code::LimitInput)?;
        let mut counts = Counts::default();
        let mut offset = 0;
        let frames: Box<dyn Iterator<Item = &[u8]>> = match format {
            Format::Ndjson => Box::new(input.split_inclusive(|b| *b == b'\n')),
            _ => Box::new(std::iter::once(input)),
        };
        for raw in frames {
            if counts.records >= COUNT_LIMIT {
                return Err(Code::LimitCount);
            }
            counts.records += 1;
            let record = if format == Format::Ndjson {
                raw.strip_suffix(b"\r\n")
                    .or_else(|| raw.strip_suffix(b"\n"))
                    .unwrap_or(raw)
            } else {
                raw
            };
            if record.len() > RECORD_LIMIT {
                return Err(Code::LimitRecord);
            }
            let mut output = Record::new(counts.records, format, offset, record.len());
            let token = if format == Format::Ndjson && record.iter().all(|b| b" \t\r\n".contains(b))
            {
                output.errors.push(parse_error(
                    Code::EmptyRecord,
                    0,
                    record,
                    offset,
                    output.source_line,
                ));
                None
            } else {
                match json::parse(record) {
                    Ok(token) => Some(token),
                    Err(error) if error.code == Code::LimitDepth => return Err(Code::LimitDepth),
                    Err(error) => {
                        output.errors.push(parse_error(
                            error.code,
                            error.offset,
                            record,
                            offset,
                            output.source_line,
                        ));
                        None
                    }
                }
            };
            if let Some(token) = token {
                self.evaluate(&token, format, &mut output);
                if output.errors.is_empty() {
                    counts.valid += 1;
                    output.status = Status::Valid;
                    output.valid_output_index = Some(counts.valid);
                    let mut valid = Vec::new();
                    token.encode(&mut valid);
                    valid.push(b'\n');
                    visit(output, Some(&valid))?;
                    offset += raw.len();
                    continue;
                }
            }
            visit(output, None)?;
            offset += raw.len();
        }
        Ok(counts)
    }

    fn evaluate(&self, token: &Value, format: Format, output: &mut Record) {
        if let Some(object) = token.object() {
            output.errors = envelope_errors(object, format);
            if output.errors.is_empty() {
                self.evaluate_routed(object, format, output);
            }
        } else {
            output.errors.push(Diagnostic::at(
                Stage::Envelope,
                Code::TopLevelType,
                Some(String::new()),
            ));
        }
    }

    fn evaluate_routed(&self, object: &Object, format: Format, output: &mut Record) {
        let event_type = object["type"].string().unwrap();
        let contract = if format == Format::CloudEvents {
            let dataschema = object["dataschema"].string().unwrap();
            let Some(key) = self.events.get(dataschema) else {
                output.errors.push(Diagnostic::at(
                    Stage::Routing,
                    Code::UnknownContract,
                    Some("/dataschema".into()),
                ));
                return;
            };
            if key.0 != event_type {
                output.errors.push(Diagnostic::at(
                    Stage::Envelope,
                    Code::EnvelopeInvalid,
                    Some("/type".into()),
                ));
                return;
            }
            self.contracts.get(key)
        } else {
            self.contracts.get(&(
                event_type.into(),
                object["schema_version"].string().unwrap().into(),
            ))
        };
        let Some(AdmittedContract {
            identity: contract,
            module,
        }) = contract
        else {
            output.errors.push(Diagnostic::at(
                Stage::Routing,
                Code::UnknownContract,
                Some("/schema_version".into()),
            ));
            return;
        };
        output.event_type = Some(contract.event_type.clone());
        output.schema_id = Some(contract.schema_id.clone());
        output.schema_version = Some(contract.schema_version.clone());
        output.module_id = Some(contract.module_id.clone());
        output.module_version = Some(contract.module_version.clone());
        let mut seen = HashSet::new();
        self.graph
            .evaluate(&contract.schema_id, &object["data"], &mut |diagnostic| {
                output.collect(diagnostic, &mut seen)
            });
        if output.errors.is_empty() {
            output.business_rules_evaluated = true;
            match module {
                Module::Order => crate::order::evaluate(object, &mut |rule, path| {
                    let mut diagnostic =
                        Diagnostic::at(Stage::Rule, Code::RuleViolation, Some(path));
                    diagnostic.rule_id = Some(rule.into());
                    diagnostic.schema_id = Some(contract.schema_id.clone());
                    output.collect(diagnostic, &mut seen)
                }),
                Module::SchemaOnly => crate::schema_only::evaluate(),
            }
        }
    }

    pub(crate) fn contract(&self, row: &Record) -> Option<&Contract> {
        self.contracts
            .get(&(row.event_type.clone()?, row.schema_version.clone()?))
            .map(|contract| &contract.identity)
    }
}

pub(crate) fn envelope_errors(object: &Object, format: Format) -> Vec<Diagnostic> {
    let fields = envelope_fields(format);
    let mut errors = Vec::new();
    for name in fields {
        let cell = object.get(*name);
        let valid = match *name {
            "data" => cell.and_then(Value::object).is_some(),
            "specversion" => cell.and_then(Value::string) == Some("1.0"),
            "datacontenttype" => cell.and_then(Value::string) == Some("application/json"),
            "time" => cell.is_none() || cell.and_then(Value::string).is_some_and(utc_timestamp),
            "source" if format == Format::CloudEvents => cell
                .and_then(Value::string)
                .is_some_and(|s| string_limit(s) && uri_reference(s)),
            _ => cell.and_then(Value::string).is_some_and(string_limit),
        };
        if !valid {
            errors.push(Diagnostic::at(
                Stage::Envelope,
                Code::EnvelopeInvalid,
                Some(pointer("", name)),
            ));
        }
    }
    if object.keys().any(|key| !fields.contains(&key.as_str())) {
        errors.push(Diagnostic::at(
            Stage::Envelope,
            Code::UnknownField,
            Some(String::new()),
        ));
    }
    errors
}

pub(crate) fn envelope_fields(format: Format) -> &'static [&'static str] {
    if format == Format::CloudEvents {
        &[
            "data",
            "datacontenttype",
            "dataschema",
            "id",
            "source",
            "specversion",
            "time",
            "type",
        ]
    } else {
        &["data", "id", "schema_version", "source", "type"]
    }
}

/// SHA-256 of the registered portable rule source package.
pub fn module_digest(id: &str) -> Option<String> {
    Module::select(id).map(|module| module.digest().into())
}

/// SHA-256 of the canonical shared Rust core source package.
pub fn core_digest() -> String {
    source_digest(&[
        ("Cargo.lock", include_str!("../Cargo.lock")),
        ("Cargo.toml", include_str!("../Cargo.toml")),
        ("src/contract.rs", include_str!("contract.rs")),
        ("src/engine.rs", include_str!("engine.rs")),
        ("src/json.rs", include_str!("json.rs")),
        ("src/order.rs", include_str!("order.rs")),
        ("src/schema.rs", include_str!("schema.rs")),
        ("src/schema_only.rs", include_str!("schema_only.rs")),
    ])
}

fn source_digest(files: &[(&str, &str)]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"sesv-source-package/1\n");
    for (name, text) in files {
        let text = text.replace("\r\n", "\n");
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name);
        hash.update((text.len() as u64).to_be_bytes());
        hash.update(text);
    }
    format!("{:x}", hash.finalize())
}

fn parse_error(
    code: Code,
    at: usize,
    bytes: &[u8],
    start: usize,
    line: Option<usize>,
) -> Diagnostic {
    let prefix = &bytes[..at];
    let last = prefix.iter().rposition(|b| *b == b'\n');
    let mut diagnostic = Diagnostic::at(Stage::Parse, code, None);
    diagnostic.location = Location {
        byte_offset: Some(start + at),
        line: Some(line.unwrap_or_else(|| prefix.iter().filter(|b| **b == b'\n').count() + 1)),
        byte_column: Some(last.map_or(at + 1, |offset| at - offset)),
    };
    diagnostic
}

pub(crate) fn utc_timestamp(value: &str) -> bool {
    let s = value.as_bytes();
    if s.len() < 20
        || s.last() != Some(&b'Z')
        || ![4, 7, 10, 13, 16]
            .into_iter()
            .zip(b"--T::")
            .all(|(i, c)| s.get(i) == Some(c))
    {
        return false;
    }
    let read = |slice: &[u8]| {
        if slice.iter().all(u8::is_ascii_digit) {
            // These timestamp fields are at most four ASCII digits. Decode
            // the checked bytes directly rather than revalidating UTF-8.
            Some(
                slice
                    .iter()
                    .fold(0_u32, |value, byte| value * 10 + u32::from(byte - b'0')),
            )
        } else {
            None
        }
    };
    let Some((((((year, month), day), hour), minute), second)) = read(&s[..4])
        .zip(read(&s[5..7]))
        .zip(read(&s[8..10]))
        .zip(read(&s[11..13]))
        .zip(read(&s[14..16]))
        .zip(read(&s[17..19]))
    else {
        return false;
    };
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => 28 + u32::from(year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)),
        _ => return false,
    };
    let fraction = &s[19..s.len() - 1];
    year != 0
        && (1..=month_days).contains(&day)
        && hour <= 23
        && minute <= 59
        && second <= 59
        && (fraction.is_empty()
            || ((2..=10).contains(&fraction.len())
                && fraction[0] == b'.'
                && fraction[1..].iter().all(u8::is_ascii_digit)))
}

// RFC 3986 Appendix A. Parse components without resolving or fetching the URI.
fn uri_reference(reference: &str) -> bool {
    let (hier_query, fragment) = reference.split_once('#').unwrap_or((reference, ""));
    let (hier, query) = hier_query.split_once('?').unwrap_or((hier_query, ""));
    if !uri_chars(query, b":@/?") || !uri_chars(fragment, b":@/?") {
        return false;
    }
    let first_segment = hier.split('/').next().unwrap_or("");
    let path = if let Some((scheme, _)) = first_segment.split_once(':') {
        if !scheme
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
            || !scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
        {
            return false;
        }
        &hier[scheme.len() + 1..]
    } else {
        hier
    };
    if let Some(rest) = path.strip_prefix("//") {
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        uri_authority(authority) && uri_chars(path, b":@/")
    } else {
        uri_chars(path, b":@/")
    }
}

fn uri_authority(authority: &str) -> bool {
    let (userinfo, host_port) = authority.split_once('@').unwrap_or(("", authority));
    if !uri_chars(userinfo, b":") {
        return false;
    }
    if let Some(literal) = host_port.strip_prefix('[') {
        let Some((ip, rest)) = literal.split_once(']') else {
            return false;
        };
        let port_ok = rest.is_empty()
            || rest
                .strip_prefix(':')
                .is_some_and(|port| port.bytes().all(|b| b.is_ascii_digit()));
        let future = ip
            .strip_prefix(['v', 'V'])
            .and_then(|value| value.split_once('.'))
            .is_some_and(|(version, address)| {
                !version.is_empty()
                    && version.bytes().all(|b| b.is_ascii_hexdigit())
                    && !address.is_empty()
                    && !address.contains('%')
                    && uri_chars(address, b":")
            });
        port_ok && (ip.parse::<std::net::Ipv6Addr>().is_ok() || future)
    } else {
        let (host, port) = host_port.split_once(':').unwrap_or((host_port, ""));
        uri_chars(host, b"") && port.bytes().all(|b| b.is_ascii_digit())
    }
}

fn uri_chars(value: &str, extra: &[u8]) -> bool {
    let mut bytes = value.bytes();
    while let Some(c) = bytes.next() {
        if c == b'%' {
            if !bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
                || !bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
            {
                return false;
            }
        } else if !c.is_ascii_alphanumeric()
            && !b"-._~!$&'()*+,;=".contains(&c)
            && !extra.contains(&c)
        {
            return false;
        }
    }
    true
}

#[derive(Default, Clone, Copy, Deserialize, Serialize)]
pub struct Counts {
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub records: usize,
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub valid: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Valid,
    Invalid,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub result_version: String,
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub record_index: usize,
    #[serde(deserialize_with = "present_option")]
    pub source_line: Option<usize>,
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub record_byte_start: usize,
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub record_byte_length: usize,
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub status: Status,
    #[serde(deserialize_with = "present_option")]
    pub event_type: Option<String>,
    #[serde(deserialize_with = "present_option")]
    pub schema_id: Option<String>,
    #[serde(deserialize_with = "present_option")]
    pub schema_version: Option<String>,
    #[serde(deserialize_with = "present_option")]
    pub module_id: Option<String>,
    #[serde(deserialize_with = "present_option")]
    pub module_version: Option<String>,
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub business_rules_evaluated: bool,
    #[serde(deserialize_with = "present_option")]
    pub valid_output_index: Option<usize>,
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub errors: Vec<Diagnostic>,
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub errors_truncated: bool,
}

impl Record {
    fn collect(
        &mut self,
        diagnostic: Diagnostic,
        seen: &mut HashSet<DiagnosticKey<String>>,
    ) -> bool {
        if !seen.insert(diagnostic.identity().owned()) {
            return true;
        }
        if self.errors.len() == ERROR_LIMIT {
            self.errors_truncated = true;
            return false;
        }
        self.errors.push(diagnostic);
        true
    }

    fn new(index: usize, format: Format, offset: usize, length: usize) -> Self {
        Self {
            result_version: RESULT_VERSION.into(),
            record_index: index,
            source_line: (format == Format::Ndjson).then_some(index),
            record_byte_start: offset,
            record_byte_length: length,
            status: Status::Invalid,
            event_type: None,
            schema_id: None,
            schema_version: None,
            module_id: None,
            module_version: None,
            business_rules_evaluated: false,
            valid_output_index: None,
            errors: Vec::new(),
            errors_truncated: false,
        }
    }
}
