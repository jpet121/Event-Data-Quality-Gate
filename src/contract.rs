use serde::{Deserialize, Serialize};

pub(crate) fn present_option<'de, D, T>(input: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(input)
}

/// Decode a present required field normally. Serde derives an immediate
/// missing-field error for a field with an explicit decoder. The fields
/// using this decoder have types that cannot default when absent.
pub(crate) fn required_field<'de, D, T>(input: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(input)
}

pub const RESULT_VERSION: &str = "1.0.0";
pub const INPUT_LIMIT: usize = 104_857_600;
pub const RECORD_LIMIT: usize = 1_048_576;
pub const COUNT_LIMIT: usize = 100_000;
pub const DEPTH_LIMIT: usize = 64;
pub const ERROR_LIMIT: usize = 100;
pub const OUTPUT_LIMIT: u64 = 1_073_741_824;
pub const RUN_LIMIT_MS: u64 = 120_000;
pub const MEMORY_LIMIT: u64 = 1_073_741_824;

macro_rules! catalog {
    ($($variant:ident => $name:literal, $message:literal;)+) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
        pub enum Code { $(#[serde(rename = $name)] $variant,)+ }

        impl Code {
            pub const fn message(self) -> &'static str {
                match self { $(Self::$variant => $message,)+ }
            }
        }
    };
}

catalog! {
    InvalidUtf8 => "INVALID_UTF8", "Input is not valid UTF-8.";
    InvalidJson => "INVALID_JSON", "Input is not valid JSON.";
    DuplicateKey => "DUPLICATE_KEY", "An object contains a repeated field name.";
    EmptyRecord => "EMPTY_RECORD", "The record is empty.";
    TopLevelType => "TOP_LEVEL_TYPE", "The event must be an object.";
    EnvelopeInvalid => "ENVELOPE_INVALID", "The event envelope violates the selected profile.";
    UnknownContract => "UNKNOWN_CONTRACT", "The selected bundle has no matching contract.";
    TypeMismatch => "TYPE_MISMATCH", "The value has an invalid type.";
    RequiredField => "REQUIRED_FIELD", "A required field is missing.";
    UnknownField => "UNKNOWN_FIELD", "The object contains an undeclared field.";
    SchemaViolation => "SCHEMA_VIOLATION", "The value violates a schema constraint.";
    RuleViolation => "RULE_VIOLATION", "The record violates a business rule.";
    ArgumentInvalid => "ARGUMENT_INVALID", "The command arguments are invalid.";
    UnsupportedFormat => "UNSUPPORTED_FORMAT", "The selected format is not supported.";
    EmptyInput => "EMPTY_INPUT", "The input file is empty.";
    InputChanged => "INPUT_CHANGED", "The source changed during acquisition.";
    BundleNotAllowed => "BUNDLE_NOT_ALLOWED", "The bundle digest is not locally allowed.";
    BundleIntegrity => "BUNDLE_INTEGRITY", "The bundle bytes do not match the manifest.";
    BundleInvalid => "BUNDLE_INVALID", "The bundle contract is invalid.";
    SchemaUnsupported => "SCHEMA_UNSUPPORTED", "The schema uses an unsupported feature.";
    ReferenceInvalid => "REFERENCE_INVALID", "A schema reference is invalid or outside the bundle.";
    ModuleUnavailable => "MODULE_UNAVAILABLE", "The exact rule module is unavailable.";
    LimitBundle => "LIMIT_BUNDLE", "The bundle exceeds a configured limit.";
    LimitInput => "LIMIT_INPUT", "The input exceeds the byte limit.";
    LimitRecord => "LIMIT_RECORD", "A record exceeds the byte limit.";
    LimitCount => "LIMIT_COUNT", "The input exceeds the record limit.";
    LimitDepth => "LIMIT_DEPTH", "The input exceeds the nesting limit.";
    LimitOutput => "LIMIT_OUTPUT", "The output exceeds the byte limit.";
    LimitMemory => "LIMIT_MEMORY", "The worker exceeded its memory budget.";
    LimitTime => "LIMIT_TIME", "The run exceeded its time budget.";
    OutputCollision => "OUTPUT_COLLISION", "The output destination already exists.";
    PathRejected => "PATH_REJECTED", "A path violates the local file boundary.";
    IoFailure => "IO_FAILURE", "A required local file operation failed.";
    ArtifactInvalid => "ARTIFACT_INVALID", "The artifact is incomplete or inconsistent.";
    InternalFailure => "INTERNAL_FAILURE", "An internal operation failed.";
    Canceled => "CANCELED", "The run was canceled.";
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Format {
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "ndjson")]
    Ndjson,
    #[serde(rename = "cloudevents-json")]
    CloudEvents,
}

impl Format {
    pub fn select(value: &str) -> Result<Self, Code> {
        match value {
            "json" => Ok(Self::Json),
            "ndjson" => Ok(Self::Ndjson),
            "cloudevents-json" => Ok(Self::CloudEvents),
            _ => Err(Code::UnsupportedFormat),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Validate,
    Verify,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    Parse,
    Envelope,
    Routing,
    Schema,
    Rule,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    #[serde(deserialize_with = "present_option")]
    pub byte_offset: Option<usize>,
    #[serde(deserialize_with = "present_option")]
    pub line: Option<usize>,
    #[serde(deserialize_with = "present_option")]
    pub byte_column: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub stage: Stage,
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub code: Code,
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub message: String,
    #[serde(deserialize_with = "present_option")]
    pub instance_path: Option<String>,
    #[serde(deserialize_with = "present_option")]
    pub schema_id: Option<String>,
    #[serde(deserialize_with = "present_option")]
    pub schema_path: Option<String>,
    #[serde(deserialize_with = "present_option")]
    pub rule_id: Option<String>,
    #[serde(deserialize_with = "crate::contract::required_field")]
    pub location: Location,
}

#[derive(Eq, Hash, PartialEq)]
pub(crate) struct DiagnosticKey<T> {
    stage: Stage,
    code: Code,
    instance_path: Option<T>,
    schema_id: Option<T>,
    schema_path: Option<T>,
    rule_id: Option<T>,
}

impl DiagnosticKey<&str> {
    pub(crate) fn owned(self) -> DiagnosticKey<String> {
        DiagnosticKey {
            stage: self.stage,
            code: self.code,
            instance_path: self.instance_path.map(str::to_owned),
            schema_id: self.schema_id.map(str::to_owned),
            schema_path: self.schema_path.map(str::to_owned),
            rule_id: self.rule_id.map(str::to_owned),
        }
    }
}

impl Diagnostic {
    pub(crate) fn identity(&self) -> DiagnosticKey<&str> {
        DiagnosticKey {
            stage: self.stage,
            code: self.code,
            instance_path: self.instance_path.as_deref(),
            schema_id: self.schema_id.as_deref(),
            schema_path: self.schema_path.as_deref(),
            rule_id: self.rule_id.as_deref(),
        }
    }

    pub(crate) fn at(stage: Stage, code: Code, path: Option<String>) -> Self {
        Self {
            stage,
            code,
            message: code.message().into(),
            instance_path: path,
            schema_id: None,
            schema_path: None,
            rule_id: None,
            location: Location::default(),
        }
    }
}

#[derive(Serialize)]
pub struct Outcome {
    result_version: &'static str,
    operation: Operation,
    status: &'static str,
    pub exit_code: u8,
    pub run_id: Option<String>,
    output_directory: Option<String>,
    code: Option<Code>,
    message: &'static str,
    record_count: Option<usize>,
    valid_count: Option<usize>,
    invalid_count: Option<usize>,
}

impl Outcome {
    pub fn failed(operation: Operation, directory: Option<String>, code: Code) -> Self {
        Self {
            result_version: RESULT_VERSION,
            operation,
            status: if code == Code::Canceled {
                "canceled"
            } else {
                "failed"
            },
            exit_code: match code {
                Code::ArgumentInvalid | Code::UnsupportedFormat => 4,
                Code::Canceled => 130,
                _ => 3,
            },
            run_id: None,
            output_directory: directory,
            code: Some(code),
            message: code.message(),
            record_count: None,
            valid_count: None,
            invalid_count: None,
        }
    }

    pub fn completed(
        operation: Operation,
        directory: String,
        id: String,
        records: usize,
        valid: usize,
    ) -> Self {
        let invalid = records - valid;
        Self {
            result_version: RESULT_VERSION,
            operation,
            status: "completed",
            exit_code: if operation == Operation::Validate && invalid > 0 {
                2
            } else {
                0
            },
            run_id: Some(id),
            output_directory: Some(directory),
            code: None,
            message: "Operation completed.",
            record_count: Some(records),
            valid_count: Some(valid),
            invalid_count: Some(invalid),
        }
    }
}
