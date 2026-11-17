use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sesv-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn configure(&self) {
        let schema = json!({
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "$id":"urn:example:telemetry:pulse",
            "type":"object",
            "properties":{"device_id":{"type":"string","minLength":1,"maxLength":64},
                          "state":{"type":"string","enum":["up","down"]}},
            "required":["device_id","state"], "additionalProperties":false
        });
        let bytes = serde_json::to_vec(&schema).unwrap();
        fs::write(self.0.join("pulse.json"), &bytes).unwrap();
        let manifest = json!({
            "bundle_format":"sesv-bundle/1","bundle_id":"pilot","bundle_version":"1.0.0",
            "rule_abi":"sesv-rule-abi/1",
            "resources":[{"schema_id":"urn:example:telemetry:pulse","file":"pulse.json","sha256":hash(&bytes)}],
            "contracts":[{"event_type":"telemetry.pulse","schema_version":"1.0.0",
               "dataschema":"urn:example:telemetry.pulse:1.0.0","root_schema_id":"urn:example:telemetry:pulse",
               "module_id":"builtin.schema-only","module_version":"1.0.0",
               "module_sha256":sesv::engine::module_digest("builtin.schema-only").unwrap()}]
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(self.0.join("bundle.json"), &bytes).unwrap();
        fs::write(
            self.0.join("allow.json"),
            json!({"allowed_manifest_sha256":[hash(&bytes)]}).to_string(),
        )
        .unwrap();
    }

    fn save_manifest(&self, manifest: &Value) {
        let bytes = serde_json::to_vec(manifest).unwrap();
        fs::write(self.0.join("bundle.json"), &bytes).unwrap();
        fs::write(
            self.0.join("allow.json"),
            json!({"allowed_manifest_sha256":[hash(&bytes)]}).to_string(),
        )
        .unwrap();
    }

    fn command(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sesv"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .unwrap()
    }

    fn validate(&self, format: &str) -> Output {
        self.command(&[
            "validate",
            "--input",
            "events.json",
            "--format",
            format,
            "--bundle",
            "bundle.json",
            "--allowlist",
            "allow.json",
            "--out",
            "run",
        ])
    }

    fn remove_run(&self) {
        let run = self.0.join("run");
        if run.is_dir() {
            fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
            fs::remove_dir_all(run).unwrap();
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.remove_run();
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn outcome(output: Output, code: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn read_json(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn in_memory_policy_keeps_limits_without_the_native_adapter() {
    use sesv::contract::{Code, Format, INPUT_LIMIT};
    use sesv::engine::{ALLOWLIST_LIMIT, Policy, module_digest};

    let fixture = Fixture::new();
    fixture.configure();
    let bundle = fs::read(fixture.0.join("bundle.json")).unwrap();
    let allow = fs::read(fixture.0.join("allow.json")).unwrap();
    let no_resources = |_: &str, _: usize| panic!("oversized policy opened a resource");
    let mut padded_allow = allow.clone();
    padded_allow.resize(ALLOWLIST_LIMIT + 1, b' ');
    assert!(matches!(
        Policy::admit(&bundle, &padded_allow, no_resources),
        Err(Code::BundleInvalid)
    ));
    let mut padded_bundle = bundle.clone();
    padded_bundle.resize(5 * 1024 * 1024 + 1, b' ');
    assert!(matches!(
        Policy::admit(&padded_bundle, &allow, no_resources),
        Err(Code::LimitBundle)
    ));
    let policy = Policy::admit(&bundle, &allow, |name, _| {
        fs::read(fixture.0.join(name)).map_err(|_| Code::IoFailure)
    })
    .unwrap();
    assert!(matches!(
        policy.validate(&vec![b' '; INPUT_LIMIT + 1], Format::Ndjson, |_, _| {
            panic!("oversized input emitted a row")
        }),
        Err(Code::LimitInput)
    ));
    assert!(module_digest("builtin.not-installed").is_none());
}

const PULSE: &str = r#"{"id":"one","source":"site","type":"telemetry.pulse","schema_version":"1.0.0","data":{"device_id":"abc","state":"up"}}"#;

#[test]
fn validates_and_independently_verifies_a_local_schema_only_run() {
    let fixture = Fixture::new();
    fixture.configure();
    fs::write(fixture.0.join("events.json"), PULSE).unwrap();
    let result = outcome(fixture.validate("json"), 0);
    assert_eq!(result["record_count"], 1);
    assert_eq!(result["valid_count"], 1);
    let run = fixture.0.join("run");
    let row = read_json(run.join("results.ndjson"));
    assert_eq!(row["record_byte_start"], 0);
    assert_eq!(row["record_byte_length"], PULSE.len());
    assert_eq!(row["event_type"], "telemetry.pulse");
    assert_eq!(row["business_rules_evaluated"], true);
    assert_eq!(row["valid_output_index"], 1);
    assert_eq!(
        read_json(run.join("valid.ndjson")),
        serde_json::from_str::<Value>(PULSE).unwrap()
    );
    let manifest = read_json(run.join("manifest.json"));
    assert_eq!(manifest["input_sha256"], hash(PULSE.as_bytes()));
    assert_eq!(manifest["delivery_authorized"], false);
    assert_eq!(manifest["contracts"].as_array().unwrap().len(), 1);
    for file in ["events.json", "bundle.json", "allow.json", "pulse.json"] {
        fs::remove_file(fixture.0.join(file)).unwrap();
    }
    assert_eq!(
        outcome(fixture.command(&["verify", "--run", "run"]), 0)["run_id"],
        result["run_id"]
    );
}

#[test]
fn mixed_ndjson_preserves_line_spans_and_redacts_undeclared_fields() {
    let fixture = Fixture::new();
    fixture.configure();
    let invalid = PULSE.replace(r#""state":"up""#, r#""unknown-private-key":"redact-me""#);
    let source = format!("{PULSE}\r\n{invalid}\n\n");
    fs::write(fixture.0.join("events.json"), &source).unwrap();
    assert_eq!(outcome(fixture.validate("ndjson"), 2)["invalid_count"], 2);
    let published = fs::read_to_string(fixture.0.join("run/results.ndjson")).unwrap();
    assert!(!published.contains("unknown-private-key") && !published.contains("redact-me"));
    let rows: Vec<Value> = published
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows[0]["record_byte_length"], PULSE.len());
    assert_eq!(rows[1]["record_byte_start"], PULSE.len() + 2);
    assert_eq!(rows[1]["source_line"], 2);
    assert_eq!(rows[1]["errors"][1]["code"], "UNKNOWN_FIELD");
    assert_eq!(rows[1]["errors"][1]["instance_path"], "/data");
    assert_eq!(rows[2]["errors"][0]["code"], "EMPTY_RECORD");
    assert_eq!(
        outcome(fixture.command(&["verify", "--run", "run"]), 0)["record_count"],
        3
    );
}

#[test]
fn stops_a_suspended_worker_when_the_operator_cancels() {
    let fixture = Fixture::new();
    fixture.configure();
    let mut events = fs::File::create(fixture.0.join("events.json")).unwrap();
    for _ in 0..80_000 {
        use std::io::Write;
        writeln!(events, "{PULSE}").unwrap();
    }
    drop(events);
    let mut child = Command::new(env!("CARGO_BIN_EXE_sesv"))
        .current_dir(&fixture.0)
        .args([
            "validate",
            "--input",
            "events.json",
            "--format",
            "ndjson",
            "--bundle",
            "bundle.json",
            "--allowlist",
            "allow.json",
            "--out",
            "run",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let supervisor = child.id() as i32;
    let children = format!("/proc/{supervisor}/task/{supervisor}/children");
    let start = std::time::Instant::now();
    let worker: i32 = loop {
        if let Some(pid) = fs::read_to_string(&children)
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse().ok())
        {
            break pid;
        }
        if child.try_wait().unwrap().is_some()
            || start.elapsed() > std::time::Duration::from_secs(2)
        {
            let _ = child.kill();
            child.wait().unwrap();
            panic!("validate did not start an independent worker");
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    };
    assert_eq!(unsafe { libc::kill(worker, libc::SIGSTOP) }, 0);
    let canceled = std::time::Instant::now();
    assert_eq!(unsafe { libc::kill(supervisor, libc::SIGINT) }, 0);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if canceled.elapsed() >= std::time::Duration::from_secs(2) {
            unsafe { libc::kill(worker, libc::SIGKILL) };
            let _ = child.kill();
            child.wait().unwrap();
            panic!("supervisor did not cancel within two seconds");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let result = outcome(child.wait_with_output().unwrap(), 130);
    assert_eq!(result["code"], "CANCELED");
    assert!(!fixture.0.join("run/COMPLETE.json").exists());
}

const ORDER: &str = r#"{"id":"ord-1","source":"alderquay.order-adapter","type":"order.created","schema_version":"1.0.0","data":{"order_id":"1","occurred_at":"2024-02-29T00:00:00.123Z","currency":"USD","items":[{"line_id":"line-1","sku":"sku","quantity":2,"unit_price_minor":150}],"total_minor":300}}"#;

#[test]
fn routes_exact_order_versions_and_separates_integer_math_from_token_rules() {
    let fixture = Fixture::new();
    fixture.configure();
    let mut manifest = read_json(fixture.0.join("bundle.json"));
    for version in ["1.0.0", "1.1.0"] {
        let id = format!("urn:alderquay:order.created:{version}");
        let mut schema: Value =
            serde_json::from_str(include_str!("../examples/order.schema.json")).unwrap();
        schema["$id"] = json!(id);
        if version == "1.1.0" {
            schema["properties"]["channel"] = json!({"type":"string","enum":["web","phone"]});
        }
        let bytes = serde_json::to_vec(&schema).unwrap();
        let name = format!("order-{version}.json");
        fs::write(fixture.0.join(&name), &bytes).unwrap();
        manifest["resources"]
            .as_array_mut()
            .unwrap()
            .push(json!({"schema_id":id,"file":name,"sha256":hash(&bytes)}));
        manifest["contracts"].as_array_mut().unwrap().push(json!({
            "event_type":"order.created","schema_version":version,"dataschema":id,"root_schema_id":id,
            "module_id":"example.order","module_version":"1.0.0",
            "module_sha256":sesv::engine::module_digest("example.order").unwrap()
        }));
    }
    fixture.save_manifest(&manifest);
    let changed = ORDER.replace(r#""quantity":2"#, r#""quantity":2.0"#);
    let next = ORDER
        .replace("1.0.0", "1.1.0")
        .replace(r#""currency":"USD""#, r#""currency":"USD","channel":"web""#);
    let missing = ORDER.replace("1.0.0", "1.2.0");
    fs::write(
        fixture.0.join("events.json"),
        format!("{ORDER}\n{changed}\n{next}\n{missing}\n"),
    )
    .unwrap();
    let run = outcome(fixture.validate("ndjson"), 2);
    assert_eq!(run["valid_count"], 2);
    let content = fs::read_to_string(fixture.0.join("run/results.ndjson")).unwrap();
    let rows: Vec<Value> = content
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows[0]["valid_output_index"], 1);
    assert_eq!(rows[1]["errors"][0]["rule_id"], "ORDER-INTEGER-TOKENS");
    assert_eq!(rows[1]["errors"].as_array().unwrap().len(), 1);
    assert_eq!(rows[2]["schema_version"], "1.1.0");
    assert_eq!(rows[3]["errors"][0]["code"], "UNKNOWN_CONTRACT");
    assert_eq!(
        outcome(fixture.command(&["verify", "--run", "run"]), 0)["invalid_count"],
        2
    );
}

#[test]
fn follows_local_schema_nodes_and_compares_decimals_above_binary64() {
    let fixture = Fixture::new();
    fixture.configure();
    let mut manifest = read_json(fixture.0.join("bundle.json"));
    let schema = br##"{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:example:telemetry:pulse","type":"object","additionalProperties":false,"properties":{"device_id":{"$ref":"#/$defs/exact"},"state":{"type":"string"}},"required":["device_id","state"],"$defs":{"exact":{"type":"integer","const":9007199254740993}}}"##;
    fs::write(fixture.0.join("pulse.json"), schema).unwrap();
    manifest["resources"][0]["sha256"] = json!(hash(schema));
    fixture.save_manifest(&manifest);
    let good = PULSE.replace(r#""abc""#, "9007199254740993.0");
    let bad = PULSE.replace(r#""abc""#, "9007199254740992");
    fs::write(fixture.0.join("events.json"), format!("{good}\n{bad}\n")).unwrap();
    assert_eq!(outcome(fixture.validate("ndjson"), 2)["valid_count"], 1);
    assert!(
        fs::read_to_string(fixture.0.join("run/valid.ndjson"))
            .unwrap()
            .contains("9007199254740993.0")
    );
    let content = fs::read_to_string(fixture.0.join("run/results.ndjson")).unwrap();
    let error: Value = serde_json::from_str(content.lines().nth(1).unwrap()).unwrap();
    assert_eq!(error["errors"][0]["schema_path"], "/$defs/exact/const");
}

#[test]
fn checks_policy_layout_before_opening_sources_and_accepts_no_fallback_module() {
    let fixture = Fixture::new();
    fixture.configure();
    let mut manifest = read_json(fixture.0.join("bundle.json"));
    manifest["resources"][0]["file"] = json!("CON.json");
    fixture.save_manifest(&manifest);
    assert_eq!(
        outcome(fixture.validate("json"), 3)["code"],
        "BUNDLE_INVALID"
    );

    fs::remove_dir(fixture.0.join("run")).unwrap();
    manifest["resources"][0]["file"] = json!("pulse.json");
    manifest["contracts"][0]["module_sha256"] = json!("0".repeat(64));
    fixture.save_manifest(&manifest);
    assert_eq!(
        outcome(fixture.validate("json"), 3)["code"],
        "MODULE_UNAVAILABLE"
    );
}

#[test]
fn verifier_rejects_rehashed_records_with_unknown_used_contracts() {
    let fixture = Fixture::new();
    fixture.configure();
    fs::write(
        fixture.0.join("events.json"),
        PULSE.replace("up", "invalid"),
    )
    .unwrap();
    assert_eq!(outcome(fixture.validate("json"), 2)["invalid_count"], 1);
    assert_eq!(
        outcome(fixture.command(&["verify", "--run", "run"]), 0)["valid_count"],
        0
    );
    let dir = fixture.0.join("run");
    let mut row = read_json(dir.join("results.ndjson"));
    row["event_type"] = json!("unknown.pulse");
    let new_result = format!("{row}\n");
    replace_output(&dir, 1, "results.ndjson", &new_result);
    assert_eq!(
        outcome(fixture.command(&["verify", "--run", "run"]), 3)["code"],
        "ARTIFACT_INVALID"
    );
}

#[test]
fn verifier_rejects_rehashed_export_missing_envelope_fields() {
    let fixture = Fixture::new();
    fixture.configure();
    fs::write(fixture.0.join("events.json"), PULSE).unwrap();
    outcome(fixture.validate("json"), 0);
    let dir = fixture.0.join("run");
    let mut envelope = read_json(dir.join("valid.ndjson"));
    envelope.as_object_mut().unwrap().remove("source");
    replace_output(&dir, 0, "valid.ndjson", &format!("{envelope}\n"));
    assert_eq!(
        outcome(fixture.command(&["verify", "--run", "run"]), 3)["code"],
        "ARTIFACT_INVALID"
    );
}

fn replace_output(dir: &Path, index: usize, name: &str, bytes: &str) {
    for file in [name, "manifest.json", "COMPLETE.json"] {
        fs::set_permissions(dir.join(file), fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(dir.join(name), bytes).unwrap();
    let mut manifest = read_json(dir.join("manifest.json"));
    manifest["outputs"][index]["sha256"] = json!(hash(bytes.as_bytes()));
    manifest["outputs"][index]["bytes"] = json!(bytes.len());
    let new_manifest = format!("{manifest}\n");
    fs::write(dir.join("manifest.json"), &new_manifest).unwrap();
    let mut complete = read_json(dir.join("COMPLETE.json"));
    complete["manifest_sha256"] = json!(hash(new_manifest.as_bytes()));
    fs::write(dir.join("COMPLETE.json"), format!("{complete}\n")).unwrap();
}

#[test]
fn cloud_source_requires_a_uri_reference() {
    for (source, valid) in [
        ("../devices/a%20b?by=state#top", true),
        ("https://[::1]:8080/devices", true),
        ("https://[not-an-ip]/devices", false),
        ("relative[bracket]", false),
        ("//host:port/resource", false),
        ("https://u@v@host/path", false),
        ("relative/%z0", false),
    ] {
        let fixture = Fixture::new();
        fixture.configure();
        let event = json!({
            "specversion":"1.0", "id":"p", "source":source,
            "type":"telemetry.pulse", "datacontenttype":"application/json",
            "dataschema":"urn:example:telemetry.pulse:1.0.0",
            "data":{"device_id":"abc","state":"up"}
        });
        fs::write(fixture.0.join("events.json"), event.to_string()).unwrap();
        outcome(
            fixture.validate("cloudevents-json"),
            if valid { 0 } else { 2 },
        );
        if !valid {
            let row = read_json(fixture.0.join("run/results.ndjson"));
            assert_eq!(row["errors"][0]["code"], "ENVELOPE_INVALID");
            assert_eq!(row["errors"][0]["instance_path"], "/source");
        }
    }
}

#[test]
fn malformed_string_escapes_report_offending_bytes() {
    let fixture = Fixture::new();
    fixture.configure();
    for (input, offset, line, column) in [
        (&b"{\"x\":\"\\\n\"}"[..], 7, 1, 8),
        (&br#"{"x":"\u12x4"}"#[..], 10, 1, 11),
        (&b"{\n\"x\":\"abc\\q\"}"[..], 11, 2, 10),
        (&br#"{"x":"\u1"#[..], 9, 1, 10),
    ] {
        fs::write(fixture.0.join("events.json"), input).unwrap();
        outcome(fixture.validate("json"), 2);
        let row = read_json(fixture.0.join("run/results.ndjson"));
        let diagnostic = &row["errors"][0];
        assert_eq!(diagnostic["code"], "INVALID_JSON");
        assert_eq!(
            diagnostic["location"],
            json!({
                "byte_offset":offset, "line":line, "byte_column":column
            })
        );
        fixture.remove_run();
    }
}

#[test]
fn refuses_shared_destinations_and_preserves_existing_runs() {
    let fixture = Fixture::new();
    fixture.configure();
    fs::write(fixture.0.join("events.json"), PULSE).unwrap();
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        outcome(fixture.validate("json"), 3)["code"],
        "PATH_REJECTED"
    );
    assert!(!fixture.0.join("run").exists());
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
    outcome(fixture.validate("json"), 0);
    let marker = fs::read(fixture.0.join("run/COMPLETE.json")).unwrap();
    assert_eq!(
        outcome(fixture.validate("json"), 3)["code"],
        "OUTPUT_COLLISION"
    );
    assert_eq!(
        fs::read(fixture.0.join("run/COMPLETE.json")).unwrap(),
        marker
    );
    outcome(fixture.command(&["verify", "--run", "run"]), 0);
}

#[test]
fn refuses_redirected_sources_schema_files_and_artifacts() {
    let fixture = Fixture::new();
    fixture.configure();
    let source = fixture.0.join("original.json");
    fs::write(&source, PULSE).unwrap();
    symlink(&source, fixture.0.join("events.json")).unwrap();
    assert_eq!(
        outcome(fixture.validate("json"), 3)["code"],
        "PATH_REJECTED"
    );
    fs::remove_file(fixture.0.join("events.json")).unwrap();
    fs::remove_dir(fixture.0.join("run")).unwrap();
    fs::rename(source, fixture.0.join("events.json")).unwrap();
    fs::rename(
        fixture.0.join("pulse.json"),
        fixture.0.join("schema-original.json"),
    )
    .unwrap();
    symlink("schema-original.json", fixture.0.join("pulse.json")).unwrap();
    assert_eq!(
        outcome(fixture.validate("json"), 3)["code"],
        "PATH_REJECTED"
    );
    fs::remove_file(fixture.0.join("pulse.json")).unwrap();
    fs::rename(
        fixture.0.join("schema-original.json"),
        fixture.0.join("pulse.json"),
    )
    .unwrap();
    fs::remove_dir(fixture.0.join("run")).unwrap();
    outcome(fixture.validate("json"), 0);
    symlink("run", fixture.0.join("alias")).unwrap();
    assert_eq!(
        outcome(fixture.command(&["verify", "--run", "alias"]), 3)["code"],
        "PATH_REJECTED"
    );
    let dir = fixture.0.join("run");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(dir.join("valid.ndjson"), fixture.0.join("export")).unwrap();
    symlink("../export", dir.join("valid.ndjson")).unwrap();
    assert_eq!(
        outcome(fixture.command(&["verify", "--run", "run"]), 3)["code"],
        "PATH_REJECTED"
    );
    assert!(
        fs::symlink_metadata(dir.join("valid.ndjson"))
            .unwrap()
            .is_symlink()
    );
}

#[test]
fn rejects_out_of_format_diagnostics_in_a_rehashed_artifact() {
    let fixture = Fixture::new();
    fixture.configure();
    fs::write(fixture.0.join("events.json"), " ").unwrap();
    outcome(fixture.validate("json"), 2);
    let dir = fixture.0.join("run");
    let mut row = read_json(dir.join("results.ndjson"));
    row["errors"][0]["code"] = json!("EMPTY_RECORD");
    row["errors"][0]["message"] = json!("The record is empty.");
    replace_output(&dir, 1, "results.ndjson", &format!("{row}\n"));
    assert_eq!(
        outcome(fixture.command(&["verify", "--run", "run"]), 3)["code"],
        "ARTIFACT_INVALID"
    );
}

#[test]
fn obeys_exact_byte_depth_and_record_count_boundaries() {
    let fixture = Fixture::new();
    fixture.configure();
    for (input, format, exit, code) in [
        (
            format!("{PULSE}{}", " ".repeat(1_048_576 - PULSE.len())),
            "json",
            0,
            Value::Null,
        ),
        (
            format!("{PULSE}{}", " ".repeat(1_048_577 - PULSE.len())),
            "json",
            3,
            json!("LIMIT_RECORD"),
        ),
        (
            format!("{}0{}", "[".repeat(64), "]".repeat(64)),
            "json",
            2,
            Value::Null,
        ),
        (
            format!("{}0{}", "[".repeat(65), "]".repeat(65)),
            "json",
            3,
            json!("LIMIT_DEPTH"),
        ),
        ("\n".repeat(100_000), "ndjson", 2, Value::Null),
        ("\n".repeat(100_001), "ndjson", 3, json!("LIMIT_COUNT")),
    ] {
        fs::write(fixture.0.join("events.json"), input).unwrap();
        let run = outcome(fixture.validate(format), exit);
        assert_eq!(run["code"], code);
        assert_eq!(fixture.0.join("run/COMPLETE.json").exists(), exit != 3);
        fixture.remove_run();
    }
}
