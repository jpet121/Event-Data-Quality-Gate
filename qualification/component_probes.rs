// The same production modules are used by the component tests and the coverage executable.
pub mod contract {
    production_source!("contract.rs");
    wire_source!("wire_contract.rs");
}
mod schema_only {
    production_source!("schema_only.rs");
}

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "sesv-component-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

mod artifact {
    production_source!("artifact.rs");
    wire_source!("wire_artifact.rs");

    #[cfg_attr(test, test)]
    pub(super) fn metered_flush_delivers_each_reserved_byte_to_disk() {
        let scratch = crate::Scratch::new();
        let path = scratch.0.join("output");
        let mut output = OutputWriter::new(File::create(&path).unwrap());
        let mut budget = Budget {
            left: OUTPUT_LIMIT,
            exceeded: false,
        };
        let mut meter = Meter(&mut budget, &mut output);
        meter.write_all(b"one\ntwo\n").unwrap();
        meter.flush().unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"one\ntwo\n");
        assert_eq!(budget.check_readback(8), Ok(()));
        assert_eq!(budget.check_readback(7), Err(Code::ArtifactInvalid));
    }
}

mod engine {
    production_source!("engine.rs");
    wire_source!("wire_engine.rs");

    #[cfg_attr(test, test)]
    pub(super) fn duplicate_diagnostics_do_not_use_a_distinct_slot() {
        let mut row = Record::new(1, Format::Json, 0, 1);
        let mut seen = HashSet::new();
        let first = Diagnostic::at(Stage::Schema, Code::RequiredField, Some("/data/id".into()));
        let next = Diagnostic::at(
            Stage::Schema,
            Code::RequiredField,
            Some("/data/name".into()),
        );
        assert!(row.collect(first.clone(), &mut seen));
        assert!(row.collect(first.clone(), &mut seen));
        assert!(row.collect(next.clone(), &mut seen));
        assert_eq!(row.errors, [first, next]);
        assert!(!row.errors_truncated);
    }

    #[cfg_attr(test, test)]
    pub(super) fn module_registry_selects_only_known_ids() {
        assert!(module_digest("builtin.schema-only").is_some_and(|digest| digest.len() == 64));
        assert_eq!(module_digest("unknown"), None);
    }

    #[cfg_attr(test, test)]
    pub(super) fn policy_names_and_calendar_boundaries_are_portable() {
        for reserved in ["CON.json", "PRN.json", "AUX.json", "NUL.json"] {
            assert!(!portable_name(reserved), "{reserved}");
        }
        assert!(portable_name("null-schema.json"));
        for (index, last) in [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
            .into_iter()
            .enumerate()
        {
            let month = index + 1;
            assert!(utc_timestamp(&format!(
                "2025-{month:02}-{last:02}T00:00:00Z"
            )));
            assert!(!utc_timestamp(&format!(
                "2025-{month:02}-{:02}T00:00:00Z",
                last + 1
            )));
        }
        assert!(utc_timestamp("2024-02-29T00:00:00Z"));
        assert!(!utc_timestamp("2025-13-01T00:00:00Z"));
    }

    #[cfg_attr(test, test)]
    pub(super) fn in_memory_limits_refuse_oversized_inputs_before_callbacks() {
        let schema = br#"{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:example:pulse","type":"object","properties":{},"additionalProperties":false}"#;
        let manifest = serde_json::to_vec(&serde_json::json!({
            "bundle_format": "sesv-bundle/1", "bundle_id": "limits", "bundle_version": "1.0.0", "rule_abi": "sesv-rule-abi/1",
            "resources": [{"schema_id": "urn:example:pulse", "file": "pulse.json", "sha256": sha256(schema)}],
            "contracts": [{"event_type": "pulse", "schema_version": "1.0.0", "dataschema": "urn:example:pulse:1",
                "root_schema_id": "urn:example:pulse", "module_id": "builtin.schema-only", "module_version": "1.0.0",
                "module_sha256": module_digest("builtin.schema-only").unwrap()}],
        })).unwrap();
        let allowlist = serde_json::to_vec(&serde_json::json!({
            "allowed_manifest_sha256": [sha256(&manifest)]
        }))
        .unwrap();
        let forbidden_resource = |_: &str, _: usize| panic!("oversized policy loaded a resource");
        let too_large_allowlist = vec![b' '; 1_048_577];
        assert!(matches!(
            Policy::admit(&manifest, &too_large_allowlist, forbidden_resource),
            Err(Code::BundleInvalid)
        ));
        let too_large_manifest = vec![b' '; 5_242_881];
        assert!(matches!(
            Policy::admit(&too_large_manifest, &allowlist, forbidden_resource),
            Err(Code::LimitBundle)
        ));
        let policy = Policy::admit(&manifest, &allowlist, |name, _| {
            assert_eq!(name, "pulse.json");
            Ok(schema.to_vec())
        })
        .unwrap();
        let data = vec![b' '; 104_857_601];
        assert!(matches!(
            policy.validate(&data, Format::Ndjson, |_, _| {
                panic!("oversized input emitted a record")
            }),
            Err(Code::LimitInput)
        ));
    }
}

mod filesystem {
    production_source!("filesystem.rs");
    wire_source!("wire_filesystem.rs");

    #[cfg_attr(test, test)]
    pub(super) fn private_cleanup_rejects_multiple_components_and_non_names() {
        let scratch = crate::Scratch::new();
        let parent = scratch.0.join("nested");
        std::fs::create_dir(&parent).unwrap();
        let child = parent.join("child");
        std::fs::create_dir(&child).unwrap();
        let outside = parent.join("keep");
        std::fs::write(&outside, b"outside").unwrap();
        let root = Directory::open(&scratch.0).unwrap();
        for invalid in ["", ".", "..", "nested/keep"] {
            assert!(matches!(basename(invalid), Err(Code::PathRejected)));
            root.unlink(invalid);
        }
        assert!(matches!(basename("nested\0keep"), Err(Code::PathRejected)));
        let stage = Staging {
            root,
            directory: Directory::open(&child).unwrap(),
            name: "nested/child".into(),
        };
        drop(stage);
        assert!(child.is_dir());
        assert_eq!(std::fs::read(outside).unwrap(), b"outside");
    }

    #[cfg_attr(test, test)]
    pub(super) fn closed_notification_endpoint_is_not_a_clean_watch() {
        let (reader, writer) = io::pipe().unwrap();
        let reader: std::os::fd::OwnedFd = reader.into();
        let watch = PublicationWatch(File::from(reader));
        drop(writer);
        assert_eq!(watch.check_clean(), Err(Code::IoFailure));
    }
}

mod json {
    production_source!("json.rs");

    #[cfg_attr(test, test)]
    pub(super) fn checked_string_decoder_preserves_the_caller_error_offset() {
        assert_eq!(decode_quoted(r#""line\n""#, 8).unwrap(), "line\n");
        let error = decode_quoted(r#""\uD800""#, 13).unwrap_err();
        assert_eq!((error.code, error.offset), (Code::InvalidJson, 13));
    }

    #[cfg_attr(test, test)]
    pub(super) fn parser_accepts_every_simple_json_escape() {
        let value = parse(b"\t\r\n \"\\\"\\\\\\/\\b\\f\\n\\r\\t\" ").unwrap();
        assert_eq!(value.string(), Some("\"\\/\u{0008}\u{000c}\n\r\t"));
    }

    #[cfg_attr(test, test)]
    pub(super) fn json_equality_preserves_values_and_number_meaning() {
        for (left, right, equal) in [
            ("null", "null", true),
            ("true", "false", false),
            ("1.20", "12e-1", true),
            ("[1,null]", "[1.0,null]", true),
            (r#"{"x":1,"y":false}"#, r#"{"y":false,"x":1.0}"#, true),
            ("null", "false", false),
        ] {
            assert_eq!(
                parse(left.as_bytes())
                    .unwrap()
                    .equal(&parse(right.as_bytes()).unwrap()),
                equal
            );
        }
    }

    #[cfg_attr(test, test)]
    pub(super) fn exact_unsigned_conversion_refuses_overflow() {
        let cases = [
            ("18446744073709551615", Some(u64::MAX)),
            ("18446744073709551616", None),
            ("20000000000000000001", None),
            ("1e18446744073709551615", None),
            ("1e18446744073709551616", None),
            ("1.1", None),
        ];
        for (input, expected) in cases {
            let token = parse(input.as_bytes()).unwrap();
            assert_eq!(
                Decimal::new(token.number().unwrap()).to_u64(),
                expected,
                "{input}"
            );
        }
    }

    #[cfg_attr(test, test)]
    pub(super) fn compact_encoding_preserves_number_spelling_and_escapes() {
        let input = "{\"z\":[true,false,null,1.20e-1],\"b\":\"\u{1f30d}/\u{e9}\",\"a\":\"\\u0000\\b\\f\\n\\r\\t\\\"\\\\\\u001f\"}";
        let expected = "{\"a\":\"\\u0000\\b\\f\\n\\r\\t\\\"\\\\\\u001f\",\"b\":\"\u{1f30d}/\u{e9}\",\"z\":[true,false,null,1.20e-1]}";
        let mut bytes = Vec::new();
        parse(input.as_bytes()).unwrap().encode(&mut bytes);
        assert_eq!(bytes, expected.as_bytes());
    }
}

pub mod native {
    production_source!("native.rs");
    wire_source!("wire_native.rs");

    #[cfg_attr(test, test)]
    pub(super) fn oversized_worker_reply_never_reaches_the_socket() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let prepared: Prepared = serde_json::from_value(serde_json::json!({
            "id": "x".repeat(REPLY_LIMIT + 1), "counts": {"records": 0, "valid": 0}, "publication": null
        })).unwrap();
        assert!(!send_reply(&mut writer, &Reply::Prepared(prepared)));
        drop(writer);
        assert_eq!(reader.read(&mut [0; 1]).unwrap(), 0);
    }

    #[cfg_attr(test, test)]
    pub(super) fn allocator_refusal_is_returned_outside_a_supervised_worker() {
        assert!(guard_allocation(std::ptr::null_mut()).is_null());
    }

    #[cfg(not(test))]
    pub(super) fn worker_panic_becomes_internal_failure() {
        // This runs from the coverage executable's single-threaded main.
        // The worker isolates the panic and its process-wide hook.
        let outcome =
            unsafe { supervise(|| panic!("private qualification sentinel"), Instant::now()) };
        assert!(matches!(outcome, Err(Code::InternalFailure)));
    }
}

mod order {
    production_source!("order.rs");

    #[cfg_attr(test, test)]
    pub(super) fn rule_evaluator_refuses_missing_order_data() {
        let mut diagnostics = Vec::new();
        evaluate(&Object::default(), &mut |rule, path| {
            diagnostics.push((rule.to_owned(), path));
            true
        });
        assert_eq!(diagnostics, [("ORDER-IDENTITY".into(), "/data".into())]);
    }

    #[cfg_attr(test, test)]
    pub(super) fn rule_evaluator_will_not_accept_a_missing_or_overflowed_subtotal() {
        for item in [
            "null",
            r#"{"line_id":"1","sku":"1"}"#,
            r#"{"line_id":"1","sku":"1","quantity":1}"#,
            r#"{"line_id":"1","sku":"1","quantity":18446744073709551616,"unit_price_minor":1}"#,
            r#"{"line_id":"1","sku":"1","quantity":1,"unit_price_minor":18446744073709551616}"#,
            r#"{"line_id":"1","sku":"1","quantity":18446744073709551615,"unit_price_minor":2}"#,
        ] {
            let fixture = format!(
                r#"{{"id":"1","source":"alderquay.order-adapter","data":{{"order_id":"1","occurred_at":"2025-01-01T00:00:00Z","total_minor":0,"items":[{item}]}}}}"#
            );
            let value = crate::json::parse(fixture.as_bytes()).unwrap();
            let mut failures = Vec::new();
            evaluate(value.object().unwrap(), &mut |rule, path| {
                failures.push((rule.to_owned(), path));
                true
            });
            assert_eq!(
                failures.last(),
                Some(&("ORDER-TOTAL".into(), "/data/total_minor".into())),
                "{item}"
            );
        }
    }
}

mod schema {
    production_source!("schema.rs");

    #[cfg_attr(test, test)]
    pub(super) fn schema_urn_refuses_incomplete_and_malformed_escapes() {
        for suffix in ["%", "%G1", "%1", "%1G"] {
            assert!(!is_urn(&format!("urn:example:policy{suffix}")));
        }
        assert!(is_urn("urn:example:policy%23name"));
    }

    #[cfg_attr(test, test)]
    pub(super) fn evaluator_applies_node_bounds_without_inventing_child_constraints() {
        // Normal admission requires an item schema for arrays. Use the real
        // walker on a minimal node to verify its independent bound check and
        // ensure it does not descend when no child node is available.
        let key = Key {
            urn: "urn:sesv:array".into(),
            path: String::new(),
        };
        let Value::Object(schema) =
            crate::json::parse(br#"{"type":"array","maxItems":1}"#).unwrap()
        else {
            panic!("fixture must be an object");
        };
        let node = Node {
            schema,
            reference: None,
            properties: BTreeMap::new(),
            items: None,
            required: BTreeSet::new(),
            regex: None,
        };
        let graph = Graph(BTreeMap::from([(key.clone(), node)]));
        let mut errors = Vec::new();
        let good = crate::json::parse(b"[0]").unwrap();
        let bad = crate::json::parse(b"[0,1]").unwrap();
        assert!(graph.walk(&key, &good, "/data", &mut |diagnostic| {
            panic!("unexpected diagnostic for the bounded array: {diagnostic:?}")
        }));
        assert!(graph.walk(&key, &bad, "/data", &mut |diagnostic| {
            errors.push(diagnostic);
            true
        }));
        assert_eq!(errors.len(), 1);
        assert_eq!(
            (errors[0].stage, errors[0].code),
            (Stage::Schema, Code::SchemaViolation)
        );
        assert_eq!(errors[0].instance_path.as_deref(), Some("/data"));
        assert_eq!(errors[0].schema_path.as_deref(), Some("/maxItems"));
    }
}

mod cli {
    production_source!("main.rs");

    #[cfg(not(test))]
    pub(super) fn run() -> ExitCode {
        main()
    }

    #[cfg_attr(test, test)]
    pub(super) fn cli_allocator_provides_zero_initialized_memory() {
        let layout = Layout::from_size_align(128, 16).unwrap();
        // Exercise the actual allocator, with explicit ownership and matching
        // deallocation independent of the compiler's choice for Vec::resize.
        let pointer = unsafe { Allocator.alloc_zeroed(layout) };
        assert!(!pointer.is_null());
        assert!(
            unsafe { std::slice::from_raw_parts(pointer, 128) }
                .iter()
                .all(|byte| *byte == 0)
        );
        unsafe { Allocator.dealloc(pointer, layout) };
    }
}

#[cfg(not(test))]
fn run_component_probes() {
    artifact::metered_flush_delivers_each_reserved_byte_to_disk();
    engine::duplicate_diagnostics_do_not_use_a_distinct_slot();
    engine::module_registry_selects_only_known_ids();
    engine::policy_names_and_calendar_boundaries_are_portable();
    engine::in_memory_limits_refuse_oversized_inputs_before_callbacks();
    filesystem::private_cleanup_rejects_multiple_components_and_non_names();
    filesystem::closed_notification_endpoint_is_not_a_clean_watch();
    json::checked_string_decoder_preserves_the_caller_error_offset();
    json::parser_accepts_every_simple_json_escape();
    json::json_equality_preserves_values_and_number_meaning();
    json::exact_unsigned_conversion_refuses_overflow();
    json::compact_encoding_preserves_number_spelling_and_escapes();
    native::oversized_worker_reply_never_reaches_the_socket();
    native::allocator_refusal_is_returned_outside_a_supervised_worker();
    native::worker_panic_becomes_internal_failure();
    order::rule_evaluator_refuses_missing_order_data();
    order::rule_evaluator_will_not_accept_a_missing_or_overflowed_subtotal();
    schema::evaluator_applies_node_bounds_without_inventing_child_constraints();
    schema::schema_urn_refuses_incomplete_and_malformed_escapes();
    cli::cli_allocator_provides_zero_initialized_memory();
}
