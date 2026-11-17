use std::process::{Command, Output};

fn sesv(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sesv"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn help_is_human_readable_and_explains_local_authority() {
    for args in [
        vec!["--help"],
        vec!["validate", "--help"],
        vec!["verify", "--help"],
    ] {
        let output = sesv(&args);
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains("allowlist"));
        assert!(help.contains("Formal policy approval happens outside SESV"));
        assert!(help.contains("source authentication"));
    }
}

#[test]
fn unknown_dispatch_has_fixed_stderr_and_empty_stdout() {
    for args in [vec![], vec!["other"], vec!["--help", "extra"]] {
        let output = sesv(&args);
        assert_eq!(output.status.code(), Some(4));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"The command arguments are invalid.\n");
    }
}

#[test]
fn invalid_known_invocation_emits_exact_outcome() {
    let output = sesv(&["verify", "--help", "--run", "/unreadable"]);
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "result_version":"1.0.0", "operation":"verify", "status":"failed",
            "exit_code":4, "run_id":null, "output_directory":null,
            "code":"ARGUMENT_INVALID", "message":"The command arguments are invalid.",
            "record_count":null, "valid_count":null, "invalid_count":null
        })
    );
}

#[test]
fn unsupported_format_is_rejected_before_opening_paths() {
    let output = sesv(&[
        "validate",
        "--input",
        "/missing",
        "--format",
        "yaml",
        "--bundle",
        "/missing",
        "--allowlist",
        "/missing",
        "--out",
        "/missing",
    ]);
    assert_eq!(output.status.code(), Some(4));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["code"], "UNSUPPORTED_FORMAT");
    assert_eq!(value["output_directory"], "/missing");
}
