# Validation results

The engineering qualification executable has SHA-256 `93d61a2d70ec37f389105d463a35d5bf252e3d851e6c30f682ae90d54f236639`.

The engineering run passed 240 public cases and 28 operational cases. All 17 declared mutants were killed. The team observed all 2,989 mapped lines, 1,040 LLVM branch directions, 888 handwritten Rust outcomes, and 2,354 generated Serde outcomes. The coverage audit used zero exclusions.

The Ubuntu 24.04 reference guest ran AppArmor in enforce mode. The checks covered crash and cancellation behavior, independent artifact verification, upgrade, and restore. The extracted ZIP also passed an offline validation and verification check.

## GitHub asset checks

The Linux download uses executable SHA-256 `7249e7ab981c844340201ec30402b19b91c07f33dd8401e8aea22272b2371071`. It uses demo policy SHA-256 `00280ca57e8d668b52dee381968b934234ed3e079a1de5fd99278e9529806d5b`.

The source ZIP built on Ubuntu 24.04. Rust format and lint checks passed. All 38 Rust tests passed. The Linux asset executable passed the 240 public cases. The sample run reported three valid records and one invalid record. The verifier accepted its output.
