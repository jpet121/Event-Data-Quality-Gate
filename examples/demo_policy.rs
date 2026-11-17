use serde_json::{Value, json};
use sesv::engine::{core_digest, module_digest, sha256};
use std::{env, fs, io::Write, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let folder = PathBuf::from(arguments.next().ok_or("supply a new fixture directory")?);
    if arguments.next().is_some() {
        return Err("supply exactly one fixture directory".into());
    }
    fs::create_dir(&folder)?;
    let order_1 = include_str!("order.schema.json");
    let mut order_1_1: Value = serde_json::from_str(order_1)?;
    order_1_1["$id"] = json!("urn:alderquay:order.created:1.1.0");
    order_1_1["properties"]["channel"] = json!({"type":"string","enum":["web","phone"]});
    let order_1_1 = format!("{}\n", serde_json::to_string_pretty(&order_1_1)?);
    let order_digest = module_digest("example.order").ok_or("order module is missing")?;
    let schema_digest =
        module_digest("builtin.schema-only").ok_or("schema-only module is missing")?;
    let mut resources = Vec::new();
    let mut contracts = Vec::new();
    for (name, text, event_type, version, dataschema, module, digest) in [
        (
            "order-1.schema.json",
            order_1,
            "order.created",
            "1.0.0",
            "urn:alderquay:order.created:1.0.0",
            "example.order",
            &order_digest,
        ),
        (
            "order-1.1.schema.json",
            order_1_1.as_str(),
            "order.created",
            "1.1.0",
            "urn:alderquay:order.created:1.1.0",
            "example.order",
            &order_digest,
        ),
        (
            "pulse.schema.json",
            include_str!("pulse.schema.json"),
            "telemetry.pulse",
            "1.0.0",
            "urn:example:telemetry.pulse:1.0.0",
            "builtin.schema-only",
            &schema_digest,
        ),
    ] {
        let schema: Value = serde_json::from_str(text)?;
        let id = &schema["$id"];
        fs::write(folder.join(name), text)?;
        resources.push(json!({"schema_id":id,"file":name,"sha256":sha256(text.as_bytes())}));
        contracts.push(json!({
            "event_type":event_type, "schema_version":version, "dataschema":dataschema,
            "root_schema_id":id, "module_id":module, "module_version":"1.0.0",
            "module_sha256":digest
        }));
    }
    let bundle = json!({
        "bundle_format":"sesv-bundle/1","bundle_id":"sesv-synthetic-pilot","bundle_version":"1.0.0",
        "rule_abi":"sesv-rule-abi/1", "resources":resources, "contracts":contracts
    });
    let bundle_text = format!("{}\n", serde_json::to_string_pretty(&bundle)?);
    let bundle_digest = sha256(bundle_text.as_bytes());
    fs::write(folder.join("bundle.json"), bundle_text)?;
    fs::write(
        folder.join("allowlist.json"),
        format!("{}\n", json!({"allowed_manifest_sha256":[bundle_digest]})),
    )?;
    let pulse = json!({
        "id":"pulse-1","source":"local-fixture","type":"telemetry.pulse","schema_version":"1.0.0",
        "data":{"device_id":"pump-1","state":"up"}
    });
    let mut order = json!({
        "id":"order-1","source":"alderquay.order-adapter","type":"order.created","schema_version":"1.0.0",
        "data":{"order_id":"one","occurred_at":"2024-02-29T00:00:00Z","currency":"USD",
            "items":[{"line_id":"a","sku":"sample","quantity":2,"unit_price_minor":150}],"total_minor":300}
    });
    let mut events = fs::File::create_new(folder.join("events.ndjson"))?;
    writeln!(events, "{pulse}")?;
    writeln!(events, "{order}")?;
    order["schema_version"] = json!("1.1.0");
    order["data"]["channel"] = json!("web");
    writeln!(events, "{order}")?;
    order["data"]["total_minor"] = json!(301);
    writeln!(events, "{order}")?;
    let cloud = json!({
        "specversion":"1.0","id":"cloud-1","source":"../telemetry","type":"telemetry.pulse",
        "datacontenttype":"application/json","dataschema":"urn:example:telemetry.pulse:1.0.0",
        "data":{"device_id":"pump-1","state":"down"}
    });
    fs::write(folder.join("cloud.json"), format!("{cloud}\n"))?;
    let source_evidence = json!({
        "bundle_sha256":bundle_digest,"core_sha256":core_digest(),
        "modules":{
            "builtin.schema-only":schema_digest,
            "example.order":order_digest
        }
    });
    fs::write(
        folder.join("source-identities.json"),
        format!("{}\n", serde_json::to_string_pretty(&source_evidence)?),
    )?;
    Ok(())
}
