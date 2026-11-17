use serde::Deserialize;
use serde_json::{Value, json};
use sesv::contract::{Code, Operation, Outcome};

#[derive(Deserialize)]
struct Query {
    code: Code,
    record_scope: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let queries: Vec<Query> = serde_json::from_reader(std::io::stdin().lock())?;
    let report: Vec<_> = queries
        .into_iter()
        .map(|query| {
            let Query { code, record_scope } = query;
            let outcome = if record_scope {
                Value::Null
            } else {
                serde_json::to_value(Outcome::failed(Operation::Validate, None, code))?
            };
            Ok(json!({"code": code, "message": code.message(), "outcome": outcome}))
        })
        .collect::<Result<_, serde_json::Error>>()?;
    serde_json::to_writer(std::io::stdout().lock(), &report)?;
    Ok(())
}
