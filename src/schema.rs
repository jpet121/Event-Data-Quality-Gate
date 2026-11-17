use crate::contract::{Code, Diagnostic, Stage};
use crate::json::{Decimal, Object, Value, pointer};
use regress::Regex;
use std::collections::{BTreeMap, BTreeSet};

const DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";
const TYPES: &[&str] = &[
    "null", "boolean", "integer", "number", "string", "array", "object",
];
const META: &[&str] = &["title", "description", "$comment"];

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct Key {
    urn: String,
    path: String,
}

struct Node {
    schema: Object,
    reference: Option<Key>,
    properties: BTreeMap<String, Key>,
    items: Option<Key>,
    required: BTreeSet<String>,
    regex: Option<Regex>,
}

pub(crate) struct Graph(BTreeMap<Key, Node>);

pub(crate) fn is_urn(value: &str) -> bool {
    let Some((nid, nss)) = value
        .strip_prefix("urn:")
        .and_then(|tail| tail.split_once(':'))
    else {
        return false;
    };
    (2..=32).contains(&nid.len())
        && nid
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && nid.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
        && nid.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        && !nss.is_empty()
        && nss
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@%/".contains(&c))
        && percent_decode(nss).is_some()
}

fn percent_decode(s: &str) -> Option<String> {
    let mut bytes = s.bytes();
    let mut result = Vec::new();
    while let Some(value) = bytes.next() {
        if value == b'%' {
            let hi = char::from(bytes.next()?).to_digit(16)?;
            let lo = char::from(bytes.next()?).to_digit(16)?;
            result.push((16 * hi + lo) as u8);
        } else {
            result.push(value);
        }
    }
    String::from_utf8(result).ok()
}

fn reference(s: &str, base: &str) -> Result<Key, Code> {
    let (urn, fragment) = s.split_once('#').unwrap_or((s, ""));
    let urn = if urn.is_empty() && s.starts_with('#') {
        base
    } else {
        urn
    };
    if !is_urn(urn) || fragment.contains('#') {
        return Err(Code::ReferenceInvalid);
    }
    let fragment = percent_decode(fragment).ok_or(Code::ReferenceInvalid)?;
    let mut path = String::new();
    if !fragment.is_empty() {
        let rest = fragment.strip_prefix('/').ok_or(Code::ReferenceInvalid)?;
        for segment in rest.split('/') {
            let mut chars = segment.chars();
            let mut decoded = String::new();
            while let Some(c) = chars.next() {
                decoded.push(match c {
                    '~' => match chars.next() {
                        Some('0') => '~',
                        Some('1') => '/',
                        _ => return Err(Code::ReferenceInvalid),
                    },
                    c => c,
                });
            }
            path = pointer(&path, &decoded);
        }
    }
    Ok(Key {
        urn: urn.into(),
        path,
    })
}

fn pattern(s: &str) -> Result<Regex, Code> {
    if s.len() > 256 || !s.bytes().all(|c| c == b' ' || c.is_ascii_graphic()) {
        return Err(Code::SchemaUnsupported);
    }
    // The admission check above permits only ASCII. Iterating characters
    // preserves each token and avoids re-decoding a byte buffer as UTF-8.
    let mut rest = s.chars().peekable();
    let mut class = false;
    while let Some(c) = rest.next() {
        match c {
            '\\' => {
                if !rest.next().is_some_and(|c| c.is_ascii_punctuation()) {
                    return Err(Code::SchemaUnsupported);
                }
            }
            '[' if !class => class = true,
            ']' if class => class = false,
            '(' if !class && rest.peek() == Some(&'?') => return Err(Code::SchemaUnsupported),
            '{' if !class => {
                let term: String = rest.by_ref().take_while(|c| *c != '}').collect();
                let (a, b) = term.split_once(',').unwrap_or((&term, &term));
                let bound = |s: &str| {
                    if s.bytes().all(|c| c.is_ascii_digit()) {
                        s.parse::<u16>().ok().filter(|v| *v <= 1000)
                    } else {
                        None
                    }
                };
                if !bound(a).zip(bound(b)).is_some_and(|(a, b)| a <= b) {
                    return Err(Code::SchemaUnsupported);
                }
            }
            _ => {}
        }
    }
    Regex::new(s).map_err(|_| Code::SchemaUnsupported)
}

fn valid_type(value: &Value, names: &[&str]) -> bool {
    match value {
        Value::String(name) => names.contains(&name.as_str()),
        Value::Array(values) => {
            let mut seen = BTreeSet::new();
            !values.is_empty()
                && values.iter().all(|v| {
                    v.string()
                        .is_some_and(|s| names.contains(&s) && seen.insert(s))
                })
        }
        _ => false,
    }
}

fn includes(types: &Value, name: &str) -> bool {
    types.string() == Some(name)
        || types
            .array()
            .is_some_and(|values| values.iter().any(|t| t.string() == Some(name)))
}

fn matches_type(kind: &Value, value: &Value) -> bool {
    match value {
        Value::Null => includes(kind, "null"),
        Value::Bool(_) => includes(kind, "boolean"),
        Value::Number(token) => {
            includes(kind, "number") || (includes(kind, "integer") && Decimal::new(token).integer())
        }
        Value::String(_) => includes(kind, "string"),
        Value::Array(_) => includes(kind, "array"),
        Value::Object(_) => includes(kind, "object"),
    }
}

fn child(key: &Key, category: &str, name: Option<&str>) -> Key {
    let path = pointer(&key.path, category);
    Key {
        urn: key.urn.clone(),
        path: name.map_or_else(|| path.clone(), |n| pointer(&path, n)),
    }
}

impl Graph {
    pub(crate) fn compile(resources: BTreeMap<String, Value>) -> Result<Self, Code> {
        let mut graph = Self(BTreeMap::new());
        for (urn, value) in resources {
            graph.insert(
                Key {
                    urn,
                    path: String::new(),
                },
                value,
            )?;
        }
        graph.validate_edges()?;
        Ok(graph)
    }

    fn insert(&mut self, key: Key, value: Value) -> Result<(), Code> {
        let Value::Object(mut schema) = value else {
            return Err(Code::SchemaUnsupported);
        };
        let unsupported = Code::SchemaUnsupported;
        let root = key.path.is_empty();
        if root
            && (schema.get("$schema").and_then(Value::string) != Some(DIALECT)
                || schema.get("$id").and_then(Value::string) != Some(&key.urn))
        {
            return Err(unsupported);
        }
        if !root && (schema.contains_key("$schema") || schema.contains_key("$id")) {
            return Err(unsupported);
        }
        schema.remove("$schema");
        schema.remove("$id");
        for name in META {
            if schema
                .remove(*name)
                .is_some_and(|value| value.string().is_none())
            {
                return Err(unsupported);
            }
        }
        let reference = if let Some(value) = schema.remove("$ref") {
            if !schema.is_empty() {
                return Err(unsupported);
            }
            Some(reference(
                value.string().ok_or(Code::ReferenceInvalid)?,
                &key.urn,
            )?)
        } else {
            let types = schema.get("type").ok_or(unsupported)?;
            if !valid_type(types, TYPES) {
                return Err(unsupported);
            }
            for (name, value) in &schema {
                let ok = match name.as_str() {
                    "type" | "const" | "$defs" => true,
                    "enum" => value.array().is_some_and(|values| {
                        !values.is_empty()
                            && !values
                                .iter()
                                .enumerate()
                                .any(|(i, v)| values[..i].iter().any(|prior| v.equal(prior)))
                    }),
                    "minimum" | "maximum" => {
                        (includes(types, "number") || includes(types, "integer"))
                            && value.number().is_some()
                    }
                    "minLength" | "maxLength" | "minItems" | "maxItems" => {
                        let ty = if name.ends_with("Length") {
                            "string"
                        } else {
                            "array"
                        };
                        includes(types, ty)
                            && value.number().is_some_and(|token| {
                                let n = Decimal::new(token);
                                n.integer() && n.nonnegative()
                            })
                    }
                    "pattern" => includes(types, "string") && value.string().is_some(),
                    "properties" | "required" => includes(types, "object"),
                    "additionalProperties" => {
                        includes(types, "object") && matches!(value, Value::Bool(false))
                    }
                    "items" => includes(types, "array"),
                    _ => false,
                };
                if !ok {
                    return Err(unsupported);
                }
            }
            if (includes(types, "object") && !schema.contains_key("additionalProperties"))
                || (includes(types, "array") && !schema.contains_key("items"))
            {
                return Err(unsupported);
            }
            for (min, max) in [
                ("minimum", "maximum"),
                ("minLength", "maxLength"),
                ("minItems", "maxItems"),
            ] {
                if let Some((a, b)) = schema
                    .get(min)
                    .and_then(Value::number)
                    .zip(schema.get(max).and_then(Value::number))
                    && Decimal::new(a).cmp(&Decimal::new(b)).is_gt()
                {
                    return Err(unsupported);
                }
            }
            None
        };
        let mut properties = BTreeMap::new();
        if let Some(value) = schema.remove("properties") {
            let Value::Object(fields) = value else {
                return Err(unsupported);
            };
            for (name, value) in fields {
                let path = child(&key, "properties", Some(&name));
                self.insert(path.clone(), value)?;
                properties.insert(name, path);
            }
        }
        let mut required = BTreeSet::new();
        if let Some(value) = schema.remove("required") {
            for name in value.array().ok_or(unsupported)? {
                let name = name.string().ok_or(unsupported)?;
                if !properties.contains_key(name) || !required.insert(name.to_owned()) {
                    return Err(unsupported);
                }
            }
        }
        if let Some(value) = schema.remove("$defs") {
            let Value::Object(defs) = value else {
                return Err(unsupported);
            };
            for (name, value) in defs {
                self.insert(child(&key, "$defs", Some(&name)), value)?;
            }
        }
        let items = if let Some(value) = schema.remove("items") {
            let path = child(&key, "items", None);
            self.insert(path.clone(), value)?;
            Some(path)
        } else {
            None
        };
        let regex = schema
            .remove("pattern")
            .and_then(|v| v.string().map(str::to_owned))
            .as_deref()
            .map(pattern)
            .transpose()?;
        self.0.insert(
            key,
            Node {
                schema,
                reference,
                properties,
                items,
                required,
                regex,
            },
        );
        Ok(())
    }

    fn validate_edges(&self) -> Result<(), Code> {
        let mut in_degree: BTreeMap<_, usize> = self.0.keys().map(|key| (key, 0)).collect();
        let edges = |key: &Key| -> Vec<&Key> {
            let n = &self.0[key];
            n.reference
                .iter()
                .chain(n.items.iter())
                .chain(n.properties.values())
                .collect()
        };
        for key in self.0.keys() {
            for to in edges(key) {
                *in_degree.get_mut(to).ok_or(Code::ReferenceInvalid)? += 1;
            }
        }
        let mut ready: Vec<_> = in_degree
            .iter()
            .filter(|(_, v)| **v == 0)
            .map(|(k, _)| *k)
            .collect();
        let mut visited = 0;
        while let Some(key) = ready.pop() {
            visited += 1;
            for to in edges(key) {
                let degree = in_degree.get_mut(to).unwrap();
                *degree -= 1;
                if *degree == 0 {
                    ready.push(to);
                }
            }
        }
        if visited == self.0.len() {
            Ok(())
        } else {
            Err(Code::ReferenceInvalid)
        }
    }

    pub(crate) fn evaluate(
        &self,
        urn: &str,
        value: &Value,
        emit: &mut dyn FnMut(Diagnostic) -> bool,
    ) {
        self.walk(
            &Key {
                urn: urn.into(),
                path: String::new(),
            },
            value,
            "/data",
            emit,
        );
    }

    /// Returns false once the diagnostic collector has reached its stopping point.
    fn walk(
        &self,
        start: &Key,
        value: &Value,
        path: &str,
        emit: &mut dyn FnMut(Diagnostic) -> bool,
    ) -> bool {
        let mut key = start;
        while let Some(target) = &self.0[key].reference {
            key = target;
        }
        let node = &self.0[key];
        let mut error = |kw: &str, code: Code, location: String| {
            let mut diagnostic = Diagnostic::at(Stage::Schema, code, Some(location));
            diagnostic.schema_id = Some(key.urn.clone());
            diagnostic.schema_path = Some(pointer(&key.path, kw));
            emit(diagnostic)
        };
        if !matches_type(&node.schema["type"], value) {
            return error("type", Code::TypeMismatch, path.into());
        }
        for (kw, violated) in [
            (
                "const",
                node.schema
                    .get("const")
                    .is_some_and(|expected| !expected.equal(value)),
            ),
            (
                "enum",
                node.schema
                    .get("enum")
                    .and_then(Value::array)
                    .is_some_and(|choices| !choices.iter().any(|expected| expected.equal(value))),
            ),
        ] {
            if violated && !error(kw, Code::SchemaViolation, path.into()) {
                return false;
            }
        }
        let compare = |kw: &str, n: &Decimal| {
            node.schema
                .get(kw)
                .and_then(Value::number)
                .map(|x| n.cmp(&Decimal::new(x)))
        };
        let within = |min: &str,
                      max: &str,
                      n: &Decimal,
                      error: &mut dyn FnMut(&str, Code, String) -> bool| {
            (!compare(min, n).is_some_and(|o| o.is_lt())
                || error(min, Code::SchemaViolation, path.into()))
                && (!compare(max, n).is_some_and(|o| o.is_gt())
                    || error(max, Code::SchemaViolation, path.into()))
        };
        match value {
            Value::Number(token)
                if !within("minimum", "maximum", &Decimal::new(token), &mut error) =>
            {
                return false;
            }
            Value::String(text) => {
                if !within(
                    "minLength",
                    "maxLength",
                    &Decimal::new(&text.chars().count().to_string()),
                    &mut error,
                ) {
                    return false;
                }
                if let Some(regex) = &node.regex {
                    let units: Vec<_> = text.encode_utf16().collect();
                    if regex.find_from_ucs2(&units, 0).next().is_none()
                        && !error("pattern", Code::SchemaViolation, path.into())
                    {
                        return false;
                    }
                }
            }
            Value::Array(values) => {
                if !within(
                    "minItems",
                    "maxItems",
                    &Decimal::new(&values.len().to_string()),
                    &mut error,
                ) {
                    return false;
                }
                if let Some(items) = &node.items {
                    for (i, item) in values.iter().enumerate() {
                        if !self.walk(items, item, &pointer(path, &i.to_string()), emit) {
                            return false;
                        }
                    }
                }
            }
            Value::Object(fields) => {
                for name in &node.required {
                    if !fields.contains_key(name)
                        && !error("required", Code::RequiredField, pointer(path, name))
                    {
                        return false;
                    }
                }
                if fields
                    .keys()
                    .any(|name| !node.properties.contains_key(name))
                    && !error("additionalProperties", Code::UnknownField, path.into())
                {
                    return false;
                }
                for (name, key) in &node.properties {
                    if let Some(field) = fields.get(name)
                        && !self.walk(key, field, &pointer(path, name), emit)
                    {
                        return false;
                    }
                }
            }
            _ => {}
        }
        true
    }
}
