//! Schema parity between the published configuration schema and the Rust
//! loader (issue #456 / E-048).
//!
//! `docs/schemas/config-v1.schema.json` is the formal JSON Schema (draft
//! 2020-12) for `.stellar-canary.toml`; `crates/canary-config` is its
//! implementation. This suite pins the two together so neither can drift:
//! every key the loader's structs carry is declared by the schema, every key
//! the schema declares is known to the loader, and across the corpus below the
//! two reach the same accept-or-reject decision for every document.
//!
//! The validator interprets the schema *as data*, using only the keywords the
//! schema document contains (asserted by
//! [`the_schema_uses_only_keywords_the_test_validator_interprets`]), so these
//! checks exercise the published file rather than a parallel re-statement of
//! it. TOML documents are converted to the JSON instance model first; the one
//! lossy step is a date-time value, which no key of this file accepts and which
//! the converter therefore renders as JSON null, so that the schema refuses it
//! for the same reason the loader does.
//!
//! Two tests mutate the schema on purpose. They are the negative direction the
//! issue asks for: they show that a loader field the schema has not caught up
//! with, or a schema key the loader never heard of, is reported as drift
//! instead of being silently tolerated.

use std::path::{Path, PathBuf};

use canary_config::{
    parse_config, ConfigFile, PolicySection, ProjectSection, ProjectTypeSetting, TestsSection,
    DEFAULT_PROTOCOL, SUPPORTED_CONFIG_VERSION,
};
use serde_json::{json, Map, Value};

const SCHEMA: &str = include_str!("../../../docs/schemas/config-v1.schema.json");

/// The name used in diagnostics only: nothing here touches the filesystem.
const PATH: &str = ".stellar-canary.toml";

/// Every keyword the schema document may use. Adding a keyword to the schema
/// without teaching this file about it fails
/// [`the_schema_uses_only_keywords_the_test_validator_interprets`], which keeps
/// the validator an honest — if small — implementation of exactly the subset
/// the schema needs.
const SUPPORTED_KEYWORDS: &[&str] = &[
    "$schema",
    "$id",
    "title",
    "description",
    "type",
    "const",
    "enum",
    "default",
    "required",
    "properties",
    "additionalProperties",
    "minimum",
    "maximum",
    "not",
];

fn schema() -> Value {
    serde_json::from_str(SCHEMA).expect("the published schema is valid JSON")
}

fn type_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Validates `instance` against `schema`, returning `Err` with a
/// path-qualified message for the first violation.
fn validate(instance: &Value, schema: &Value, path: &str) -> Result<(), String> {
    if let Some(expected) = schema.get("type") {
        let wanted: Vec<&str> = match expected {
            Value::String(name) => vec![name.as_str()],
            Value::Array(names) => names.iter().filter_map(Value::as_str).collect(),
            other => return Err(format!("{path}: schema has an unusable `type`: {other}")),
        };
        if !wanted.contains(&type_of(instance)) {
            return Err(format!(
                "{path}: expected type {expected}, found {}",
                type_of(instance)
            ));
        }
    }
    if let Some(constant) = schema.get("const") {
        if instance != constant {
            return Err(format!("{path}: expected {constant}, found {instance}"));
        }
    }
    if let Some(values) = schema.get("enum") {
        if !values
            .as_array()
            .is_some_and(|values| values.contains(instance))
        {
            return Err(format!("{path}: {instance} is not one of {values}"));
        }
    }
    if let Some(minimum) = schema.get("minimum") {
        match (instance.as_f64(), minimum.as_f64()) {
            (Some(value), Some(min)) if value >= min => {}
            _ => return Err(format!("{path}: {instance} is below the minimum {minimum}")),
        }
    }
    if let Some(maximum) = schema.get("maximum") {
        match (instance.as_f64(), maximum.as_f64()) {
            (Some(value), Some(max)) if value <= max => {}
            _ => return Err(format!("{path}: {instance} is above the maximum {maximum}")),
        }
    }
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        if let Some(object) = instance.as_object() {
            for field in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(field) {
                    return Err(format!("{path}: required field `{field}` is missing"));
                }
            }
        }
    }
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        if let Some(object) = instance.as_object() {
            for (name, sub_schema) in properties {
                if let Some(value) = object.get(name) {
                    validate(value, sub_schema, &format!("{path}.{name}"))?;
                }
            }
        }
    }
    if let Some(extra) = schema.get("additionalProperties") {
        if let Some(object) = instance.as_object() {
            let declared = schema.get("properties").and_then(Value::as_object);
            for (name, value) in object {
                if declared.is_some_and(|properties| properties.contains_key(name)) {
                    continue;
                }
                match extra {
                    Value::Bool(true) => {}
                    Value::Bool(false) => {
                        return Err(format!("{path}.{name} is not a declared configuration key"));
                    }
                    sub_schema => validate(value, sub_schema, &format!("{path}.{name}"))?,
                }
            }
        }
    }
    // A `not` subschema is a rejection: matching it is the violation. The
    // configuration schema uses exactly one, for the rule that a file cannot
    // turn off every surface at once.
    if let Some(negated) = schema.get("not") {
        if validate(instance, negated, path).is_ok() {
            return Err(format!("{path}: matches the schema's `not` constraint"));
        }
    }
    Ok(())
}

/// What one side of the contract decided about one document.
enum Outcome {
    Accepted,
    Rejected(String),
}

impl Outcome {
    fn accepted(&self) -> bool {
        matches!(self, Outcome::Accepted)
    }

    fn describe(&self) -> String {
        match self {
            Outcome::Accepted => "accept".to_string(),
            Outcome::Rejected(reason) => format!("reject ({reason})"),
        }
    }
}

/// Converts a TOML value into the JSON instance model the schema validates.
///
/// A date-time becomes `null` deliberately: `.stellar-canary.toml` has no key
/// that accepts one, and the loader refuses it for every key, so the converted
/// document has to be refused by the schema for the same reason.
fn to_json(value: toml::Value) -> Value {
    match value {
        toml::Value::String(text) => Value::String(text),
        toml::Value::Integer(number) => json!(number),
        toml::Value::Float(number) => serde_json::Number::from_f64(number)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        toml::Value::Boolean(flag) => json!(flag),
        toml::Value::Datetime(_) => Value::Null,
        toml::Value::Array(items) => Value::Array(items.into_iter().map(to_json).collect()),
        toml::Value::Table(table) => {
            let mut object = Map::new();
            for (key, item) in table {
                object.insert(key, to_json(item));
            }
            Value::Object(object)
        }
    }
}

fn rust_outcome(text: &str) -> Outcome {
    match parse_config(text, Path::new(PATH)) {
        Ok(_) => Outcome::Accepted,
        Err(error) => Outcome::Rejected(error.to_string()),
    }
}

fn schema_outcome(text: &str, schema: &Value) -> Outcome {
    let table: toml::Table = match toml::from_str(text) {
        Ok(table) => table,
        Err(error) => return Outcome::Rejected(format!("not a TOML document: {error}")),
    };
    let instance = to_json(toml::Value::Table(table));
    match validate(&instance, schema, "$") {
        Ok(()) => Outcome::Accepted,
        Err(reason) => Outcome::Rejected(reason),
    }
}

/// The name of the difference between the two sides, or `None` when they agree.
fn parity_miss(name: &str, text: &str, schema: &Value) -> Option<String> {
    let rust = rust_outcome(text);
    let model = schema_outcome(text, schema);
    if rust.accepted() == model.accepted() {
        return None;
    }
    Some(format!(
        "{name}: the loader would {} but the schema would {}\ndocument:\n{text}",
        rust.describe(),
        model.describe()
    ))
}

/// One key of one table: the table it belongs to, its name, and the TOML text
/// of its value. An empty table name is the document root.
type Item = (String, String, String);

/// The tables in document order, so a generated document reads like a file.
const TABLES: [&str; 4] = ["", "project", "tests", "policy"];

fn item(table: &str, key: &str, value: &str) -> Item {
    (table.to_string(), key.to_string(), value.to_string())
}

/// A configuration carrying every key the loader knows, each with a value the
/// loader accepts.
fn full_config() -> Vec<Item> {
    vec![
        item("", "version", "1"),
        item("", "protocol", "28"),
        item("", "network", "\"testnet\""),
        item("", "rpc_url", "\"https://soroban-testnet.stellar.org\""),
        item("", "fixtures_dir", "\"fixtures\""),
        item("project", "type", "\"auto\""),
        item("tests", "xdr", "true"),
        item("tests", "rpc", "true"),
        item("tests", "soroban", "true"),
        item("policy", "warnings_are_failures", "false"),
    ]
}

/// Renders items as a TOML document: `skip` drops one key, `replace` gives one
/// key new text, and `added` contributes extra keys. A table whose keys all
/// disappear loses its header, which is what a hand-written file does when it
/// leaves the section out.
fn render(
    entries: &[Item],
    skip: Option<(&str, &str)>,
    replace: Option<(&str, &str, &str)>,
    added: &[Item],
) -> String {
    let mut out = String::from("# written by crates/canary-config/tests/schema_parity.rs\n");
    for table in TABLES {
        let mut lines = Vec::new();
        for (owner, key, value) in entries.iter().chain(added.iter()) {
            if owner != table {
                continue;
            }
            if skip == Some((table, key)) {
                continue;
            }
            let written = match replace {
                Some((at, target, text)) if at == table && target == key => text,
                _ => value,
            };
            lines.push(format!("{key} = {written}\n"));
        }
        if lines.is_empty() {
            continue;
        }
        if !table.is_empty() {
            out.push_str(&format!("\n[{table}]\n"));
        }
        for line in lines {
            out.push_str(&line);
        }
    }
    out
}

/// A value of a different type than the one it replaces, for the generated
/// wrong-type cases.
fn mistyped(value: &str) -> String {
    if value.starts_with('"') {
        "1".to_string()
    } else if value == "true" || value == "false" {
        "\"yes\"".to_string()
    } else {
        "\"text\"".to_string()
    }
}

/// The corpus: hand-written documents covering the loader's own rules, plus
/// every single-key mutation of the fully-populated document (one omitted, one
/// mistyped per key, one unknown key per table).
fn corpus() -> Vec<(String, String)> {
    let full = full_config();
    let mut cases: Vec<(String, String)> = Vec::new();

    // The documented shape, and the files a real project writes.
    cases.push((
        "fully-populated".to_string(),
        render(&full, None, None, &[]),
    ));
    for (name, text) in [
        ("minimal", "version = 1\nprotocol = 28\n"),
        (
            "one surface off",
            "version = 1\nprotocol = 28\n\n[tests]\nxdr = false\n",
        ),
        (
            "one surface on",
            "version = 1\nprotocol = 28\n\n[tests]\nxdr = true\nrpc = false\nsoroban = false\n",
        ),
        (
            "custom network and fixture directory",
            "version = 1\nprotocol = 22\nnetwork = \"mine\"\nfixtures_dir = \"my-fixtures\"\n",
        ),
        (
            "project table with nothing in it",
            "version = 1\nprotocol = 28\n\n[project]\n",
        ),
        // The loader stores `rpc_url` verbatim: an unusable scheme is a
        // runtime problem, not a configuration-format one, so both accept it.
        (
            "rpc_url the runtime cannot use",
            "version = 1\nprotocol = 28\nrpc_url = \"ftp://rpc.example.invalid\"\n",
        ),
    ] {
        cases.push((name.to_string(), text.to_string()));
    }
    for project_type in [
        "auto",
        "soroban",
        "rpc-consumer",
        "stellar-sdk",
        "generic-stellar",
        "unknown",
    ] {
        cases.push((
            format!("project type {project_type}"),
            render(
                &full,
                None,
                Some(("project", "type", &format!("\"{project_type}\""))),
                &[],
            ),
        ));
    }

    // Rejections that come from the loader's rules rather than the file shape.
    for (name, text) in [
        ("unsupported version", "version = 2\nprotocol = 28\n"),
        ("zero version", "version = 0\nprotocol = 28\n"),
        ("zero protocol", "version = 1\nprotocol = 0\n"),
        ("protocol above u32", "version = 1\nprotocol = 4294967296\n"),
        ("negative protocol", "version = 1\nprotocol = -1\n"),
        (
            "every surface off",
            "version = 1\nprotocol = 28\n\n[tests]\nxdr = false\nrpc = false\nsoroban = false\n",
        ),
        (
            "project type outside the set",
            "version = 1\nprotocol = 28\n\n[project]\ntype = \"smart-contract\"\n",
        ),
    ] {
        cases.push((name.to_string(), text.to_string()));
    }

    // Rejections that come from the file shape.
    for (name, text) in [
        (
            "misspelled table",
            "version = 1\nprotocol = 28\n\n[test]\nrpc = false\n",
        ),
        (
            "misspelled top-level key",
            "version = 1\nprotocol = 28\nnetworks = \"mainnet\"\n",
        ),
        (
            "misspelled key in a table",
            "version = 1\nprotocol = 28\n\n[policy]\nwarnings_are_failure = true\n",
        ),
        ("empty file", ""),
        ("comment-only file", "# nothing here\n"),
        ("malformed toml", "this is not valid toml [[[\n"),
        ("duplicate key", "version = 1\nversion = 1\nprotocol = 28\n"),
        (
            "date-time value",
            "version = 1\nprotocol = 28\nnetwork = 1979-05-27T07:32:00Z\n",
        ),
        (
            "array value for a scalar key",
            "version = 1\nprotocol = 28\nnetwork = [\"testnet\"]\n",
        ),
        (
            "inline table for a scalar key",
            "version = 1\nprotocol = 28\nnetwork = { name = \"testnet\" }\n",
        ),
        (
            "table where a scalar belongs",
            "version = 1\nprotocol = 28\n\n[network]\nname = \"testnet\"\n",
        ),
    ] {
        cases.push((name.to_string(), text.to_string()));
    }

    // Every declared key, mutated.
    for entry in &full {
        let (table, key, value) = (&entry.0, &entry.1, &entry.2);
        cases.push((
            format!("omitted {table:?}/{key}"),
            render(&full, Some((table, key)), None, &[]),
        ));
        cases.push((
            format!("mistyped {table:?}/{key}"),
            render(&full, None, Some((table, key, &mistyped(value))), &[]),
        ));
    }
    for table in TABLES {
        cases.push((
            format!("unknown key in {table:?}"),
            render(
                &full,
                None,
                None,
                &[item(table, "an_unmapped_key", "\"a value\"")],
            ),
        ));
    }

    cases
}

#[test]
fn the_published_schema_is_draft_2020_12_for_configuration_version_1() {
    let schema = schema();
    assert_eq!(
        schema["$schema"], "https://json-schema.org/draft/2020-12/schema",
        "the published schema targets draft 2020-12"
    );
    assert!(schema["$id"].is_string(), "the schema is identified");
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["properties"]["version"]["const"], 1);

    let required = schema["required"]
        .as_array()
        .expect("required is an array")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<&str>>();
    assert_eq!(
        required,
        vec!["version", "protocol"],
        "only the keys the loader has no default for may be required"
    );
}

#[test]
fn the_schema_uses_only_keywords_the_test_validator_interprets() {
    // Walks schema positions only: each value of `properties`, the single
    // `not`, and a schema-valued `additionalProperties` are themselves
    // schemas, while key names, enums and required lists are data.
    fn walk(node: &Value) {
        let Some(map) = node.as_object() else {
            return;
        };
        for (keyword, value) in map {
            assert!(
                SUPPORTED_KEYWORDS.contains(&keyword.as_str()),
                "the schema uses keyword `{keyword}` this suite does not interpret; \
                 teach tests/schema_parity.rs about it (and extend the corpus)"
            );
            match keyword.as_str() {
                "properties" => value
                    .as_object()
                    .into_iter()
                    .flat_map(|properties| properties.values())
                    .for_each(walk),
                "not" => walk(value),
                "additionalProperties" if value.is_object() => walk(value),
                _ => {}
            }
        }
    }
    walk(&schema());
}

/// The schema node describing one table; the root document is `""`.
fn schema_table<'a>(schema: &'a Value, table: &str) -> &'a Value {
    if table.is_empty() {
        return schema;
    }
    schema
        .get("properties")
        .and_then(|properties| properties.get(table))
        .unwrap_or_else(|| panic!("the schema declares no `{table}` table"))
}

fn declared_keys(node: &Value) -> Vec<String> {
    let mut keys: Vec<String> = node
        .get("properties")
        .and_then(Value::as_object)
        .map(|properties| properties.keys().cloned().collect())
        .unwrap_or_default();
    keys.sort();
    keys
}

/// The keys of an instance object, for the Rust side of the comparison: a
/// serialized `ConfigFile` has no `properties` keyword, it *is* the object.
fn object_keys(node: &Value) -> Vec<String> {
    let mut keys: Vec<String> = node
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default();
    keys.sort();
    keys
}

/// The key tree of the Rust structs, read from the serializable form of a
/// fully-populated `ConfigFile` rather than restated by hand.
fn rust_keys() -> Vec<(String, Vec<String>)> {
    let populated = ConfigFile {
        version: SUPPORTED_CONFIG_VERSION,
        protocol: DEFAULT_PROTOCOL,
        network: Some("testnet".to_string()),
        rpc_url: Some("https://soroban-testnet.stellar.org".to_string()),
        fixtures_dir: Some(PathBuf::from("fixtures")),
        project: ProjectSection {
            project_type: ProjectTypeSetting::Auto,
        },
        tests: TestsSection::default(),
        policy: PolicySection {
            warnings_are_failures: true,
        },
    };
    let value = serde_json::to_value(&populated).expect("a configuration always serializes");
    TABLES
        .iter()
        .map(|table| {
            let node = if table.is_empty() {
                &value
            } else {
                value
                    .get(*table)
                    .unwrap_or_else(|| panic!("ConfigFile carries a `{table}` table"))
            };
            ((*table).to_string(), object_keys(node))
        })
        .collect()
}

#[test]
fn every_key_of_the_rust_structs_is_declared_by_the_schema() {
    let schema = schema();
    let full = full_config();
    for (table, keys) in rust_keys() {
        assert_eq!(
            declared_keys(schema_table(&schema, &table)),
            keys,
            "the keys of {table:?} must match the schema's declarations exactly",
        );
        for key in &keys {
            let leaf = full
                .iter()
                .any(|(owner, declared, _)| *owner == table && *declared == *key);
            // A table key of the root is exercised through its own members.
            let table_key = full.iter().any(|(owner, _, _)| owner == key);
            assert!(
                leaf || table_key,
                "the corpus must exercise {table:?}.{key}",
            );
        }
    }
}

#[test]
fn every_table_the_schema_declares_is_closed_against_unknown_keys() {
    // Parity with `#[serde(deny_unknown_fields)]`: an open table would accept
    // the misspelling the loader refuses.
    let schema = schema();
    for table in TABLES {
        assert_eq!(
            schema_table(&schema, table)["additionalProperties"],
            Value::Bool(false),
            "the table {table:?} must reject keys the loader does not know",
        );
    }
}

#[test]
fn the_loader_and_the_schema_reach_the_same_decision_for_every_case() {
    let cases = corpus();
    let mut misses = Vec::new();
    let mut accepted = 0;
    for (name, text) in &cases {
        if let Some(difference) = parity_miss(name, text, &schema()) {
            misses.push(difference);
        }
        if rust_outcome(text).accepted() {
            accepted += 1;
        }
    }
    assert!(
        misses.is_empty(),
        "{} of {} cases disagree:\n{}",
        misses.len(),
        cases.len(),
        misses.join("\n\n")
    );
    // Guards against the corpus degenerating into one direction only: a suite
    // that only rejects proves nothing about what either side accepts.
    assert!(
        cases.len() >= 45,
        "the corpus is {} cases; it must exercise every declared key",
        cases.len()
    );
    assert!(
        accepted >= 12 && accepted * 2 <= cases.len(),
        "the corpus has {accepted} accepted and {} rejected cases; it needs both",
        cases.len() - accepted
    );
}

#[test]
fn required_lists_match_the_keys_the_loader_cannot_omit() {
    let schema = schema();
    let full = full_config();
    for table in TABLES {
        let mut loader_requires = Vec::new();
        for (owner, key, _) in full.iter().filter(|(owner, _, _)| owner == table) {
            let text = render(&full, Some((owner, key)), None, &[]);
            if !rust_outcome(&text).accepted() {
                loader_requires.push(key.clone());
            }
        }
        let required: Vec<String> = schema_table(&schema, table)
            .get("required")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(
            required, loader_requires,
            "the schema's `required` for {table:?} must be the keys the loader has no default for",
        );
    }
}

#[test]
fn the_schemas_documented_defaults_are_the_loaders_defaults() {
    // `default` is an annotation this validator ignores, so compare it against
    // the values `ConfigFile::default()` actually produces.
    let schema = schema();
    let default = ConfigFile::default();
    for (path, expected) in [
        ("tests.xdr", default.tests.xdr),
        ("tests.rpc", default.tests.rpc),
        ("tests.soroban", default.tests.soroban),
        (
            "policy.warnings_are_failures",
            default.policy.warnings_are_failures,
        ),
    ] {
        let mut node = &schema;
        for part in path.split('.') {
            node = &node["properties"][part];
        }
        assert_eq!(
            node["default"],
            Value::Bool(expected),
            "the schema documents the wrong default for {path}",
        );
    }
    assert_eq!(
        schema["properties"]["project"]["properties"]["type"]["default"],
        Value::String("auto".to_string()),
        "`auto` is what an absent [project].type means",
    );
}

#[test]
fn a_loader_field_the_schema_has_not_caught_up_with_breaks_parity() {
    // The issue's negative direction. `rpc_url` stands in for a key a future
    // change adds to `ConfigFile`: dropping it from the schema must make the
    // checks report the drift rather than tolerate it.
    let mut mutated = schema();
    mutated
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .expect("the root table declares properties")
        .remove("rpc_url")
        .expect("the schema declares rpc_url");

    let text = render(&full_config(), None, None, &[]);
    assert!(
        rust_outcome(&text).accepted(),
        "the loader accepts the document it was written for",
    );
    let miss = parity_miss("drift probe", &text, &mutated)
        .expect("an undeclared loader key must show up as a parity miss");
    assert!(miss.contains("rpc_url"), "{miss}");

    let declared = declared_keys(&mutated);
    let from_rust = rust_keys()
        .into_iter()
        .find(|(table, _)| table.is_empty())
        .map(|(_, keys)| keys)
        .expect("the root table is compared");
    assert_eq!(
        from_rust
            .iter()
            .filter(|key| !declared.contains(key))
            .cloned()
            .collect::<Vec<String>>(),
        vec!["rpc_url".to_string()],
        "the structural comparison names the key that drifted",
    );
}

#[test]
fn a_schema_key_the_loader_does_not_know_breaks_parity() {
    // The other direction: a schema that grows a key the structs never gained
    // must be caught by the accept-or-reject corpus, since the loader refuses
    // it with `deny_unknown_fields`.
    let mut mutated = schema();
    mutated["properties"]["adopted_a_future_key"] = json!({ "type": "string" });

    let text = "version = 1\nprotocol = 28\nadopted_a_future_key = \"yes\"\n";
    assert!(
        !rust_outcome(text).accepted(),
        "the loader refuses a key it does not have",
    );
    let miss = parity_miss("drift probe", text, &mutated)
        .expect("a schema key the loader lacks must show up as a parity miss");
    assert!(miss.contains("adopted_a_future_key"), "{miss}");
}
