//! The policy engine — bundle loading, dialect auto-detect, and fail-closed
//! evaluation.

use regorus::value::{Array, Object, Set};
use regorus::Value;

use crate::bundle::PolicyBundle;
use crate::error::PolicyError;
use crate::verdict::{PolicyVerdict, Violation};

/// Fail-closed Rego policy evaluator.
///
/// Loads [`PolicyBundle`]s (compiling eagerly — a bundle that fails to
/// compile yields [`PolicyError::CompileFailed`] **and poisons the engine**),
/// then evaluates them against an arbitrary JSON input document.
///
/// # Fail-closed semantics (ported from the battle-tested evergreenctl
/// evaluator)
///
/// - A bundle with any compile error fails the whole evaluation — never
///   silently passes. Even if the [`PolicyError`] returned by
///   [`add_bundle`](PolicyEngine::add_bundle) is ignored, every subsequent
///   `evaluate*` call on this engine reports
///   [`PolicyVerdict::EvalError`].
/// - Strict builtin errors: a builtin failing at runtime (e.g. an
///   RE2-incompatible regex) surfaces as
///   [`PolicyVerdict::EvalError`], never as a skipped expression.
/// - Evaluating all bundles, one bad bundle fails the whole verdict —
///   violations from sibling bundles are discarded so a partially-evaluated
///   policy set can never be reported as compliant.
/// - A `default deny = false` that does not fire is not a violation.
///
/// # Rego dialects
///
/// Both dialects are auto-detected per bundle: v1 is tried first, then v0
/// (they are mutually exclusive at parse time). Both `deny[msg]` string-set
/// forms and the v1 `deny contains msg if` / partial-set `{msg: true}` map
/// shapes are collected as violations.
///
/// # Example
///
/// ```
/// use policy_kit::{PolicyBundle, PolicyEngine, PolicyVerdict};
///
/// let mut engine = PolicyEngine::new();
/// let loaded = engine.add_bundle(PolicyBundle::new(
///     "no-latest",
///     r#"
///     package examples.tags
///
///     deny contains msg if {
///         endswith(input.image, ":latest")
///         msg := "floating :latest tag is not allowed"
///     }
///     "#,
/// ));
/// assert!(loaded.is_ok());
///
/// let verdict = engine.evaluate_str(r#"{"image": "nginx:latest"}"#);
/// assert!(matches!(verdict, PolicyVerdict::Violations(ref v) if v.len() == 1));
/// ```
pub struct PolicyEngine {
    compiled: Vec<CompiledBundle>,
    failed: Vec<String>,
}

struct CompiledBundle {
    name: String,
    /// A regorus engine with exactly this bundle's policy compiled in.
    /// Per-bundle isolation: rules evaluate in their own engine, so package
    /// names never collide and violations attribute cleanly. Cloning a
    /// compiled engine is far cheaper than recompiling per evaluation.
    engine: regorus::Engine,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    /// Create an empty engine.
    pub fn new() -> Self {
        Self {
            compiled: Vec::new(),
            failed: Vec::new(),
        }
    }

    /// Compile and load a bundle.
    ///
    /// Rego v1 is tried first, then v0 — the dialects are mutually exclusive
    /// at parse time, so the retry is the auto-detect. On failure the bundle
    /// is recorded as failed (poisoning the engine, see
    /// [`Self::is_poisoned`]) and [`PolicyError::CompileFailed`] is
    /// returned.
    pub fn add_bundle(&mut self, bundle: PolicyBundle) -> Result<(), PolicyError> {
        let name = bundle.name;
        let path = format!("{name}.rego");
        match compile_engine(&path, &bundle.rego_code) {
            Ok(engine) => {
                self.compiled.push(CompiledBundle { name, engine });
                Ok(())
            }
            Err(detail) => {
                self.failed.push(name.clone());
                Err(PolicyError::CompileFailed {
                    bundle: name,
                    detail,
                })
            }
        }
    }

    /// Compile and load every bundle; stops at the first failure (which is
    /// still recorded — the engine stays fail-closed).
    pub fn add_bundles(
        &mut self,
        bundles: impl IntoIterator<Item = PolicyBundle>,
    ) -> Result<(), PolicyError> {
        for bundle in bundles {
            self.add_bundle(bundle)?;
        }
        Ok(())
    }

    /// Names of the successfully loaded bundles, in load order.
    pub fn bundle_names(&self) -> impl Iterator<Item = &str> {
        self.compiled.iter().map(|b| b.name.as_str())
    }

    /// True if any bundle failed to compile on this engine. Every evaluation
    /// on a poisoned engine returns [`PolicyVerdict::EvalError`].
    pub fn is_poisoned(&self) -> bool {
        !self.failed.is_empty()
    }

    /// Evaluate one named bundle against a JSON input document (raw text).
    ///
    /// Unknown bundle names are fail-closed too: [`PolicyVerdict::EvalError`],
    /// never `Compliant`.
    pub fn evaluate_bundle_str(&self, bundle: &str, input: &str) -> PolicyVerdict {
        let doc = match self.parse_input(input) {
            Ok(doc) => doc,
            Err(verdict) => return verdict,
        };
        match self.compiled.iter().find(|b| b.name == bundle) {
            Some(compiled) => eval_compiled(compiled, &doc),
            None if self.failed.iter().any(|f| f == bundle) => {
                PolicyVerdict::EvalError(format!("bundle {bundle} failed to compile (fail-closed)"))
            }
            None => PolicyVerdict::EvalError(format!("unknown bundle: {bundle}")),
        }
    }

    /// Evaluate every loaded bundle against a JSON input document (raw
    /// text), returning one verdict per bundle in load order.
    pub fn evaluate_all_str(&self, input: &str) -> Vec<(String, PolicyVerdict)> {
        let doc = match self.parse_input(input) {
            Ok(doc) => doc,
            Err(verdict) => {
                return self
                    .compiled
                    .iter()
                    .map(|b| (b.name.clone(), verdict.clone()))
                    .collect();
            }
        };
        self.compiled
            .iter()
            .map(|b| (b.name.clone(), eval_compiled(b, &doc)))
            .collect()
    }

    /// Evaluate every loaded bundle against a JSON input document (raw
    /// text), aggregating to a single fail-closed verdict: one bad bundle
    /// fails the whole evaluation.
    pub fn evaluate_str(&self, input: &str) -> PolicyVerdict {
        let doc = match self.parse_input(input) {
            Ok(doc) => doc,
            Err(verdict) => return verdict,
        };
        let mut violations: Vec<Violation> = Vec::new();
        for bundle in &self.compiled {
            match eval_compiled(bundle, &doc) {
                PolicyVerdict::Compliant => {}
                PolicyVerdict::Violations(mut found) => violations.append(&mut found),
                PolicyVerdict::EvalError(message) => {
                    return PolicyVerdict::EvalError(format!("{message} (bundle {})", bundle.name));
                }
            }
        }
        verdict_from_violations(violations)
    }

    /// Evaluate one named bundle against a JSON input document.
    #[cfg(feature = "json")]
    pub fn evaluate_bundle(&self, bundle: &str, input: &serde_json::Value) -> PolicyVerdict {
        self.evaluate_bundle_str(bundle, &input.to_string())
    }

    /// Evaluate every loaded bundle against a JSON input document, returning
    /// one verdict per bundle in load order.
    #[cfg(feature = "json")]
    pub fn evaluate_all(&self, input: &serde_json::Value) -> Vec<(String, PolicyVerdict)> {
        self.evaluate_all_str(&input.to_string())
    }

    /// Evaluate every loaded bundle against a JSON input document,
    /// aggregating to a single fail-closed verdict: one bad bundle fails the
    /// whole evaluation.
    #[cfg(feature = "json")]
    pub fn evaluate(&self, input: &serde_json::Value) -> PolicyVerdict {
        self.evaluate_str(&input.to_string())
    }

    /// Parse an input document, strip null fields, and enforce the
    /// fail-closed compile gate.
    fn parse_input(&self, input: &str) -> Result<Value, PolicyVerdict> {
        if self.is_poisoned() {
            return Err(PolicyVerdict::EvalError(format!(
                "fail-closed: bundle(s) failed to compile: {}",
                self.failed.join(", ")
            )));
        }
        let value = Value::from_json_str(input)
            .map_err(|e| PolicyVerdict::EvalError(format!("invalid input document: {e}")))?;
        Ok(strip_null_fields(&value))
    }
}

// ---------------------------------------------------------------------------
// Engine plumbing (ported from evergreenctl's battle-tested evaluator)
// ---------------------------------------------------------------------------

/// Compile a policy source into an engine, auto-detecting Rego dialect.
///
/// regorus defaults to Rego v1, where `deny[msg] { ... }` (no `if` keyword)
/// is a parse error; legacy bundles use v0 syntax while modern bundles use
/// `import rego.v1`. Try v1 first, then retry v0 — the two dialects are
/// mutually exclusive at parse time.
fn compile_engine(policy_path: &str, rego_code: &str) -> Result<regorus::Engine, String> {
    let mut engine = regorus::Engine::new();
    if engine
        .add_policy(policy_path.to_string(), rego_code.to_string())
        .is_ok()
    {
        engine.set_strict_builtin_errors(true);
        return Ok(engine);
    }

    let mut engine = regorus::Engine::new();
    engine.set_rego_v0(true);
    engine
        .add_policy(policy_path.to_string(), rego_code.to_string())
        .map_err(|e| format!("failed to compile policy: {e}"))?;
    engine.set_strict_builtin_errors(true);
    Ok(engine)
}

/// Evaluate one compiled bundle against the input document.
fn eval_compiled(bundle: &CompiledBundle, input: &Value) -> PolicyVerdict {
    let mut engine = bundle.engine.clone();
    engine.set_input(input.clone());
    // Strict builtin errors are set at compile time and inherited by the
    // clone: a failing builtin (e.g. an invalid regex) is an EvalError,
    // never a silently-skipped expression.

    let results = match engine.eval_query("data".to_string(), false) {
        Ok(results) => results,
        Err(e) => return PolicyVerdict::EvalError(format!("evaluation failed: {e}")),
    };

    let value = match results.result.first().and_then(|r| r.expressions.first()) {
        Some(expression) => expression.value.clone(),
        None => {
            return PolicyVerdict::EvalError("evaluation returned no expressions".to_string());
        }
    };

    let mut messages = Vec::new();
    collect_rule_outputs(&value, &mut messages);
    verdict_from_messages(&bundle.name, messages)
}

/// Recursively collect `deny`/`warn` values from a data document.
///
/// Rules live in arbitrary packages, so walk the whole document instead of
/// hard-coding package names.
fn collect_rule_outputs(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, val) in map.iter() {
                if is_deny_or_warn(key) {
                    append_rule_output(val, out);
                }
                collect_rule_outputs(val, out);
            }
        }
        Value::Array(items) => {
            for item in items.iter() {
                collect_rule_outputs(item, out);
            }
        }
        Value::Set(items) => {
            for item in items.iter() {
                collect_rule_outputs(item, out);
            }
        }
        _ => {}
    }
}

/// True if the object key is a `deny` or `warn` rule output.
fn is_deny_or_warn(key: &Value) -> bool {
    match key {
        Value::String(s) => s.as_ref() == "deny" || s.as_ref() == "warn",
        _ => false,
    }
}

/// Extract violation messages from one rule's output document.
fn append_rule_output(value: &Value, out: &mut Vec<String>) {
    match value {
        // `default deny = false` that never fired — not a violation.
        Value::Bool(false) | Value::Null | Value::Undefined => {}
        Value::Bool(true) => out.push("rule fired".to_string()),
        Value::String(message) => out.push(message.to_string()),
        // Sets and multi-value rules serialize as arrays...
        Value::Array(items) => {
            for item in items.iter() {
                append_rule_output(item, out);
            }
        }
        Value::Set(items) => {
            for item in items.iter() {
                append_rule_output(item, out);
            }
        }
        Value::Object(map) => {
            // ...but regorus serializes a v1 `deny[msg] if { ... }` partial
            // set as `{msg: true}` (the keys are the messages), while v0
            // bundles and `deny contains msg if` produce string arrays.
            // Accept both shapes: a boolean-`true` value means the key IS
            // the message; anything else is a nested document to recurse
            // into.
            for (key, val) in map.iter() {
                if val == &Value::Bool(true) {
                    out.push(key_to_message(key));
                } else {
                    append_rule_output(val, out);
                }
            }
        }
        other => out.push(value_to_string(other)),
    }
}

/// Stringify an object key for the `{msg: true}` map form.
fn key_to_message(key: &Value) -> String {
    match key {
        Value::String(s) => s.to_string(),
        other => value_to_string(other),
    }
}

/// Fallback stringification for non-string rule outputs (numbers, …).
fn value_to_string(value: &Value) -> String {
    match value.to_json_str() {
        Ok(json) => json,
        Err(_) => format!("{value:?}"),
    }
}

/// Build the verdict from collected messages: sorted, deduped, tagged with
/// the bundle name.
fn verdict_from_messages(rule: &str, mut messages: Vec<String>) -> PolicyVerdict {
    if messages.is_empty() {
        return PolicyVerdict::Compliant;
    }
    messages.sort();
    messages.dedup();
    PolicyVerdict::Violations(
        messages
            .into_iter()
            .map(|message| Violation {
                rule: rule.to_string(),
                message,
            })
            .collect(),
    )
}

/// Sort + dedup aggregated violations (bundle name, then message).
fn verdict_from_violations(mut violations: Vec<Violation>) -> PolicyVerdict {
    if violations.is_empty() {
        return PolicyVerdict::Compliant;
    }
    violations.sort();
    violations.dedup();
    PolicyVerdict::Violations(violations)
}

/// Strip `null` fields from the input document, recursively.
///
/// A JSON `null` is a *defined* value in Rego, so `not input.sbom` would be
/// false for a serialized `null` field and the rule would silently never
/// fire. Object fields whose value is `null` are removed entirely; null
/// *array elements* are kept (removing them would shift Rego array indices),
/// but objects inside arrays are stripped recursively.
fn strip_null_fields(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let kept: Object = map
                .iter()
                .filter_map(|(key, val)| match val {
                    Value::Null => None,
                    val => Some((key.clone(), strip_null_fields(val))),
                })
                .collect();
            Value::Object(kept.into())
        }
        Value::Array(items) => {
            let stripped: Vec<Value> = items
                .iter()
                .map(|item| match item {
                    Value::Null => Value::Null,
                    item => strip_null_fields(item),
                })
                .collect();
            Value::Array(Array::from(stripped).into())
        }
        Value::Set(items) => {
            let stripped: Set = items.iter().map(strip_null_fields).collect();
            Value::Set(stripped.into())
        }
        other => other.clone(),
    }
}
