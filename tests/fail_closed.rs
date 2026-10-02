//! Fail-closed aggregation: one bad rule fails the bundle, one bad bundle
//! fails the whole evaluation. A partially-evaluated policy set can never be
//! reported as compliant.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use policy_kit::{PolicyBundle, PolicyEngine, PolicyVerdict};

/// A rule that always fires (its input field is present).
const ALWAYS_FIRES: &str = r#"
package test.good

deny contains msg if {
    input.dockerfile
    msg := "always fires"
}
"#;

/// A rule whose builtin fails at runtime: RE2 cannot compile lookaheads/
/// named-capture alternations, so `regex.match` errors mid-evaluation.
const RUNTIME_BROKEN: &str = r#"
package test.broken

deny contains msg if {
    input.dockerfile
    regex.match("(?P<named>unsupported|lookahead(?!x))", input.dockerfile)
    msg := "unreachable"
}
"#;

fn engine_with(bundles: &[(&str, &str)]) -> PolicyEngine {
    let mut engine = PolicyEngine::new();
    for (name, rego) in bundles {
        engine
            .add_bundle(PolicyBundle::new(*name, *rego))
            .map_err(|e| e.to_string())
            .unwrap_or_else(|e| panic!("{e}"));
    }
    engine
}

#[test]
fn test_runtime_builtin_failure_is_typed_eval_error() {
    let engine = engine_with(&[("broken", RUNTIME_BROKEN)]);
    let verdict = engine.evaluate_bundle_str("broken", r#"{"dockerfile": "FROM scratch"}"#);

    match &verdict {
        PolicyVerdict::EvalError(message) => {
            assert!(!message.is_empty(), "error message must be preserved");
            assert!(
                message.contains("evaluation failed"),
                "strict builtin error surfaces as EvalError: {verdict:?}"
            );
        }
        other => panic!("expected EvalError, got {other:?}"),
    }
}

#[test]
fn test_bundle_eval_error_is_fail_closed() {
    // good + broken in one engine: the aggregated verdict must be
    // EvalError, never partial violations, never compliant.
    let engine = engine_with(&[("good", ALWAYS_FIRES), ("broken", RUNTIME_BROKEN)]);
    let verdict = engine.evaluate_str(r#"{"dockerfile": "FROM scratch"}"#);

    assert!(
        matches!(&verdict, PolicyVerdict::EvalError(m) if m.contains("broken")),
        "aggregate eval must fail closed and name the failing bundle: {verdict:?}"
    );
}

#[test]
fn test_aggregate_reports_all_violations_when_healthy() {
    let engine = engine_with(&[("good", ALWAYS_FIRES), ("other", ALWAYS_FIRES)]);
    let verdict = engine.evaluate_str(r#"{"dockerfile": "FROM scratch"}"#);

    let violations = verdict
        .violations()
        .unwrap_or_else(|| panic!("both bundles fire: {verdict:?}"));
    assert_eq!(violations.len(), 2);
    let rules: Vec<&str> = violations.iter().map(|v| v.rule.as_str()).collect();
    assert_eq!(rules, vec!["good", "other"], "sorted by (rule, message)");
}

#[test]
fn test_unknown_bundle_is_fail_closed() {
    let engine = engine_with(&[("good", ALWAYS_FIRES)]);
    let verdict = engine.evaluate_bundle_str("does-not-exist", r#"{"dockerfile": "x"}"#);
    assert!(
        matches!(&verdict, PolicyVerdict::EvalError(m) if m.contains("does-not-exist")),
        "unknown bundle must be EvalError, never Compliant: {verdict:?}"
    );
}

#[test]
fn test_unparseable_input_is_fail_closed() {
    let engine = engine_with(&[("good", ALWAYS_FIRES)]);
    let verdict = engine.evaluate_str("{not json");
    assert!(
        verdict.is_eval_error(),
        "invalid input document must be EvalError: {verdict:?}"
    );

    // evaluate_all also degrades to fail-closed per bundle.
    let per_bundle = engine.evaluate_all_str("{not json");
    assert_eq!(per_bundle.len(), 1);
    assert!(per_bundle[0].1.is_eval_error());
}

#[test]
fn test_compliant_when_no_rule_fires() {
    let engine = engine_with(&[("good", ALWAYS_FIRES)]);
    let verdict = engine.evaluate_str(r#"{"dockerfile": null}"#);
    // "dockerfile" is stripped (null), so `input.dockerfile` is undefined
    // and the rule does not fire.
    assert_eq!(verdict, PolicyVerdict::Compliant);
}

#[test]
fn test_evaluate_all_preserves_load_order_and_attribution() {
    let engine = engine_with(&[("aaa", ALWAYS_FIRES), ("zzz", ALWAYS_FIRES)]);
    let results = engine.evaluate_all_str(r#"{"dockerfile": "FROM scratch"}"#);

    let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, vec!["aaa", "zzz"], "load order preserved");
    for (name, verdict) in &results {
        let violations = verdict
            .violations()
            .unwrap_or_else(|| panic!("{name} should fire: {verdict:?}"));
        assert!(
            violations.iter().all(|v| v.rule == *name),
            "violations attribute to their own bundle: {violations:?}"
        );
    }
}
