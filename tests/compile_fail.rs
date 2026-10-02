//! Compile-failure is typed, load-time, and fail-closed: a bundle that
//! cannot compile must never degrade into a compliant verdict.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use policy_kit::{PolicyBundle, PolicyEngine, PolicyError, PolicyVerdict};

const BROKEN: &str = r#"
package broken

deny[msg] {
    input.x
    msg := "this never compiles"  # v0 syntax missing `if` AND unbalanced:
"#;

const GOOD: &str = r#"
package good

deny contains msg if {
    input.x
    msg := "x is present"
}
"#;

#[test]
fn test_compile_error_is_typed() {
    let mut engine = PolicyEngine::new();
    let err = engine
        .add_bundle(PolicyBundle::new("broken", BROKEN))
        .expect_err("broken bundle must fail to compile");

    match &err {
        PolicyError::CompileFailed { bundle, detail } => {
            assert_eq!(bundle, "broken");
            assert!(!detail.is_empty(), "diagnostic must be preserved");
        }
    }
    assert_eq!(err.bundle(), Some("broken"));
    assert!(err.to_string().contains("broken"));
}

#[test]
fn test_failed_bundle_poisons_evaluation_even_if_error_ignored() {
    let mut engine = PolicyEngine::new();
    // The error is deliberately ignored — the engine must still fail closed.
    let _ = engine.add_bundle(PolicyBundle::new("broken", BROKEN));

    let verdict = engine.evaluate_str(r#"{"x": true}"#);
    assert!(
        matches!(&verdict, PolicyVerdict::EvalError(m) if m.contains("broken")),
        "ignored compile error must still fail closed: {verdict:?}"
    );
    assert!(engine.is_poisoned());
}

#[test]
fn test_good_bundle_alongside_failed_bundle_fails_closed() {
    let mut engine = PolicyEngine::new();
    assert!(engine.add_bundle(PolicyBundle::new("good", GOOD)).is_ok());
    let _ = engine.add_bundle(PolicyBundle::new("broken", BROKEN));

    // The good bundle alone would be Compliant on this input's complement;
    // the poisoned engine must not report compliance for anything.
    let verdict = engine.evaluate_str(r#"{"y": true}"#);
    assert!(verdict.is_eval_error(), "must fail closed: {verdict:?}");

    let per_bundle = engine.evaluate_all_str(r#"{"y": true}"#);
    assert!(
        per_bundle.iter().all(|(_, v)| v.is_eval_error()),
        "every verdict on a poisoned engine is fail-closed: {per_bundle:?}"
    );
}

#[test]
fn test_evaluating_a_failed_bundle_by_name_is_fail_closed() {
    let mut engine = PolicyEngine::new();
    let _ = engine.add_bundle(PolicyBundle::new("broken", BROKEN));

    let verdict = engine.evaluate_bundle_str("broken", r#"{"x": true}"#);
    assert!(
        matches!(&verdict, PolicyVerdict::EvalError(m) if m.contains("failed to compile")),
        "naming the failed bundle must report the compile failure: {verdict:?}"
    );
}

#[test]
fn test_good_bundle_still_loads_after_failure() {
    let mut engine = PolicyEngine::new();
    let _ = engine.add_bundle(PolicyBundle::new("broken", BROKEN));
    let second = engine.add_bundle(PolicyBundle::new("good", GOOD));
    assert!(
        second.is_ok(),
        "loading continues after a failure; the poison flag handles fail-closure"
    );
}

#[test]
fn test_engine_starts_unpoisoned_and_empty() {
    let engine = PolicyEngine::new();
    assert!(!engine.is_poisoned());
    assert_eq!(engine.bundle_names().count(), 0);
}

#[test]
fn test_add_bundles_loads_in_order_and_names_report() {
    let mut engine = PolicyEngine::new();
    let loaded = engine.add_bundles([
        PolicyBundle::new("first", GOOD),
        PolicyBundle::new("second", GOOD),
    ]);
    assert!(loaded.is_ok());
    let names: Vec<&str> = engine.bundle_names().collect();
    assert_eq!(names, vec!["first", "second"]);

    let verdict = engine.evaluate_str(r#"{"x": true}"#);
    let violations = verdict.violations().expect("both bundles fire");
    assert_eq!(violations.len(), 2);
}

#[test]
fn test_add_bundles_stops_at_first_failure_and_records_it() {
    let mut engine = PolicyEngine::new();
    let loaded = engine.add_bundles([
        PolicyBundle::new("broken", BROKEN),
        PolicyBundle::new("good", GOOD),
    ]);
    assert!(loaded.is_err(), "the broken bundle's error propagates");
    assert!(engine.is_poisoned());
    // The engine is fail-closed even though "good" also loaded.
    assert!(engine.evaluate_str(r#"{"x": true}"#).is_eval_error());
}
