//! Both Rego dialects evaluate, and both violation output shapes are
//! collected: the v0 `deny[msg]` string-array form and the v1 bracket /
//! partial-set `{msg: true}` map form.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use policy_kit::{PolicyBundle, PolicyEngine, PolicyVerdict};

fn eval_single(name: &str, rego: &str, input: &str) -> PolicyVerdict {
    let mut engine = PolicyEngine::new();
    engine
        .add_bundle(PolicyBundle::new(name, rego))
        .map_err(|e| e.to_string())
        .unwrap_or_else(|e| panic!("{e}"));
    engine.evaluate_bundle_str(name, input)
}

#[test]
fn test_v0_dialect_evaluate() {
    // v0 syntax: no `if` keyword, `deny[msg]` multi-value rule.
    let verdict = eval_single(
        "v0",
        r#"
        package test.v0

        deny[msg] {
            contains(input.image, ":latest")
            msg := "v0 fired"
        }
        "#,
        r#"{"image": "nginx:latest"}"#,
    );
    let violations = verdict
        .violations()
        .unwrap_or_else(|| panic!("v0 dialect should evaluate: {verdict:?}"));
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].message, "v0 fired");
    assert_eq!(violations[0].rule, "v0");
}

#[test]
fn test_v1_bracket_if_form_evaluate() {
    // v1 syntax: `import rego.v1` + `deny[msg] if { ... }`.
    let verdict = eval_single(
        "v1-bracket",
        r#"
        package test.v1_bracket

        import rego.v1

        deny[msg] if {
            contains(input.image, ":latest")
            msg := "v1 bracket fired"
        }
        "#,
        r#"{"image": "nginx:latest"}"#,
    );
    let violations = verdict
        .violations()
        .unwrap_or_else(|| panic!("v1 bracket form should evaluate: {verdict:?}"));
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].message, "v1 bracket fired");
}

#[test]
fn test_v1_contains_form_evaluate() {
    // v1 syntax: `deny contains msg if { ... }`.
    let verdict = eval_single(
        "v1-contains",
        r#"
        package test.v1_contains

        deny contains msg if {
            contains(input.image, ":latest")
            msg := "v1 contains fired"
        }
        "#,
        r#"{"image": "nginx:latest"}"#,
    );
    let violations = verdict
        .violations()
        .unwrap_or_else(|| panic!("v1 contains form should evaluate: {verdict:?}"));
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].message, "v1 contains fired");
}

#[test]
fn test_default_deny_false_that_never_fires_is_not_a_violation() {
    // `default deny = false` + a `deny[msg]` that doesn't fire must yield
    // Compliant — the boolean false is not collected ("rule fired" would be
    // wrong), and neither is the unfired partial set.
    let verdict = eval_single(
        "default-deny",
        r#"
        package test.default_deny

        default deny = false

        deny[msg] {
            contains(input.image, ":latest")
            msg := "floating tag"
        }
        "#,
        r#"{"image": "nginx:1.27"}"#,
    );
    assert_eq!(verdict, PolicyVerdict::Compliant);
}

#[test]
fn test_default_deny_false_composes_with_firing_rule() {
    let verdict = eval_single(
        "default-deny-fires",
        r#"
        package test.default_deny_fires

        default deny = false

        deny[msg] {
            contains(input.image, ":latest")
            msg := "floating tag"
        }
        "#,
        r#"{"image": "nginx:latest"}"#,
    );
    let violations = verdict
        .violations()
        .unwrap_or_else(|| panic!("firing rule must be collected: {verdict:?}"));
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].message, "floating tag");
}

#[test]
fn test_bare_boolean_deny_true_reports_rule_fired() {
    // A boolean `deny` rule with no message binding: the v1 shorthand
    // `deny if { ... }`. Reported as a violation with a placeholder message.
    let verdict = eval_single(
        "bool-deny",
        r#"
        package test.bool_deny

        import rego.v1

        deny if input.image
        "#,
        r#"{"image": "nginx:latest"}"#,
    );
    let violations = verdict
        .violations()
        .unwrap_or_else(|| panic!("boolean deny should be collected: {verdict:?}"));
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].message, "rule fired");
}

#[test]
fn test_dialects_coexist_across_bundles() {
    // v0 and v1 bundles load into one engine and evaluate independently.
    let mut engine = PolicyEngine::new();
    engine
        .add_bundle(PolicyBundle::new(
            "v0-bundle",
            r#"
            package test.mix.v0

            deny[msg] {
                input.image
                msg := "from v0"
            }
            "#,
        ))
        .map_err(|e| e.to_string())
        .unwrap_or_else(|e| panic!("{e}"));
    engine
        .add_bundle(PolicyBundle::new(
            "v1-bundle",
            r#"
            package test.mix.v1

            deny contains msg if {
                input.image
                msg := "from v1"
            }
            "#,
        ))
        .map_err(|e| e.to_string())
        .unwrap_or_else(|e| panic!("{e}"));

    let verdict = engine.evaluate_str(r#"{"image": "nginx"}"#);
    let violations = verdict
        .violations()
        .unwrap_or_else(|| panic!("both dialects must fire: {verdict:?}"));
    assert_eq!(violations.len(), 2);
    assert!(
        violations.iter().any(|v| v.message == "from v0"),
        "v0 violation collected: {violations:?}"
    );
    assert!(
        violations.iter().any(|v| v.message == "from v1"),
        "v1 violation collected: {violations:?}"
    );
}

#[test]
fn test_violations_are_deduped_and_sorted() {
    let verdict = eval_single(
        "dedup",
        r#"
        package test.dedup

        deny contains msg if { msg := "b" }
        deny contains msg if { msg := "a" }
        deny contains msg if { msg := "a" }
        "#,
        r#"{"x": true}"#,
    );
    let violations = verdict
        .violations()
        .unwrap_or_else(|| panic!("violations expected: {verdict:?}"));
    let messages: Vec<&str> = violations.iter().map(|v| v.message.as_str()).collect();
    assert_eq!(messages, vec!["a", "b"], "sorted and deduped");
}
