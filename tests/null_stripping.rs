//! Null-stripping: a JSON `null` is a *defined* value in Rego, so `None`
//! input fields are stripped before evaluation — `not input.x` must fire
//! for a stripped field, at any nesting depth.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use policy_kit::{PolicyBundle, PolicyEngine, PolicyVerdict};

fn guard_bundle(guard: &str) -> PolicyEngine {
    let mut engine = PolicyEngine::new();
    let rego = format!(
        r#"package test.guard

deny contains msg if {{
    {guard}
    msg := "guard condition held"
}}
"#
    );
    engine
        .add_bundle(PolicyBundle::new("guard", rego))
        .map_err(|e| e.to_string())
        .unwrap_or_else(|e| panic!("{e}"));
    engine
}

#[test]
fn test_null_field_is_stripped_top_level() {
    let engine = guard_bundle("not input.sbom");
    // "sbom": null would be defined in Rego and defeat `not input.sbom`.
    let verdict = engine.evaluate_str(r#"{"image": "nginx", "sbom": null}"#);
    let violations = verdict
        .violations()
        .unwrap_or_else(|| panic!("stripped field must let the guard fire: {verdict:?}"));
    assert_eq!(violations[0].message, "guard condition held");
}

#[test]
fn test_present_field_keeps_guard_quiet() {
    let engine = guard_bundle("not input.sbom");
    let verdict = engine.evaluate_str(r#"{"image": "nginx", "sbom": {"format": "spdx"}}"#);
    assert_eq!(verdict, PolicyVerdict::Compliant);
}

#[test]
fn test_absent_field_behaves_like_stripped_null() {
    let engine = guard_bundle("not input.sbom");
    let verdict = engine.evaluate_str(r#"{"image": "nginx"}"#);
    assert!(!verdict.is_compliant(), "absent == stripped");
}

#[test]
fn test_nested_null_field_is_stripped() {
    let engine = guard_bundle("not input.spec.security_context");
    let verdict = engine.evaluate_str(r#"{"spec": {"security_context": null, "replicas": 2}}"#);
    assert!(
        !verdict.is_compliant(),
        "nested null must be stripped too: {verdict:?}"
    );
}

#[test]
fn test_null_inside_array_element_object_is_stripped() {
    let engine = guard_bundle("some c in input.containers; not c.resources");
    let verdict = engine.evaluate_str(
        r#"{"containers": [
            {"name": "app", "resources": null},
            {"name": "sidecar", "resources": {"limits": {"memory": "64Mi"}}}
        ]}"#,
    );
    // Only the first container's null `resources` is stripped -> fires once.
    let violations = verdict
        .violations()
        .unwrap_or_else(|| panic!("array-object null must be stripped: {verdict:?}"));
    assert_eq!(violations.len(), 1);
}

#[test]
fn test_null_array_elements_preserve_array_shape() {
    // Null array ELEMENTS are kept: dropping them would shift Rego indices.
    let engine = guard_bundle(r#"input.items[1] == "second""#);
    let verdict = engine.evaluate_str(r#"{"items": ["first", null, "second"]}"#);

    // `input.items[1]` is null (defined), so the guard `== "second"` is
    // false and nothing fires. The point of this test is that evaluation
    // does not panic and indexing is unchanged; with element-dropping,
    // items[1] would be "second" and the rule would fire.
    assert_eq!(verdict, PolicyVerdict::Compliant);
}

#[test]
fn test_empty_object_remains_defined() {
    let engine = guard_bundle("not input.sbom");
    let verdict = engine.evaluate_str(r#"{"sbom": {}}"#);
    // An empty object is defined — stripping nulls must not erase it.
    assert_eq!(verdict, PolicyVerdict::Compliant);
}

#[test]
fn test_non_null_sibling_fields_untouched() {
    // The guard holds only if `input.image` survived stripping intact while
    // its null sibling was removed.
    let engine = guard_bundle(r#"input.image == "nginx:1.27""#);
    let verdict = engine.evaluate_str(r#"{"image": "nginx:1.27", "tier": null}"#);
    let violations = verdict
        .violations()
        .unwrap_or_else(|| panic!("sibling field must survive stripping: {verdict:?}"));
    assert_eq!(violations[0].message, "guard condition held");
}

#[cfg(feature = "json")]
#[test]
fn test_typed_input_with_nulls_is_stripped() {
    // The serde path: `Option<T>::None` serializes to null, policy-kit
    // strips it before evaluation.
    let input = serde_json::json!({
        "image": "nginx",
        "sbom": Option::<serde_json::Value>::None,
    });
    let engine = guard_bundle("not input.sbom");
    let verdict = engine.evaluate(&input);
    assert!(
        !verdict.is_compliant(),
        "serialized None must behave like a stripped field: {verdict:?}"
    );
}
