//! A generic, non-container-registry example: evaluate a Kubernetes
//! Deployment manifest against a sample guardrails bundle. This is the
//! domain-agnostic contract — the input is just JSON; policy-kit never
//! knows what a container is.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use policy_kit::{PolicyBundle, PolicyEngine, PolicyVerdict};

const K8S_GUARDRAILS: &str = r#"
package examples.k8s.guardrails

import rego.v1

# Every deployment carries a team label for ownership routing.
deny contains msg if {
    not input.metadata.labels.team
    msg := "deployment must carry a team label"
}

# Every container declares a memory limit.
deny contains msg if {
    some container in input.spec.template.spec.containers
    not container.resources.limits.memory
    msg := sprintf("container %s has no memory limit", [container.name])
}

# No floating :latest tags.
deny contains msg if {
    some container in input.spec.template.spec.containers
    endswith(container.image, ":latest")
    msg := sprintf("container %s uses the floating :latest tag", [container.name])
}
"#;

fn guardrails_engine() -> PolicyEngine {
    let mut engine = PolicyEngine::new();
    engine
        .add_bundle(PolicyBundle::new("k8s-guardrails", K8S_GUARDRAILS))
        .map_err(|e| e.to_string())
        .unwrap_or_else(|e| panic!("{e}"));
    engine
}

fn compliant_deployment() -> &'static str {
    r#"{
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "api",
            "labels": {"team": "platform"}
        },
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "api",
                            "image": "registry.internal/api@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                            "resources": {"limits": {"memory": "512Mi"}}
                        },
                        {
                            "name": "sidecar",
                            "image": "registry.internal/sidecar:1.4.2",
                            "resources": {"limits": {"memory": "64Mi"}}
                        }
                    ]
                }
            }
        }
    }"#
}

#[test]
fn test_compliant_deployment_is_compliant() {
    let engine = guardrails_engine();
    let verdict = engine.evaluate_str(compliant_deployment());
    assert_eq!(verdict, PolicyVerdict::Compliant, "{verdict:?}");
}

#[test]
fn test_violations_carry_rule_and_message() {
    let engine = guardrails_engine();
    let verdict = engine.evaluate_str(
        r#"{
        "metadata": {"name": "api", "labels": {}},
        "spec": {"template": {"spec": {"containers": [
            {"name": "api", "image": "nginx:latest"}
        ]}}}
    }"#,
    );

    let violations = verdict
        .violations()
        .unwrap_or_else(|| panic!("expected violations: {verdict:?}"));
    let messages: Vec<&str> = violations.iter().map(|v| v.message.as_str()).collect();

    assert!(
        messages.iter().any(|m| m.contains("team label")),
        "missing team label fires: {violations:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("no memory limit") && m.contains("api")),
        "missing memory limit fires with the container name: {violations:?}"
    );
    assert!(
        messages.iter().any(|m| m.contains(":latest")),
        "floating tag fires: {violations:?}"
    );
    assert!(
        violations.iter().all(|v| v.rule == "k8s-guardrails"),
        "violations attribute to the bundle: {violations:?}"
    );
}

#[test]
fn test_null_labels_field_behaves_like_missing() {
    // labels.team explicitly null must behave exactly like absent.
    let engine = guardrails_engine();
    let verdict = engine.evaluate_str(
        r#"{"metadata": {"labels": {"team": null}}, "spec": {"template": {"spec": {"containers": []}}}}"#,
    );
    let violations = verdict
        .violations()
        .unwrap_or_else(|| panic!("null label must fire the ownership guard: {verdict:?}"));
    assert!(violations.iter().any(|v| v.message.contains("team label")));
}

#[cfg(feature = "json")]
#[test]
fn test_typed_deployment_evaluation() {
    // The typed path: serialize your own input model with serde.
    use serde_json::json;

    let engine = guardrails_engine();
    let deployment = json!({
        "metadata": {"labels": {"team": "platform"}},
        "spec": {"template": {"spec": {"containers": [
            {"name": "api", "image": "registry.internal/api:2.1.0", "resources": {"limits": {"memory": "512Mi"}}},
        ]}}},
    });
    let verdict = engine.evaluate(&deployment);
    assert_eq!(verdict, PolicyVerdict::Compliant);
}

#[test]
fn test_raw_str_path_matches_json_path() {
    // evaluate_str and evaluate agree on the same document.
    let engine = guardrails_engine();
    let raw = r#"{"metadata": {"labels": {}}, "spec": {"template": {"spec": {"containers": [
        {"name": "api", "image": "nginx:latest"}
    ]}}}}"#;

    let from_str = engine.evaluate_str(raw);
    #[cfg(feature = "json")]
    {
        let typed: serde_json::Value = serde_json::from_str(raw)
            .map_err(|e| e.to_string())
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(from_str, engine.evaluate(&typed));
    }
    #[cfg(not(feature = "json"))]
    {
        assert!(!from_str.is_compliant());
    }
}

#[cfg(feature = "json")]
#[test]
fn test_evaluate_all_and_evaluate_bundle_typed_paths() {
    // The typed counterparts of evaluate_all_str / evaluate_bundle_str.
    let engine = guardrails_engine();
    let input: serde_json::Value = serde_json::from_str(compliant_deployment())
        .map_err(|e| e.to_string())
        .unwrap_or_else(|e| panic!("{e}"));

    let all = engine.evaluate_all(&input);
    let names: Vec<&str> = all.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, vec!["k8s-guardrails"]);
    assert_eq!(all[0].1, PolicyVerdict::Compliant);

    let single = engine.evaluate_bundle("k8s-guardrails", &input);
    assert_eq!(single, PolicyVerdict::Compliant);

    let unknown = engine.evaluate_bundle("missing", &input);
    assert!(unknown.is_eval_error());
}
