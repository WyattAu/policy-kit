//! Fail-closed Rego policy evaluation for Rust.
//!
//! `policy-kit` wraps Microsoft's [regorus] OPA-compatible Rego engine with
//! the estate's battle-tested evaluation semantics (proven on 654 images in
//! the Evergreen Image Registry): **a policy that cannot compile or evaluate
//! is a typed error, never a silent pass.**
//!
//! - **Bundles, not plumbing** — load named [`PolicyBundle`]s of Rego source;
//!   compile errors surface as [`PolicyError::CompileFailed`] *and* poison
//!   the engine, so a broken bundle can never degrade into a compliant
//!   verdict.
//! - **Dialect auto-detect** — Rego v0 (`deny[msg] { … }`) and v1
//!   (`import rego.v1`, `deny contains msg if`) bundles both evaluate; the
//!   v1 partial-set `{msg: true}` map shape and the v0 string-array shape
//!   are both collected as violations.
//! - **Typed verdicts** — [`PolicyVerdict`] is `Compliant`,
//!   `Violations(Vec<Violation>)`, or `EvalError(String)`. One bad rule
//!   fails the whole bundle; one bad bundle fails the whole evaluation.
//! - **Null-safe inputs** — `null` fields are stripped from the input
//!   document before evaluation: in Rego, `null` is a *defined* value and
//!   would defeat `not input.x` guards.
//! - **Domain-agnostic** — the input is an arbitrary JSON document. The
//!   crate never looks inside it: Dockerfile rules, deployment-manifest
//!   rules, anything Rego can express.
//!
//! # Example
//!
//! ```
//! use policy_kit::{PolicyBundle, PolicyEngine, PolicyVerdict};
//!
//! let mut engine = PolicyEngine::new();
//! let loaded = engine.add_bundle(PolicyBundle::new(
//!     "digest-pinning",
//!     r#"
//!     package examples.supply_chain
//!
//!     deny contains msg if {
//!         some repo in input.images
//!         not contains(repo.reference, "@sha256:")
//!         msg := sprintf("image %s is not digest-pinned", [repo.name])
//!     }
//!     "#,
//! ));
//! assert!(loaded.is_ok());
//!
//! let verdict = engine.evaluate_str(r#"
//!     {"images": [{"name": "nginx", "reference": "nginx:1.27"}]}
//! "#);
//!
//! match &verdict {
//!     PolicyVerdict::Violations(violations) => {
//!         assert_eq!(violations[0].rule, "digest-pinning");
//!         assert!(violations[0].message.contains("nginx"));
//!     }
//!     other => panic!("expected violations, got {other:?}"),
//! }
//! ```
//!
//! # Evaluating a typed document (feature `json`)
//!
//! With the default `json` feature, `evaluate` accepts any
//! `serde_json::Value` — serialize your own input types with serde:
//!
//! ```rust
//! # #[cfg(feature = "json")]
//! # {
//! use policy_kit::{PolicyBundle, PolicyEngine, PolicyVerdict};
//!
//! let mut engine = PolicyEngine::new();
//! engine
//!     .add_bundle(PolicyBundle::new(
//!         "no-latest",
//!         r#"
//!         package examples.tags
//!
//!         deny contains msg if {
//!             endswith(input.image, ":latest")
//!             msg := "floating :latest tag is not allowed"
//!         }
//!         "#,
//!     ))
//!     .map_err(|e| e.to_string())
//!     .unwrap_or_else(|e| panic!("{e}"));
//!
//! let input: serde_json::Value = serde_json::json!({ "image": "nginx:latest" });
//! let verdict = engine.evaluate(&input);
//! assert!(matches!(verdict, PolicyVerdict::Violations(_)));
//! # }
//! ```
//!
//! Without the feature, evaluate from raw `&str` JSON via
//! [`PolicyEngine::evaluate_str`] — no serde in your tree at all.
//!
//! # Feature table
//!
//! | Feature  | Default | Effect                                                       |
//! |----------|---------|--------------------------------------------------------------|
//! | `json`   | ✅      | `evaluate(&serde_json::Value)` inputs, serde on verdict types |
//!
//! [regorus]: https://github.com/microsoft/regorus

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod bundle;
mod engine;
mod error;
mod verdict;

pub use bundle::PolicyBundle;
pub use engine::PolicyEngine;
pub use error::PolicyError;
pub use verdict::{PolicyVerdict, Violation};
