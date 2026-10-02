//! Criterion benches: compiled-engine reuse vs fresh compile per evaluation.
//!
//! The engine compiles each bundle once at `add_bundle` and clones the
//! compiled regorus engine per evaluation; the "fresh compile" arm rebuilds
//! the engine from source on every call. Targets: cached evaluation in the
//! low-microseconds class, compile an order of magnitude (or more) above it.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use criterion::{criterion_group, criterion_main, Criterion};
use policy_kit::{PolicyBundle, PolicyEngine};

const BUNDLE: &str = r#"
package bench.supply_chain

deny contains msg if {
    some repo in input.images
    not contains(repo.reference, "@sha256:")
    msg := sprintf("image %s is not digest-pinned", [repo.name])
}

deny contains msg if {
    some repo in input.images
    endswith(repo.reference, ":latest")
    msg := sprintf("image %s uses the floating :latest tag", [repo.name])
}
"#;

const INPUT: &str = r#"
{"images": [
    {"name": "nginx", "reference": "nginx:1.27"},
    {"name": "redis", "reference": "redis:7@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"name": "postgres", "reference": "postgres:latest"},
    {"name": "caddy", "reference": "caddy:2@sha256:cafea42f8b2f789ea6e6f5a1b0becbd2a5d0d3d1ba1a0f8f8e1a9a4b0e1c2d3f"}
]}
"#;

/// Evaluation on a pre-compiled engine (the `PolicyEngine` steady state):
/// compile happens once at `add_bundle`, outside the measured loop.
fn bench_compile_cached(c: &mut Criterion) {
    let mut engine = PolicyEngine::new();
    engine
        .add_bundle(PolicyBundle::new("supply-chain", BUNDLE))
        .expect("bench bundle compiles");

    c.bench_function("evaluate_cached_engine", |b| {
        b.iter(|| engine.evaluate_str(INPUT))
    });
}

/// Fresh compile per evaluation (what naive integrators do: rebuild the
/// engine for every input). Compiled-engine reuse should dominate.
fn bench_compile_fresh(c: &mut Criterion) {
    c.bench_function("evaluate_fresh_compile", |b| {
        b.iter(|| {
            let mut engine = PolicyEngine::new();
            let loaded = engine.add_bundle(PolicyBundle::new("supply-chain", BUNDLE));
            debug_assert!(loaded.is_ok());
            engine.evaluate_str(INPUT)
        })
    });
}

criterion_group!(benches, bench_compile_cached, bench_compile_fresh);
criterion_main!(benches);
