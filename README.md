# policy-kit

Fail-closed Rego policy evaluation for Rust — bundle loading, v0/v1 dialect
auto-detect, typed verdicts. The estate's policy engine: **a policy that
cannot compile or evaluate is a typed error, never a silent pass.** Built on
Microsoft's [regorus] OPA-compatible Rego engine; semantics proven on 654
images in the Evergreen Image Registry.

[regorus]: https://github.com/microsoft/regorus

- **Typed verdicts**: [`PolicyVerdict`] is `Compliant`,
  `Violations(Vec<Violation>)`, or `EvalError(String)`. `EvalError` means
  "unknown" — gate deploys on `is_compliant()`, which errors never satisfy.
- **Fail-closed loading**: a bundle that fails to compile returns
  [`PolicyError::CompileFailed`] *and* poisons the engine — even if the
  error is ignored, every later evaluation fails closed.
- **Fail-closed aggregation**: one bad rule fails the bundle; one bad
  bundle fails the whole evaluation. Partially-evaluated policy sets are
  never reported as compliant.
- **Dialect auto-detect**: Rego v0 (`deny[msg] { … }`) and v1
  (`import rego.v1`, `deny contains msg if`) both load; the v1 partial-set
  `{msg: true}` map shape and the v0 string-array shape are both collected.
- **Null-safe inputs**: `null` fields are stripped from the input document
  before evaluation — in Rego, `null` is a *defined* value and would defeat
  `not input.x` guards.
- **Strict builtin errors**: a builtin failing at runtime (an
  RE2-incompatible regex, say) surfaces as `EvalError`, never as a skipped
  expression.
- **Domain-agnostic**: the input is an arbitrary JSON document. policy-kit
  never looks inside it — Dockerfile rules, deployment-manifest rules,
  anything Rego can express. (The Dockerfile-specific rule bundles live
  with their consumer, `evergreenctl`.)
- **`#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`**, clippy
  `unwrap_used`/`expect_used`/`panic`/`indexing_slicing` denied.

[`PolicyVerdict`]: https://docs.rs/policy-kit/latest/policy_kit/enum.PolicyVerdict.html
[`PolicyError::CompileFailed`]: https://docs.rs/policy-kit/latest/policy_kit/enum.PolicyError.html

## Install

```toml
[dependencies]
policy-kit = "0.1"
```

## Example

```rust
use policy_kit::{PolicyBundle, PolicyEngine, PolicyVerdict};

let mut engine = PolicyEngine::new();
let loaded = engine.add_bundle(PolicyBundle::new(
    "digest-pinning",
    r#"
    package examples.supply_chain

    deny contains msg if {
        some repo in input.images
        not contains(repo.reference, "@sha256:")
        msg := sprintf("image %s is not digest-pinned", [repo.name])
    }
    "#,
));
assert!(loaded.is_ok());

let verdict = engine.evaluate_str(r#"
    {"images": [{"name": "nginx", "reference": "nginx:1.27"}]}
"#);

match &verdict {
    PolicyVerdict::Violations(violations) => {
        assert_eq!(violations[0].rule, "digest-pinning");
        assert!(violations[0].message.contains("nginx"));
    }
    other => panic!("expected violations, got {other:?}"),
}
```

With the default `json` feature, `evaluate` accepts any `serde_json::Value`
— serialize your own input types with serde. Without it, evaluate from raw
`&str` JSON via `evaluate_str` and no serde reaches your tree.

Evaluate one bundle at a time (`evaluate_bundle_str`) or get per-bundle
verdicts in load order (`evaluate_all_str`).

## Feature table

| Feature | Default | Effect                                                        |
|---------|---------|---------------------------------------------------------------|
| `json`  | ✅      | `evaluate(&serde_json::Value)` inputs; serde on verdict types |

## Performance

Compile happens once per bundle at `add_bundle`; evaluation clones the
compiled engine (order of magnitude cheaper than recompiling — see
`benches/eval_bench.rs`, `evaluate_cached_engine` vs
`evaluate_fresh_compile`).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
