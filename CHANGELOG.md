# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [0.1.0] - 2026-10-02

### Added

- **`PolicyEngine`** — fail-closed Rego policy evaluation:
  - `add_bundle` / `add_bundles` compile eagerly; compile errors are typed
    [`PolicyError::CompileFailed { bundle, detail }`] **and poison the
    engine** — even if the returned error is ignored, every subsequent
    evaluation reports `PolicyVerdict::EvalError`. A broken bundle can
    never degrade into a compliant verdict.
  - `evaluate` / `evaluate_str` aggregate every loaded bundle to one
    fail-closed verdict; `evaluate_all` / `evaluate_all_str` return
    per-bundle verdicts in load order; `evaluate_bundle` /
    `evaluate_bundle_str` evaluate one named bundle.
- **Dialect auto-detect** — Rego v1 tried first, v0 as fallback (the
  dialects are mutually exclusive at parse time). Both violation output
  shapes are collected: the v0 `deny[msg]` string-array form and the v1
  `deny contains msg if` / partial-set `{msg: true}` map form (a
  boolean-`true` value means the key is the message). A `default deny =
  false` that never fires is not a violation; a bare boolean `deny if`
  reports `"rule fired"`.
- **Null-stripping** — `null` object fields are stripped from the input
  document before evaluation (deep, including objects inside arrays; null
  array elements are kept so Rego indices don't shift): a JSON `null` is a
  *defined* value in Rego and would defeat `not input.x` guards.
- **Strict builtin errors** — a builtin failing at runtime (e.g. an
  RE2-incompatible regex) surfaces as `PolicyVerdict::EvalError`, never as
  a silently-skipped expression.
- **Typed verdicts** — `PolicyVerdict::{Compliant, Violations, EvalError}`
  with `is_compliant` / `is_eval_error` / `violations` accessors,
  `Display` (`COMPLIANT` / `VIOLATIONS (n)` / `EVAL_ERROR`), and serde
  support under the `json` feature. `Violation { rule, message }` tagged
  with the originating bundle name.
- **`json` feature** (default on) — `evaluate(&serde_json::Value)` inputs
  and serde derives; without it, evaluate from raw `&str` JSON
  (`evaluate_str` family) with no serde in the tree.
- Evaluation semantics ported from the battle-tested `evergreenctl`
  evaluator (regorus-backed, proven on 654 images in the Evergreen Image
  Registry); compiled engines are reused per evaluation via clone.
- Criterion benches: cached compiled engine vs fresh compile per
  evaluation.
