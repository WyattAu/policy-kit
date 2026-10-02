# Security Policy — policy-kit

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a vulnerability

Report privately via [GitHub security advisories] for this repository, or
email **wyatt_au@protonmail.com**. Do **not** open a public issue for
security reports.

You will receive an acknowledgement within **72 hours**. Coordinated
disclosure: we ask for up to 90 days before public disclosure while a
patch ships.

## Scope notes

`policy-kit` evaluates Rego policies with Microsoft's regorus engine
(OPA-compatible). Security considerations for integrators:

- **Policies are code.** A `PolicyBundle`'s `rego_code` executes with the
  full Rego builtin surface. Only load bundles you trust — treat policy
  sources like dependencies, review them, and pin them.
- **Fail-closed is the contract.** Compile failures poison the engine,
  builtin failures surface as `PolicyVerdict::EvalError`, and unknown
  bundle names are `EvalError` — never silent passes. Gate decisions on
  `verdict.is_compliant()`, which an `EvalError` can never satisfy.
- **Inputs are data.** The input document is never executed; it is only
  queried. `null` fields are stripped before evaluation (documented
  behavior) — rules that must distinguish "absent" from "explicitly null"
  cannot be written against this crate.
- **Not a sandbox boundary.** Rego is a declarative query language without
  I/O builtins, but policy-kit makes no isolation guarantees beyond
  regorus's own. Do not evaluate untrusted policy sources.

[GitHub security advisories]: https://github.com/WyattAu/policy-kit/security/advisories/new
