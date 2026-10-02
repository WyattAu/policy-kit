//! Typed errors. Fail-closed by construction: [`PolicyError::CompileFailed`]
//! is returned at load time *and* poisons the engine, so a broken bundle can
//! never degrade into a silent pass.

use std::fmt;

/// Errors raised while loading a policy bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// The bundle's Rego source failed to compile (parse or compile error).
    ///
    /// Fail-closed: besides being returned, the failure is recorded by the
    /// [`PolicyEngine`](crate::PolicyEngine) — every subsequent evaluation on
    /// that engine reports a fail-closed
    /// [`PolicyVerdict::EvalError`](crate::PolicyVerdict::EvalError) even if
    /// the returned error was ignored.
    CompileFailed {
        /// The name of the bundle that failed to compile.
        bundle: String,
        /// The underlying compiler diagnostic.
        detail: String,
    },
}

impl PolicyError {
    /// The name of the bundle that failed to compile, if applicable.
    pub fn bundle(&self) -> Option<&str> {
        match self {
            PolicyError::CompileFailed { bundle, .. } => Some(bundle),
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::CompileFailed { bundle, detail } => {
                write!(f, "bundle \"{bundle}\" failed to compile: {detail}")
            }
        }
    }
}

impl std::error::Error for PolicyError {}
