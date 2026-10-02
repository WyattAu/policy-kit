//! Typed verdicts — the aggregate result of evaluating policies against one
//! input document.

/// A single rule violation produced by Rego evaluation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "json", derive(serde::Serialize, serde::Deserialize))]
pub struct Violation {
    /// The rule/bundle that produced the violation (the
    /// [`PolicyBundle::name`](crate::PolicyBundle::name)).
    pub rule: String,
    /// The message produced by the Rego `deny`/`warn` rule.
    pub message: String,
}

/// Verdict of evaluating Rego policy code against an input document.
///
/// Fail-closed: [`EvalError`](PolicyVerdict::EvalError) means "unknown", and
/// callers must never treat it as compliant.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize, serde::Deserialize))]
pub enum PolicyVerdict {
    /// Every rule evaluated and none fired.
    Compliant,
    /// At least one rule fired.
    Violations(Vec<Violation>),
    /// The rules could not be compiled or evaluated. Fail-closed: callers
    /// must treat this as "unknown", never as compliant.
    EvalError(String),
}

impl PolicyVerdict {
    /// True if this verdict is a typed evaluation error.
    pub fn is_eval_error(&self) -> bool {
        matches!(self, PolicyVerdict::EvalError(_))
    }

    /// Violations, if any. `None` for `Compliant` and `EvalError`.
    pub fn violations(&self) -> Option<&[Violation]> {
        match self {
            PolicyVerdict::Violations(v) => Some(v),
            _ => None,
        }
    }

    /// True if every rule evaluated and none fired. An
    /// [`EvalError`](PolicyVerdict::EvalError) is *not* compliant — this is
    /// the fail-closed predicate to gate deploys on.
    pub fn is_compliant(&self) -> bool {
        matches!(self, PolicyVerdict::Compliant)
    }
}

impl std::fmt::Display for PolicyVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyVerdict::Compliant => write!(f, "COMPLIANT"),
            PolicyVerdict::Violations(v) => write!(f, "VIOLATIONS ({})", v.len()),
            PolicyVerdict::EvalError(_) => write!(f, "EVAL_ERROR"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_display_forms() {
        assert_eq!(PolicyVerdict::Compliant.to_string(), "COMPLIANT");
        assert_eq!(
            PolicyVerdict::Violations(vec![Violation {
                rule: "b".to_string(),
                message: "m".to_string(),
            }])
            .to_string(),
            "VIOLATIONS (1)"
        );
        assert_eq!(
            PolicyVerdict::EvalError("x".into()).to_string(),
            "EVAL_ERROR"
        );
    }

    #[test]
    fn test_accessors() {
        assert!(PolicyVerdict::Compliant.is_compliant());
        assert!(!PolicyVerdict::EvalError("x".into()).is_compliant());
        assert!(PolicyVerdict::EvalError("x".into()).is_eval_error());
        assert!(PolicyVerdict::Compliant.violations().is_none());
        let v = PolicyVerdict::Violations(vec![Violation {
            rule: "r".to_string(),
            message: "m".to_string(),
        }]);
        assert_eq!(v.violations().map(|v| v.len()), Some(1));
    }

    #[cfg(feature = "json")]
    #[test]
    fn test_verdict_json_round_trip() {
        let verdict = PolicyVerdict::Violations(vec![Violation {
            rule: "supply-chain".to_string(),
            message: "not digest-pinned".to_string(),
        }]);
        let json = serde_json::to_string(&verdict).expect("serialize");
        let back: PolicyVerdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(verdict, back);
    }
}
