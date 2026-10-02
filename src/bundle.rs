//! Policy bundles — named Rego module sets.

/// A named Rego policy bundle: one or more `deny`/`warn` rules in a single
/// Rego source document (one package).
///
/// A bundle is **domain-agnostic**: the Rego code may inspect any shape of
/// input document. Dockerfile rules, deployment-manifest rules, or anything
/// else are just Rego — policy-kit never looks inside the input.
///
/// # Naming
///
/// The name becomes the Rego module path (`<name>.rego`) and the `rule` tag
/// on every [`Violation`](crate::Violation) the bundle produces, so give it
/// a stable, diagnostic-friendly value (`"supply-chain"`, `"k8s-guardrails"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyBundle {
    /// Bundle name — doubles as the module path stem and the violation
    /// `rule` tag.
    pub name: String,
    /// Rego source for the bundle's rules.
    pub rego_code: String,
}

impl PolicyBundle {
    /// Create a bundle from a name and Rego source.
    ///
    /// ```
    /// use policy_kit::PolicyBundle;
    ///
    /// let bundle = PolicyBundle::new(
    ///     "no-latest",
    ///     r#"
    ///     package examples.tags
    ///
    ///     deny contains msg if {
    ///         endswith(input.image, ":latest")
    ///         msg := "floating :latest tag is not allowed"
    ///     }
    ///     "#,
    /// );
    /// assert_eq!(bundle.name, "no-latest");
    /// ```
    pub fn new(name: impl Into<String>, rego_code: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            rego_code: rego_code.into(),
        }
    }
}
