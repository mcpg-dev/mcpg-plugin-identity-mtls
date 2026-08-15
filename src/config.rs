//! Operator-supplied configuration schema for `dev.mcpg.identity.mtls`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MtlsConfig {
    /// Sources walked in priority order. First successful parse wins.
    pub sources: Vec<Source>,
    pub extraction: ExtractionConfig,
    /// Optional per-canonicalised-subject metadata.
    #[serde(default)]
    pub identities: BTreeMap<String, IdentityMetadata>,
    #[serde(default)]
    pub resolution: ResolutionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    /// Envoy / Istio `X-Forwarded-Client-Cert` per RFC 6962.
    Xfcc {
        header: String,
        #[serde(default)]
        chain_position: ChainPosition,
    },
    /// nginx-style `X-SSL-Client-S-DN` (single-DN header value).
    DnString { header: String },
    /// Cloud-LB or operator-custom shape.
    CustomHeader {
        header: String,
        extraction_hint: ExtractionHint,
    },
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChainPosition {
    #[default]
    First,
    Last,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionHint {
    /// Header value is a Subject DN string.
    Dn,
    /// Header value is a SHA-256 fingerprint (hex; colons OK).
    Fingerprint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionConfig {
    pub mode: ExtractionMode,
    /// Applies to `subject_cn` mode. Default false (lowercased).
    #[serde(default)]
    pub case_sensitive: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionMode {
    /// Find `CN=<value>` in the subject DN. Common pattern.
    SubjectCn,
    /// Use the entire (whitespace-normalised) subject DN.
    SubjectDn,
    /// Use the SHA-256 fingerprint (hex, lowercase, no colons).
    Fingerprint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionConfig {
    #[serde(default = "default_trust_level")]
    pub trust_level: String,
    #[serde(default = "default_auth_provider_label")]
    pub auth_provider_label: String,
}

impl Default for ResolutionConfig {
    fn default() -> Self {
        Self {
            trust_level: default_trust_level(),
            auth_provider_label: default_auth_provider_label(),
        }
    }
}

/// Default trust level for header-derived mTLS identity.
///
/// `header_asserted`, NOT `verified`: this v0.1 plugin reads the
/// peer identity from request headers (XFCC / DN strings), which a client
/// can forge unless a trusted proxy terminates mTLS and strips inbound
/// copies. Defaulting to `verified` let any client assert an arbitrary
/// subject as a fully-trusted principal. Operators with such a proxy opt
/// in explicitly via `resolution.trust_level: "verified"`.
fn default_trust_level() -> String {
    "header_asserted".into()
}

fn default_auth_provider_label() -> String {
    "mtls".into()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityMetadata {
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid identity.mtls config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("identity.mtls: `sources` must be non-empty")]
    EmptySources,
    #[error("identity.mtls: source[{index}]: header is empty")]
    EmptySourceHeader { index: usize },
    #[error(
        "identity.mtls: invalid trust_level `{value}` \
         (allowed: verified | header_asserted)"
    )]
    InvalidTrustLevel { value: String },
}

impl MtlsConfig {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.sources.is_empty() {
            return Err(ConfigError::EmptySources);
        }
        for (index, source) in self.sources.iter().enumerate() {
            let header = match source {
                Source::Xfcc { header, .. }
                | Source::DnString { header }
                | Source::CustomHeader { header, .. } => header,
            };
            if header.trim().is_empty() {
                return Err(ConfigError::EmptySourceHeader { index });
            }
        }
        match self.resolution.trust_level.as_str() {
            "verified" | "header_asserted" => {}
            other => {
                return Err(ConfigError::InvalidTrustLevel {
                    value: other.into(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_minimal_config() {
        let cfg = json!({
            "sources": [
                { "kind": "xfcc", "header": "XFCC", "chain_position": "first" }
            ],
            "extraction": { "mode": "subject_cn" }
        })
        .to_string();
        let parsed = MtlsConfig::parse(&cfg).unwrap();
        assert_eq!(parsed.sources.len(), 1);
        assert_eq!(parsed.extraction.mode, ExtractionMode::SubjectCn);
    }

    /// Regression: an omitted trust_level must default to the lower
    /// `header_asserted` tier, not `verified` — header-derived identity is
    /// only trustworthy behind a trusted proxy, which the operator opts into.
    #[test]
    fn default_trust_level_is_header_asserted() {
        assert_eq!(default_trust_level(), "header_asserted");
        let cfg = json!({
            "sources": [{ "kind": "xfcc", "header": "XFCC" }],
            "extraction": { "mode": "subject_cn" }
        })
        .to_string();
        let parsed = MtlsConfig::parse(&cfg).unwrap();
        assert_eq!(parsed.resolution.trust_level, "header_asserted");
    }

    #[test]
    fn rejects_empty_sources() {
        let cfg = json!({
            "sources": [],
            "extraction": { "mode": "subject_cn" }
        })
        .to_string();
        let err = MtlsConfig::parse(&cfg).unwrap_err();
        matches!(err, ConfigError::EmptySources);
    }

    #[test]
    fn rejects_empty_source_header() {
        let cfg = json!({
            "sources": [{ "kind": "dn_string", "header": "" }],
            "extraction": { "mode": "subject_dn" }
        })
        .to_string();
        let err = MtlsConfig::parse(&cfg).unwrap_err();
        matches!(err, ConfigError::EmptySourceHeader { .. });
    }

    #[test]
    fn rejects_invalid_trust_level() {
        let cfg = json!({
            "sources": [{ "kind": "xfcc", "header": "X" }],
            "extraction": { "mode": "subject_cn" },
            "resolution": { "trust_level": "alien" }
        })
        .to_string();
        let err = MtlsConfig::parse(&cfg).unwrap_err();
        matches!(err, ConfigError::InvalidTrustLevel { .. });
    }
}
