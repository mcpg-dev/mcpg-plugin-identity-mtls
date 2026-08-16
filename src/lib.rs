//! `dev.mcpg.identity.mtls` — mTLS identity_provider (header-
//! injection sources only for v0.1).
//!
//! This crate is the implementation; operator-facing
//! summary lives in `README.md`.
//!
//! # v0.1 scope (current)
//!
//! - Source kinds: `xfcc` (Envoy / Istio `X-Forwarded-Client-Cert`
//!   per RFC 6962), `dn_string` (nginx-style single-DN headers),
//!   `custom_header` (cloud-LB / operator-named shapes).
//! - Extraction modes: `subject_cn`, `subject_dn`, `fingerprint`.
//! - Optional per-subject metadata map (`identities`).
//! - Trust mode (every successfully extracted subject accepted).
//!
//! # Deferred
//!
//! - Native peer-cert validation (`direct_mtls` source). Requires
//!   `RequestMetadata.tls` threading + protocol 1.0 → 1.1 bump.
//! - SAN extraction modes (`san_uri`, `san_dns`, `san_email`).
//!   XFCC parsing for SAN fields exists but the v0.1 scope cuts
//!   them; operators today extract via `subject_cn` /
//!   `subject_dn` / `fingerprint`.
//! - Allowlist mode (constant-time-compared digest allowlist).
//!   v0.1 ships trust mode only; operators wanting strict
//!   allowlists compose with policy_engine for now.

mod config;

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use mcpg_plugin_protocol::{
    IdentityProviderPlugin, IdentityResolution, PluginClass, PluginIdentity, PluginManifest,
};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncIdentityResolver;
use serde_json::Value;
use tracing::{debug, info_span, warn};

pub use config::{
    ChainPosition, ConfigError, ExtractionConfig, ExtractionHint, ExtractionMode, IdentityMetadata,
    MtlsConfig, ResolutionConfig, Source,
};

const PLUGIN_ID: &str = "dev.mcpg.identity.mtls";

fn record_resolve_outcome(result: &IdentityResolution, elapsed: std::time::Duration) {
    let outcome = match result {
        IdentityResolution::Resolved { .. } => "resolved",
        IdentityResolution::None => "none",
        IdentityResolution::Invalid { .. } => "invalid",
    };
    metrics::counter!(
        "mcpg_identity_mtls_resolutions_total",
        "outcome" => outcome,
    )
    .increment(1);
    metrics::histogram!("mcpg_identity_mtls_resolve_ms").record(elapsed.as_millis() as f64);
    match result {
        IdentityResolution::Resolved { identity } => debug!(
            subject = identity.subject_id.as_deref().unwrap_or(""),
            elapsed_ms = %elapsed.as_millis(),
            "mtls identity resolved"
        ),
        IdentityResolution::None => debug!(
            elapsed_ms = %elapsed.as_millis(),
            "mtls identity: no header — fall through"
        ),
        IdentityResolution::Invalid { reason, .. } => warn!(
            reason = %reason,
            elapsed_ms = %elapsed.as_millis(),
            "mtls identity: invalid client cert header"
        ),
    }
}

pub struct MtlsIdentityPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    config: MtlsConfig,
}

impl MtlsIdentityPlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = MtlsConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "mtls identity: config parse failed; refusing to register"
            );
            panic!(
                "mtls identity config parse failed: {err}. A misconfigured \
                 identity resolver is a security hole; refusing to load."
            )
        });
        Self::from_validated_config(cfg)
    }

    fn from_validated_config(cfg: MtlsConfig) -> Self {
        tracing::info!(
            plugin_id = PLUGIN_ID,
            sources = cfg.sources.len(),
            mode = ?cfg.extraction.mode,
            identities_loaded = cfg.identities.len(),
            "mtls identity: configured"
        );
        // `verified` maps to the top trust bucket but this plugin reads
        // identity from forwarded headers. Loudly remind operators that it is
        // only safe behind a trusted proxy that terminates mTLS and strips
        // client-supplied copies of these headers.
        if cfg.resolution.trust_level == "verified" {
            tracing::warn!(
                plugin_id = PLUGIN_ID,
                "mtls identity: trust_level=`verified` emits fully-trusted identities from \
                 request headers — ONLY safe behind a trusted proxy that terminates mTLS and \
                 strips inbound XFCC/DN headers. Without one, any client can spoof identity."
            );
        }
        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "mTLS Identity Resolver".into(),
                    plugin_class: PluginClass::IdentityProvider,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                config: cfg,
            }),
        }
    }
}

/// Pre-parsed cert metadata extracted from one source. Only the
/// fields used by v0.1's three extraction modes are surfaced;
/// SAN fields are deferred (see module docs).
#[derive(Debug, Clone, Default)]
struct ParsedCertMetadata {
    subject_dn: Option<String>,
    fingerprint_sha256: Option<String>,
    /// Tag of the source that produced this metadata. Surfaced as
    /// the `mtls.source` attribute on the resolved identity.
    source_tag: &'static str,
}

fn lookup_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|(n, v)| {
        if n.eq_ignore_ascii_case(name) {
            Some(v.as_str())
        } else {
            None
        }
    })
}

/// Parse an XFCC header value per RFC 6962 §3.4. The input is
/// `<hop>(,<hop>)*`; each `<hop>` is `key=value(;key=value)*`
/// where values may be quoted with `"` and escapes are `\"` and
/// `\\`.
///
/// Returns the recognised fields from the chosen hop.
/// Split an XFCC header value into hops. Hops are comma-separated, but
/// Envoy/Istio quote DN values with `"` and those values may contain
/// commas, so a comma is a hop boundary only when it is not inside a quoted
/// run. Inside a quoted run, `\"` and `\\` are escapes. Always returns at
/// least one element.
fn split_xfcc_hops(raw: &str) -> Vec<&str> {
    let bytes = raw.as_bytes();
    let mut hops = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut in_quotes = false;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if in_quotes && i + 1 < bytes.len() => {
                i += 2; // skip the escaped char inside a quoted run
                continue;
            }
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes => {
                hops.push(&raw[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    hops.push(&raw[start..]);
    hops
}

fn parse_xfcc_hop(hop: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let bytes = hop.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Find key=
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let key = std::str::from_utf8(&bytes[key_start..i])
            .unwrap_or("")
            .trim()
            .to_owned();
        i += 1; // skip '='
        let mut value = String::new();
        if i < bytes.len() && bytes[i] == b'"' {
            i += 1; // skip opening quote
            while i < bytes.len() {
                let c = bytes[i];
                if c == b'\\' && i + 1 < bytes.len() {
                    value.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
                if c == b'"' {
                    i += 1; // closing quote
                    break;
                }
                value.push(c as char);
                i += 1;
            }
        } else {
            // Unquoted value — runs until ';' or end.
            while i < bytes.len() && bytes[i] != b';' {
                value.push(bytes[i] as char);
                i += 1;
            }
        }
        if !key.is_empty() {
            out.insert(key, value);
        }
        // Skip separator ';'
        if i < bytes.len() && bytes[i] == b';' {
            i += 1;
        }
    }
    out
}

fn parse_source(source: &Source, headers: &[(String, String)]) -> Option<ParsedCertMetadata> {
    match source {
        Source::Xfcc {
            header,
            chain_position,
        } => {
            let raw = lookup_header(headers, header)?;
            // Split chain hops on `,`, but only when the comma is outside a
            // quoted run — Envoy/Istio quote DN values that themselves
            // contain commas (`Subject="CN=alice,O=acme,C=US"`).
            let hops = split_xfcc_hops(raw);
            let chosen = match chain_position {
                ChainPosition::First => hops.first().copied(),
                ChainPosition::Last => hops.last().copied(),
            }?;
            let map = parse_xfcc_hop(chosen.trim());
            let mut parsed = ParsedCertMetadata {
                source_tag: "xfcc",
                ..Default::default()
            };
            // Recognised XFCC keys: `Subject`, `Hash`, `By`, etc.
            if let Some(subject) = map.get("Subject").or_else(|| map.get("subject")) {
                parsed.subject_dn = Some(subject.clone());
            }
            if let Some(hash) = map.get("Hash").or_else(|| map.get("hash")) {
                parsed.fingerprint_sha256 = Some(hash.to_lowercase());
            }
            if parsed.subject_dn.is_some() || parsed.fingerprint_sha256.is_some() {
                Some(parsed)
            } else {
                None
            }
        }
        Source::DnString { header } => {
            let raw = lookup_header(headers, header)?;
            if raw.trim().is_empty() {
                return None;
            }
            Some(ParsedCertMetadata {
                subject_dn: Some(raw.to_owned()),
                source_tag: "dn_string",
                ..Default::default()
            })
        }
        Source::CustomHeader {
            header,
            extraction_hint,
        } => {
            let raw = lookup_header(headers, header)?;
            if raw.trim().is_empty() {
                return None;
            }
            let mut parsed = ParsedCertMetadata {
                source_tag: "custom_header",
                ..Default::default()
            };
            match extraction_hint {
                ExtractionHint::Dn => parsed.subject_dn = Some(raw.to_owned()),
                ExtractionHint::Fingerprint => {
                    parsed.fingerprint_sha256 = Some(raw.to_lowercase());
                }
            }
            Some(parsed)
        }
    }
}

fn extract_subject(
    parsed: &ParsedCertMetadata,
    extraction: &ExtractionConfig,
) -> Result<String, String> {
    match extraction.mode {
        ExtractionMode::SubjectCn => {
            let dn = parsed
                .subject_dn
                .as_deref()
                .ok_or("no subject_dn in cert metadata")?;
            // Find first CN= attribute. RDN parsing: split on `,`
            // (RFC 4514) then look for CN=.
            let cn = dn
                .split(',')
                .map(str::trim)
                .find_map(|rdn| {
                    let mut parts = rdn.splitn(2, '=');
                    let k = parts.next()?.trim();
                    let v = parts.next()?.trim();
                    if k.eq_ignore_ascii_case("CN") {
                        Some(v.to_owned())
                    } else {
                        None
                    }
                })
                .ok_or("no CN= in subject_dn")?;
            if cn.is_empty() {
                return Err("subject CN extraction failed: empty CN".into());
            }
            if extraction.case_sensitive {
                Ok(cn)
            } else {
                Ok(cn.to_lowercase())
            }
        }
        ExtractionMode::SubjectDn => {
            let dn = parsed
                .subject_dn
                .as_deref()
                .ok_or("no subject_dn in cert metadata")?;
            // Normalise: trim each RDN and re-join. Doesn't fully
            // canonicalise (would require RFC 4518 string prep)
            // but stops trivial whitespace differences from
            // creating distinct identities.
            let normalised: Vec<String> = dn
                .split(',')
                .map(|rdn| rdn.trim().to_owned())
                .filter(|rdn| !rdn.is_empty())
                .collect();
            Ok(normalised.join(","))
        }
        ExtractionMode::Fingerprint => {
            let fp = parsed
                .fingerprint_sha256
                .as_deref()
                .ok_or("no fingerprint in cert metadata")?
                .to_lowercase();
            // SHA-256 hex is 64 chars. Allow operators to provide
            // colon-separated forms (`a1:b2:...`) which we strip.
            let cleaned: String = fp.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if cleaned.len() != 64 {
                return Err(format!(
                    "fingerprint must be 64 hex chars (sha256); got {} chars",
                    cleaned.len()
                ));
            }
            Ok(cleaned)
        }
    }
}

fn resolve(inner: &Inner, headers: &[(String, String)]) -> IdentityResolution {
    // Walk sources in priority order. First success wins.
    let mut last_invalid_reason: Option<String> = None;
    let mut last_source_tag: &'static str = "";
    for source in &inner.config.sources {
        let Some(parsed) = parse_source(source, headers) else {
            continue;
        };
        let source_tag = parsed.source_tag;
        match extract_subject(&parsed, &inner.config.extraction) {
            Ok(subject) => {
                let metadata = inner.config.identities.get(&subject).cloned();
                let mut attributes: BTreeMap<String, String> = metadata
                    .as_ref()
                    .map(|m| m.attributes.clone())
                    .unwrap_or_default();
                attributes.insert("mtls.source".into(), source_tag.into());
                if let Some(dn) = &parsed.subject_dn {
                    attributes.insert("mtls.subject_dn".into(), dn.clone());
                }
                if let Some(fp) = &parsed.fingerprint_sha256 {
                    attributes.insert("mtls.fingerprint".into(), fp.clone());
                }
                return IdentityResolution::Resolved {
                    identity: PluginIdentity {
                        kind: inner.config.resolution.trust_level.clone(),
                        trust_level: inner.config.resolution.trust_level.clone(),
                        subject_id: Some(subject),
                        auth_provider: Some(inner.config.resolution.auth_provider_label.clone()),
                        issuer: None,
                        roles: metadata
                            .as_ref()
                            .map(|m| m.roles.clone())
                            .unwrap_or_default(),
                        groups: metadata
                            .as_ref()
                            .map(|m| m.groups.clone())
                            .unwrap_or_default(),
                        scopes: metadata
                            .as_ref()
                            .map(|m| m.scopes.clone())
                            .unwrap_or_default(),
                        attributes,
                    },
                };
            }
            Err(reason) => {
                last_invalid_reason = Some(reason);
                last_source_tag = source_tag;
            }
        }
    }
    if let Some(reason) = last_invalid_reason {
        IdentityResolution::Invalid {
            reason: format!("mtls {last_source_tag}: {reason}"),
            response_headers: Vec::new(),
        }
    } else {
        IdentityResolution::None
    }
}

#[async_trait]
impl IdentityProviderPlugin for MtlsIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    async fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        _config: &Value,
    ) -> IdentityResolution {
        // Header-injection sources only. The protocol-1.1
        // `metadata.tls` field is reserved for the native peer-cert
        // validation path (`direct_mtls` source), still to come.
        let _span = info_span!("identity_mtls_resolve", plugin_id = PLUGIN_ID).entered();
        let started = std::time::Instant::now();
        let result = resolve(&self.inner, headers);
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

impl SyncIdentityResolver for MtlsIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        _config: &Value,
    ) -> IdentityResolution {
        let _span = info_span!("identity_mtls_resolve", plugin_id = PLUGIN_ID).entered();
        let started = std::time::Instant::now();
        let result = resolve(&self.inner, headers);
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

declare_plugin! {

    plugin_id: "dev.mcpg.identity.mtls",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        identity as id {
            inner_name: "",
            plugin_type: MtlsIdentityPlugin,
            // mTLS identity reads peer cert from per-request RequestMetadata;
            // no cross-node state to coordinate.
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> MtlsIdentityPlugin {
                MtlsIdentityPlugin::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn build(cfg: serde_json::Value) -> MtlsIdentityPlugin {
        MtlsIdentityPlugin::from_config_json(&cfg.to_string())
    }

    fn h(name: &str, value: &str) -> Vec<(String, String)> {
        vec![(name.into(), value.into())]
    }

    #[test]
    fn xfcc_subject_cn_resolves() {
        let plugin = build(json!({
            "sources": [
                { "kind": "xfcc", "header": "X-Forwarded-Client-Cert", "chain_position": "first" }
            ],
            "extraction": { "mode": "subject_cn" }
        }));
        let r = resolve(
            &plugin.inner,
            &h(
                "X-Forwarded-Client-Cert",
                "Hash=abcd;Subject=\"CN=alice,O=acme,L=NYC\"",
            ),
        );
        match r {
            IdentityResolution::Resolved { identity } => {
                assert_eq!(identity.subject_id.as_deref(), Some("alice"));
                assert_eq!(
                    identity.attributes.get("mtls.source").map(String::as_str),
                    Some("xfcc")
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn xfcc_chain_position_last() {
        let plugin = build(json!({
            "sources": [
                { "kind": "xfcc", "header": "XFCC", "chain_position": "last" }
            ],
            "extraction": { "mode": "subject_cn" }
        }));
        let r = resolve(
            &plugin.inner,
            &h("XFCC", "Subject=\"CN=first\",Subject=\"CN=last\""),
        );
        match r {
            IdentityResolution::Resolved { identity } => {
                assert_eq!(identity.subject_id.as_deref(), Some("last"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn split_xfcc_hops_keeps_quoted_commas_together() {
        // Two hops, each with a quoted DN containing commas. A naive split on
        // every comma would shatter this into six fragments and misattribute
        // the chosen hop.
        let raw = "By=spiffe://a;Subject=\"CN=alice,O=acme,C=US\",\
                   By=spiffe://b;Subject=\"CN=bob,O=acme,C=US\"";
        let hops = split_xfcc_hops(raw);
        assert_eq!(hops.len(), 2, "got: {hops:?}");
        assert!(hops[0].contains("CN=alice,O=acme,C=US"));
        assert!(hops[1].contains("CN=bob,O=acme,C=US"));
    }

    #[test]
    fn split_xfcc_hops_single_hop_is_one_element() {
        let hops = split_xfcc_hops("Subject=\"CN=solo,O=acme\"");
        assert_eq!(hops.len(), 1);
    }

    #[test]
    fn xfcc_last_hop_with_quoted_commas_picks_correct_subject() {
        // The last hop's Subject CN must be `bob`. With a naive comma split the
        // last element is a stray `C=US"` fragment that carries no Subject, so
        // resolution would wrongly fail or pick the wrong identity.
        let plugin = build(json!({
            "sources": [
                { "kind": "xfcc", "header": "XFCC", "chain_position": "last" }
            ],
            "extraction": { "mode": "subject_cn" }
        }));
        let raw = "By=spiffe://a;Subject=\"CN=alice,O=acme,C=US\",\
                   By=spiffe://b;Subject=\"CN=bob,O=acme,C=US\"";
        let r = resolve(&plugin.inner, &h("XFCC", raw));
        match r {
            IdentityResolution::Resolved { identity } => {
                assert_eq!(identity.subject_id.as_deref(), Some("bob"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn dn_string_subject_dn_normalised() {
        let plugin = build(json!({
            "sources": [
                { "kind": "dn_string", "header": "X-SSL-Client-S-DN" }
            ],
            "extraction": { "mode": "subject_dn" }
        }));
        let r = resolve(
            &plugin.inner,
            &h("X-SSL-Client-S-DN", " CN=alice , O=acme "),
        );
        match r {
            IdentityResolution::Resolved { identity } => {
                assert_eq!(identity.subject_id.as_deref(), Some("CN=alice,O=acme"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn fingerprint_extraction_strips_colons() {
        let fp = "a".repeat(64);
        let colon_form: String = fp
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        let plugin = build(json!({
            "sources": [
                { "kind": "custom_header", "header": "X-Cert-Fingerprint", "extraction_hint": "fingerprint" }
            ],
            "extraction": { "mode": "fingerprint" }
        }));
        let r = resolve(&plugin.inner, &h("X-Cert-Fingerprint", &colon_form));
        match r {
            IdentityResolution::Resolved { identity } => {
                assert_eq!(identity.subject_id.as_deref(), Some(fp.as_str()));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn fingerprint_wrong_length_invalid() {
        let plugin = build(json!({
            "sources": [
                { "kind": "custom_header", "header": "X-Cert-Fingerprint", "extraction_hint": "fingerprint" }
            ],
            "extraction": { "mode": "fingerprint" }
        }));
        let r = resolve(&plugin.inner, &h("X-Cert-Fingerprint", "tooshort"));
        match r {
            IdentityResolution::Invalid { reason, .. } => {
                assert!(reason.contains("fingerprint"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn no_source_present_returns_none() {
        let plugin = build(json!({
            "sources": [
                { "kind": "xfcc", "header": "X-Forwarded-Client-Cert", "chain_position": "first" }
            ],
            "extraction": { "mode": "subject_cn" }
        }));
        let r = resolve(&plugin.inner, &[]);
        assert!(matches!(r, IdentityResolution::None));
    }

    #[test]
    fn case_insensitive_cn_lowercased() {
        let plugin = build(json!({
            "sources": [
                { "kind": "xfcc", "header": "XFCC", "chain_position": "first" }
            ],
            "extraction": { "mode": "subject_cn", "case_sensitive": false }
        }));
        let r = resolve(&plugin.inner, &h("XFCC", "Subject=\"CN=ALICE,O=acme\""));
        match r {
            IdentityResolution::Resolved { identity } => {
                assert_eq!(identity.subject_id.as_deref(), Some("alice"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn case_sensitive_cn_preserved() {
        let plugin = build(json!({
            "sources": [
                { "kind": "xfcc", "header": "XFCC", "chain_position": "first" }
            ],
            "extraction": { "mode": "subject_cn", "case_sensitive": true }
        }));
        let r = resolve(&plugin.inner, &h("XFCC", "Subject=\"CN=ALICE,O=acme\""));
        match r {
            IdentityResolution::Resolved { identity } => {
                assert_eq!(identity.subject_id.as_deref(), Some("ALICE"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn identities_metadata_attached_to_resolved_identity() {
        let plugin = build(json!({
            "sources": [
                { "kind": "xfcc", "header": "XFCC", "chain_position": "first" }
            ],
            "extraction": { "mode": "subject_cn" },
            "identities": {
                "alice": {
                    "roles": ["operator"],
                    "groups": ["humans"],
                    "scopes": ["console.read"],
                    "attributes": { "department": "platform" }
                }
            }
        }));
        let r = resolve(&plugin.inner, &h("XFCC", "Subject=\"CN=alice\""));
        match r {
            IdentityResolution::Resolved { identity } => {
                assert_eq!(identity.roles, vec!["operator".to_owned()]);
                assert_eq!(identity.scopes, vec!["console.read".to_owned()]);
                assert_eq!(
                    identity.attributes.get("department").map(String::as_str),
                    Some("platform")
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn multi_source_priority_xfcc_then_dn_string() {
        let plugin = build(json!({
            "sources": [
                { "kind": "xfcc", "header": "XFCC", "chain_position": "first" },
                { "kind": "dn_string", "header": "X-SSL-DN" }
            ],
            "extraction": { "mode": "subject_cn" }
        }));
        // Only DN string present.
        let r = resolve(&plugin.inner, &h("X-SSL-DN", "CN=bob,O=acme"));
        match r {
            IdentityResolution::Resolved { identity } => {
                assert_eq!(identity.subject_id.as_deref(), Some("bob"));
                assert_eq!(
                    identity.attributes.get("mtls.source").map(String::as_str),
                    Some("dn_string")
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
