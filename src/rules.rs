use crate::pe::{PeSummary, shannon_entropy};
use crate::scan::Finding;
use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use memchr::{memchr2, memmem};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

const BUNDLE_FORMAT: &str = "larchscan-rules/1";
const SIGNING_DOMAIN: &[u8] = b"larchscan-rules/1\n";
const MAX_PATTERN_BYTES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HashRule {
    pub id: String,
    pub sha256: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternKind {
    Ascii,
    AsciiNocase,
    Hex,
    Utf16le,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StringSpec {
    pub kind: PatternKind,
    pub value: String,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PatternRule {
    pub id: String,
    pub reason: String,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub pe_only: bool,
    #[serde(default)]
    pub min_entropy: Option<f64>,
    #[serde(default = "default_true")]
    pub match_all: bool,
    pub strings: Vec<StringSpec>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleSignature {
    pub algorithm: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleBundle {
    pub format: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub hashes: Vec<HashRule>,
    #[serde(default)]
    pub patterns: Vec<PatternRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<BundleSignature>,
}

#[derive(Serialize)]
struct CanonicalBundle<'a> {
    format: &'a str,
    version: &'a Option<String>,
    publisher: &'a Option<String>,
    hashes: &'a [HashRule],
    patterns: &'a [PatternRule],
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BundleSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    pub hash_count: usize,
    pub pattern_count: usize,
    pub signature_verified: bool,
}

enum CompiledNeedle {
    Exact(Vec<u8>),
    AsciiNocase(Vec<u8>),
}

impl CompiledNeedle {
    fn compile(spec: &StringSpec) -> Result<Self> {
        ensure!(!spec.value.is_empty(), "pattern string cannot be empty");
        let needle = match spec.kind {
            PatternKind::Ascii => {
                let bytes = spec.value.as_bytes().to_vec();
                ensure!(bytes.len() <= MAX_PATTERN_BYTES, "pattern too long");
                Self::Exact(bytes)
            }
            PatternKind::AsciiNocase => {
                ensure!(
                    spec.value.is_ascii(),
                    "ascii_nocase pattern must contain ASCII characters only"
                );
                let bytes = spec.value.to_ascii_lowercase().into_bytes();
                ensure!(bytes.len() <= MAX_PATTERN_BYTES, "pattern too long");
                Self::AsciiNocase(bytes)
            }
            PatternKind::Hex => {
                let compact: String = spec
                    .value
                    .chars()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect();
                let bytes = hex::decode(&compact).context("invalid hex pattern")?;
                ensure!(
                    !bytes.is_empty() && bytes.len() <= MAX_PATTERN_BYTES,
                    "invalid hex pattern length"
                );
                Self::Exact(bytes)
            }
            PatternKind::Utf16le => {
                let mut bytes = Vec::with_capacity(spec.value.len() * 2);
                for unit in spec.value.encode_utf16() {
                    bytes.extend_from_slice(&unit.to_le_bytes());
                }
                ensure!(
                    !bytes.is_empty() && bytes.len() <= MAX_PATTERN_BYTES,
                    "invalid utf16le pattern length"
                );
                Self::Exact(bytes)
            }
        };
        Ok(needle)
    }

    fn matches(&self, haystack: &[u8]) -> bool {
        match self {
            Self::Exact(needle) => memmem::find(haystack, needle).is_some(),
            Self::AsciiNocase(lower) => contains_ascii_nocase(haystack, lower),
        }
    }
}

fn contains_ascii_nocase(haystack: &[u8], lower_needle: &[u8]) -> bool {
    if lower_needle.is_empty() || haystack.len() < lower_needle.len() {
        return false;
    }
    let first_lo = lower_needle[0];
    let first_hi = first_lo.to_ascii_uppercase();
    let max_start = haystack.len() - lower_needle.len();
    let mut pos = 0usize;
    while pos <= max_start {
        let Some(offset) = memchr2(first_lo, first_hi, &haystack[pos..=max_start]) else {
            return false;
        };
        let start = pos + offset;
        if haystack[start..start + lower_needle.len()]
            .iter()
            .zip(lower_needle)
            .all(|(&a, &b)| a.to_ascii_lowercase() == b)
        {
            return true;
        }
        pos = start + 1;
    }
    false
}

pub struct CompiledPatternRule {
    finding: Finding,
    extensions: Vec<String>,
    pe_only: bool,
    min_entropy: Option<f64>,
    match_all: bool,
    needles: Vec<CompiledNeedle>,
}

impl CompiledPatternRule {
    pub fn matches(&self, path: &Path, bytes: &[u8], pe: Option<&PeSummary>) -> bool {
        if self.pe_only && pe.is_none() {
            return false;
        }
        if !self.extensions.is_empty() {
            let ext_ok = path
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|ext| {
                    let lower = ext.to_ascii_lowercase();
                    self.extensions.iter().any(|allowed| allowed == &lower)
                });
            if !ext_ok {
                return false;
            }
        }
        if let Some(min_ent) = self.min_entropy {
            let ent = pe
                .map(|p| p.max_code_entropy)
                .filter(|&e| e > 0.0)
                .unwrap_or_else(|| shannon_entropy(bytes));
            if ent < min_ent {
                return false;
            }
        }
        if self.match_all {
            self.needles.iter().all(|n| n.matches(bytes))
        } else {
            self.needles.iter().any(|n| n.matches(bytes))
        }
    }

    pub fn finding(&self) -> Finding {
        self.finding.clone()
    }
}

pub struct RuleSet {
    pub hashes: HashMap<String, Finding>,
    pub patterns: Vec<CompiledPatternRule>,
    pub summary: BundleSummary,
}

fn validate_id_and_reason(id: &str, reason: &str) -> Result<()> {
    ensure!(
        !id.trim().is_empty()
            && !reason.trim().is_empty()
            && !id.starts_with("amsi.")
            && !id.starts_with("triage.")
            && !id.starts_with("archive.")
            && !id.starts_with("persistence."),
        "invalid rule id or reason"
    );
    Ok(())
}

fn canonical_payload(bundle: &RuleBundle) -> Result<Vec<u8>> {
    let mut payload = Vec::from(SIGNING_DOMAIN);
    let body = serde_json::to_vec(&CanonicalBundle {
        format: &bundle.format,
        version: &bundle.version,
        publisher: &bundle.publisher,
        hashes: &bundle.hashes,
        patterns: &bundle.patterns,
    })?;
    payload.extend_from_slice(&body);
    Ok(payload)
}

pub fn generate_keypair_hex() -> Result<(String, String)> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("CSPRNG failed: {e}"))?;
    let signing = SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    Ok((
        hex::encode(signing.to_bytes()),
        hex::encode(verifying.to_bytes()),
    ))
}

pub fn sign_bundle(mut bundle: RuleBundle, private_key_hex: &str) -> Result<RuleBundle> {
    ensure!(
        bundle.format == BUNDLE_FORMAT,
        "unsupported rule bundle format"
    );
    let key_bytes = hex::decode(private_key_hex.trim()).context("invalid private key hex")?;
    let seed: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 private key must be 32 bytes (64 hex chars)"))?;
    let signing = SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    let payload = canonical_payload(&bundle)?;
    let sig = signing.sign(&payload);
    bundle.signature = Some(BundleSignature {
        algorithm: "ed25519".into(),
        public_key_hex: hex::encode(verifying.to_bytes()),
        signature_hex: hex::encode(sig.to_bytes()),
    });
    Ok(bundle)
}

pub fn verify_bundle_signature(bundle: &RuleBundle, trusted_pubkey_hex: &str) -> Result<()> {
    let expected_hex = trusted_pubkey_hex.trim().to_ascii_lowercase();
    let pub_bytes = hex::decode(&expected_hex).context("invalid trusted public key hex")?;
    let pub_arr: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 public key must be 32 bytes (64 hex chars)"))?;
    let verifying = VerifyingKey::from_bytes(&pub_arr).context("invalid Ed25519 public key")?;

    let sig_block = bundle
        .signature
        .as_ref()
        .context("rule bundle is unsigned; a trusted Ed25519 signature is required")?;
    ensure!(
        sig_block.algorithm.eq_ignore_ascii_case("ed25519"),
        "unsupported signature algorithm"
    );
    ensure!(
        sig_block
            .public_key_hex
            .trim()
            .eq_ignore_ascii_case(&expected_hex),
        "rule bundle was signed by an untrusted public key"
    );
    let sig_bytes = hex::decode(sig_block.signature_hex.trim()).context("invalid signature hex")?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_arr);
    let payload = canonical_payload(bundle)?;
    verifying
        .verify_strict(&payload, &signature)
        .context("rule bundle Ed25519 signature verification failed")?;
    Ok(())
}

pub fn load_ruleset(
    builtin_demo: HashRule,
    custom_bytes: Option<&[u8]>,
    trusted_pubkey_hex: Option<&str>,
) -> Result<RuleSet> {
    let mut hash_rules = vec![builtin_demo];
    let mut pattern_specs = Vec::new();
    let mut summary = BundleSummary::default();

    if let Some(raw) = custom_bytes {
        let value: serde_json::Value =
            serde_json::from_slice(raw).context("invalid rule file JSON")?;
        if value.is_array() {
            ensure!(
                trusted_pubkey_hex.is_none(),
                "a legacy unsigned rule array cannot be used when a trusted rule public key is required"
            );
            let parsed: Vec<HashRule> =
                serde_json::from_value(value).context("invalid rule file")?;
            summary.format = Some("legacy-array".into());
            summary.hash_count = parsed.len();
            hash_rules.extend(parsed);
        } else if value.is_object() {
            let bundle: RuleBundle =
                serde_json::from_value(value).context("invalid rule bundle")?;
            ensure!(
                bundle.format == BUNDLE_FORMAT,
                "unsupported rule bundle format '{}'",
                bundle.format
            );
            if let Some(pubkey) = trusted_pubkey_hex {
                verify_bundle_signature(&bundle, pubkey)?;
                summary.signature_verified = true;
            }
            summary.format = Some(bundle.format);
            summary.version = bundle.version;
            summary.publisher = bundle.publisher;
            summary.hash_count = bundle.hashes.len();
            summary.pattern_count = bundle.patterns.len();
            hash_rules.extend(bundle.hashes);
            pattern_specs.extend(bundle.patterns);
        } else {
            bail!("invalid rule file: expected JSON array or larchscan-rules/1 object");
        }
    }

    let mut ids = HashSet::new();
    let mut hashes = HashMap::new();
    for rule in hash_rules {
        validate_id_and_reason(&rule.id, &rule.reason)?;
        ensure!(
            rule.sha256.len() == 64 && rule.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid SHA-256 in {}",
            rule.id
        );
        ensure!(ids.insert(rule.id.clone()), "duplicate rule id {}", rule.id);
        ensure!(
            hashes
                .insert(
                    rule.sha256.to_ascii_lowercase(),
                    Finding {
                        id: rule.id,
                        reason: rule.reason,
                    }
                )
                .is_none(),
            "duplicate SHA-256"
        );
    }

    let mut patterns = Vec::with_capacity(pattern_specs.len());
    for spec in pattern_specs {
        validate_id_and_reason(&spec.id, &spec.reason)?;
        ensure!(ids.insert(spec.id.clone()), "duplicate rule id {}", spec.id);
        ensure!(
            !spec.strings.is_empty(),
            "pattern rule {} requires at least one string",
            spec.id
        );
        if let Some(ent) = spec.min_entropy {
            ensure!(
                (0.0..=8.0).contains(&ent),
                "invalid min_entropy in {}",
                spec.id
            );
        }
        let needles = spec
            .strings
            .iter()
            .map(CompiledNeedle::compile)
            .collect::<Result<Vec<_>>>()?;
        let extensions = spec
            .extensions
            .into_iter()
            .map(|e| e.trim().trim_start_matches('.').to_ascii_lowercase())
            .filter(|e| !e.is_empty())
            .collect();
        patterns.push(CompiledPatternRule {
            finding: Finding {
                id: spec.id,
                reason: spec.reason,
            },
            extensions,
            pe_only: spec.pe_only,
            min_entropy: spec.min_entropy,
            match_all: spec.match_all,
            needles,
        });
    }

    Ok(RuleSet {
        hashes,
        patterns,
        summary,
    })
}
