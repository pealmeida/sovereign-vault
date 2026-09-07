//! Durable public locators and the locator-exchange contract (ADR-0016).
//!
//! A [`PublicLocator`] is the marker written into rewritten files: durable
//! identity with **zero authority**. Possession conveys no access and no
//! consent; it is an index key the vault can look up, nothing more. A locator
//! is never dereferenced directly — it is *exchanged* for a freshly scoped
//! [`ReferenceToken`], and every existing control (revocation, aggregate
//! limits, policy) applies at exchange time rather than at rewrite time.
//!
//! ## Why the identifier is random, never derived
//!
//! ADR-0016 explicitly rejected deriving the locator as an HMAC of the value
//! under a vault key. Any function of the value restores digest-style
//! linkage: equal values yield equal markers, which correlates the same
//! person or credential across every repository, branch, and backup the
//! marker reaches, and makes every published marker a target tied to one key
//! whose compromise would relink the entire corpus. Two occurrences of the
//! same secret therefore receive two **unrelated** locators. Do not
//! "optimize" this: there is deliberately no `from_value` constructor, and
//! `generate` takes no value parameter. A future change that derives the id
//! from content reverses a recorded security decision.
//!
//! ## Why exchange failures are indistinguishable
//!
//! [`LocatorExchangeError`] keeps distinct variants for "unknown locator",
//! "registry entry revoked", and "resource revoked" so vault-side internals
//! can branch (audit detail, record pruning). Their *surfaced* form —
//! [`Display`](core::fmt::Display) and [`LocatorExchangeError::code`] — is
//! deliberately identical for all three: a holder probing candidate markers
//! must not be able to distinguish "never existed" from "existed and was
//! revoked", because that difference is an existence oracle over vault
//! state. Do not collapse the variants, and do not differentiate their
//! messages.

use std::collections::BTreeMap;

use crate::error::{Result, RuntimeError};
use crate::references::token::{base64url_decode, base64url_encode, ReferenceToken};
use crate::types::InternalResourceId;

/// Prefix of the external form, including the format version and the literal
/// square brackets that make the marker greppable in a rewritten file.
const LOCATOR_PREFIX: &str = "[SV:LOC:v1:";

/// Suffix of the external form.
const LOCATOR_SUFFIX: &str = "]";

/// Raw length of a locator identifier, in bytes.
const LOCATOR_BYTES: usize = 32;

/// A durable public locator: random identity, zero authority.
///
/// The identifier is 32 bytes drawn from the operating system CSPRNG — not a
/// hash, digest, HMAC, or any other function of the value it stands for (see
/// the module documentation for why this must never change). It carries no
/// category label and no metadata: the identifier alone. The locator-to-
/// resource mapping is vault-side state; the file holds only the opaque
/// marker.
///
/// Possession of a locator conveys no access. The only path from a marker to
/// material runs through [`LocatorLedger::exchange`], which authenticates,
/// checks revocation and aggregate limits, and issues a scoped
/// [`ReferenceToken`].
///
/// Deliberately not `Serialize`/`Deserialize`: the locator is published into
/// files, which is authority enough for it to have in logs and audit records
/// by accident. Its [`Debug`] implementation prints a fixed marker and never
/// the identifier, following the [`SensitiveBytes`](crate::types::SensitiveBytes)
/// discipline — the id in a log is durable correlation material.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicLocator([u8; LOCATOR_BYTES]);

impl PublicLocator {
    /// Generates a fresh locator from the operating system CSPRNG.
    ///
    /// Takes no value parameter on purpose: the locator must not be derivable
    /// from the secret it names. Callers mint a fresh locator per occurrence.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; LOCATOR_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| RuntimeError::InvalidStructure)?;
        Ok(PublicLocator(bytes))
    }

    /// Parses a locator from its external wire form.
    ///
    /// Strict: the exact `[SV:LOC:v1:` prefix and `]` suffix, the unpadded
    /// base64url alphabet, and exactly 32 decoded bytes. Anything malformed
    /// is rejected rather than guessed at — a lenient parser would accept
    /// marker-shaped strings that were never minted by the vault. The error
    /// never echoes the input.
    pub fn parse(value: &str) -> Result<Self> {
        let body = value
            .strip_prefix(LOCATOR_PREFIX)
            .and_then(|rest| rest.strip_suffix(LOCATOR_SUFFIX))
            .ok_or(RuntimeError::ReferenceInvalid)?;
        let decoded = base64url_decode(body).ok_or(RuntimeError::ReferenceInvalid)?;
        let bytes: [u8; LOCATOR_BYTES] = decoded
            .try_into()
            .map_err(|_| RuntimeError::ReferenceInvalid)?;
        Ok(PublicLocator(bytes))
    }

    /// Renders the locator in its external wire form.
    pub fn to_external(&self) -> String {
        format!(
            "{LOCATOR_PREFIX}{}{LOCATOR_SUFFIX}",
            base64url_encode(&self.0)
        )
    }

    /// The raw identifier bytes, for vault-side mapping storage.
    fn id(&self) -> &[u8; LOCATOR_BYTES] {
        &self.0
    }
}

impl core::fmt::Debug for PublicLocator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Fixed marker only: never the identifier. A locator in a log is
        // durable correlation material even though it is not a credential.
        f.write_str("PublicLocator([REDACTED])")
    }
}

/// Why a locator exchange failed.
///
/// The variants separate the reasons so vault-side internals can act on them
/// (pruning dead records, audit detail). The surfaced form — [`Display`] and
/// [`code`](LocatorExchangeError::code) — is deliberately **identical** for
/// [`Unknown`](LocatorExchangeError::Unknown),
/// [`EntryRevoked`](LocatorExchangeError::EntryRevoked), and
/// [`ResourceRevoked`](LocatorExchangeError::ResourceRevoked): an unknown
/// locator and a revoked one must be indistinguishable to the caller, or
/// probing candidate markers becomes an existence oracle over vault state.
/// Do not collapse the variants into one, and do not give them distinct
/// messages.
///
/// This is a hand-written [`Display`](core::fmt::Display) rather than a
/// `thiserror` derive precisely because a per-variant `#[error("…")]`
/// attribute invites exactly the distinct messages this type must not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocatorExchangeError {
    /// No mapping entry exists for the locator.
    Unknown,
    /// The locator's registry entry has been revoked.
    EntryRevoked,
    /// The resource the locator names has been revoked.
    ResourceRevoked,
    /// The resource's aggregate limits are exhausted; re-exchanging a locator
    /// never resets them.
    Exhausted,
    /// Internal failure (for example, the CSPRNG was unavailable). The use,
    /// once consumed, is not refunded — the same tradeoff the reference
    /// registry makes to keep replay impossible.
    Internal,
}

/// The single surfaced message for every "this locator does not resolve"
/// reason. One constant, shared by three variants, so the wording can never
/// drift apart.
const UNAVAILABLE_MESSAGE: &str = "locator exchange unavailable";

impl LocatorExchangeError {
    /// Stable surfaced code for the error.
    ///
    /// Like [`Display`], this must not distinguish the three unresolvable
    /// reasons; all three share one code. Matching on the variants is for
    /// vault-side internals only.
    pub fn code(&self) -> &'static str {
        match self {
            LocatorExchangeError::Unknown
            | LocatorExchangeError::EntryRevoked
            | LocatorExchangeError::ResourceRevoked => "locator_unavailable",
            LocatorExchangeError::Exhausted => "locator_limit_reached",
            LocatorExchangeError::Internal => "locator_exchange_failed",
        }
    }
}

impl core::fmt::Display for LocatorExchangeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // Existence-oracle defense: unknown, entry-revoked, and
            // resource-revoked render as one fixed string. Never "not found"
            // versus "revoked" — that difference is the leak.
            LocatorExchangeError::Unknown
            | LocatorExchangeError::EntryRevoked
            | LocatorExchangeError::ResourceRevoked => f.write_str(UNAVAILABLE_MESSAGE),
            LocatorExchangeError::Exhausted => f.write_str("locator exchange limit reached"),
            LocatorExchangeError::Internal => f.write_str("locator exchange failed"),
        }
    }
}

impl std::error::Error for LocatorExchangeError {}

/// The vault-side mapping for one locator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatorRecord {
    /// Internal resource the locator names.
    pub resource: InternalResourceId,
    /// Whether this mapping has been revoked. A revoked mapping never
    /// exchanges, but — by the oracle defense — fails exactly like an
    /// unknown one from the caller's point of view.
    pub revoked: bool,
}

impl LocatorRecord {
    /// A live mapping to `resource`.
    pub fn new(resource: InternalResourceId) -> Self {
        LocatorRecord {
            resource,
            revoked: false,
        }
    }
}

/// Aggregate state of a resource, as seen by locator exchange.
///
/// The counters live here, keyed by resource — **not** in the issued token.
/// ADR-0016 §2: the limits are properties of the resource, not of the handle
/// issued for it, so re-exchanging a locator cannot reset them. The counter
/// has no setter and no constructor argument: the only way it moves is a
/// successful [`LocatorLedger::exchange`], so a caller cannot accidentally
/// (or deliberately) hand back a smaller number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceState {
    /// Whether the resource itself has been revoked.
    pub revoked: bool,
    /// Maximum total exchanges across every locator naming the resource.
    pub max_uses: Option<u32>,
    use_count: u32,
}

impl ResourceState {
    /// Fresh aggregate state for a resource capped at `max_uses`.
    pub fn new(max_uses: Option<u32>) -> Self {
        ResourceState {
            revoked: false,
            max_uses,
            use_count: 0,
        }
    }

    /// Exchanges consumed so far, across every locator naming the resource.
    pub fn use_count(&self) -> u32 {
        self.use_count
    }

    /// Consumes one use, refusing only when the aggregate cap is reached.
    fn consume(&mut self) -> std::result::Result<(), LocatorExchangeError> {
        if let Some(max) = self.max_uses {
            if self.use_count >= max {
                return Err(LocatorExchangeError::Exhausted);
            }
        }
        self.use_count = self
            .use_count
            .checked_add(1)
            .ok_or(LocatorExchangeError::Exhausted)?;
        Ok(())
    }
}

/// The vault-side locator mapping and the exchange contract over it.
///
/// This is the pure-logic slice of ADR-0016 §2: the mapping from locator to
/// [`InternalResourceId`] plus the aggregate state exchange consults. It
/// performs no I/O and holds no keys; a full registry wraps this with
/// encrypted, authenticated storage and principal authentication.
#[derive(Debug, Default)]
pub struct LocatorLedger {
    records: BTreeMap<[u8; LOCATOR_BYTES], LocatorRecord>,
    resources: BTreeMap<InternalResourceId, ResourceState>,
}

impl LocatorLedger {
    /// Creates an empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Maps `locator` to `resource`, creating the resource's aggregate state.
    ///
    /// Refuses an already-mapped locator rather than overwriting: remapping a
    /// published marker would silently relocate what a file in the wild
    /// points at.
    pub fn map(&mut self, locator: &PublicLocator, resource: InternalResourceId) -> Result<()> {
        if self.records.contains_key(locator.id()) {
            return Err(RuntimeError::InvalidStructure);
        }
        self.resources
            .entry(resource.clone())
            .or_insert_with(|| ResourceState::new(None));
        self.records
            .insert(*locator.id(), LocatorRecord::new(resource));
        Ok(())
    }

    /// Revokes one locator's mapping. Idempotent.
    pub fn revoke_entry(&mut self, locator: &PublicLocator) {
        if let Some(record) = self.records.get_mut(locator.id()) {
            record.revoked = true;
        }
    }

    /// Revokes a resource, failing exchange for *every* locator naming it.
    /// Idempotent.
    pub fn revoke_resource(&mut self, resource: &InternalResourceId) {
        if let Some(state) = self.resources.get_mut(resource) {
            state.revoked = true;
        }
    }

    /// Exchanges a locator for a freshly scoped, expiring [`ReferenceToken`].
    ///
    /// A locator is never dereferenced directly; this is the only path from a
    /// published marker toward material, and it applies revocation and
    /// aggregate limits *now* — so policy changes and revocation reach
    /// markers that were written to disk long ago.
    ///
    /// Failure reasons are returned as [`LocatorExchangeError`]; unknown and
    /// revoked are indistinguishable on the surfaced surface by design. The
    /// use is consumed before the token is minted, so a failure after
    /// consumption may lose a use but can never replay one.
    pub fn exchange(
        &mut self,
        locator: &PublicLocator,
    ) -> std::result::Result<ReferenceToken, LocatorExchangeError> {
        let record = self
            .records
            .get(locator.id())
            .ok_or(LocatorExchangeError::Unknown)?;
        if record.revoked {
            return Err(LocatorExchangeError::EntryRevoked);
        }
        let state = self
            .resources
            .get_mut(&record.resource)
            .ok_or(LocatorExchangeError::Unknown)?;
        if state.revoked {
            return Err(LocatorExchangeError::ResourceRevoked);
        }
        state.consume()?;
        ReferenceToken::generate().map_err(|_| LocatorExchangeError::Internal)
    }

    /// The resource a locator names, for vault-side diagnostics only.
    ///
    /// This is the internal view; it is *not* part of the surfaced exchange
    /// contract and must never be exposed across the mediation boundary.
    pub fn resource_of(&self, locator: &PublicLocator) -> Option<&InternalResourceId> {
        self.records.get(locator.id()).map(|r| &r.resource)
    }

    /// Aggregate exchange count for a resource, for tests and diagnostics.
    pub fn use_count(&self, resource: &InternalResourceId) -> Option<u32> {
        self.resources.get(resource).map(ResourceState::use_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapped_ledger(resource: &str, max_uses: Option<u32>) -> (LocatorLedger, PublicLocator) {
        let mut ledger = LocatorLedger::new();
        let locator = PublicLocator::generate().expect("csprng");
        ledger
            .map(&locator, InternalResourceId::from(resource))
            .expect("map");
        ledger
            .resources
            .get_mut(&InternalResourceId::from(resource))
            .expect("state")
            .max_uses = max_uses;
        (ledger, locator)
    }

    #[test]
    fn locator_roundtrips_through_its_external_form() {
        let locator = PublicLocator::generate().expect("csprng");
        let parsed = PublicLocator::parse(&locator.to_external()).expect("roundtrip");
        assert_eq!(parsed, locator);
    }

    #[test]
    fn external_form_has_the_versioned_wire_shape() {
        let external = PublicLocator::generate().expect("csprng").to_external();
        assert!(external.starts_with("[SV:LOC:v1:"));
        assert!(external.ends_with(']'));
        // base64url of 32 bytes is 43 characters, unpadded.
        assert_eq!(external.len(), "[SV:LOC:v1:".len() + 43 + 1);
        let body = &external["[SV:LOC:v1:".len()..external.len() - 1];
        assert!(!body.contains('='));
        assert!(!body.contains('+'));
        assert!(!body.contains('/'));
    }

    #[test]
    fn parse_rejects_malformed_locators() {
        let valid = PublicLocator::generate().expect("csprng").to_external();
        let body = valid
            .strip_prefix(LOCATOR_PREFIX)
            .and_then(|v| v.strip_suffix(LOCATOR_SUFFIX))
            .expect("valid shape");

        let cases = [
            String::new(),
            "[SV:LOC".to_string(),
            "[SV:LOC:v2:{body}]".to_string(),
            "[sv:loc:v1:{body}]".to_string(),
            "[SV:LOC:V1:{body}]".to_string(),
            body.to_string(),
            format!("{LOCATOR_PREFIX}{body}"),
            format!("{body}{LOCATOR_SUFFIX}"),
            format!("{LOCATOR_PREFIX}{body}]x"),
            format!("{LOCATOR_PREFIX}x{body}{LOCATOR_SUFFIX}"),
            format!(
                "{LOCATOR_PREFIX}{}{LOCATOR_SUFFIX}",
                &body[..body.len() - 1]
            ),
            format!("{LOCATOR_PREFIX}{body}AA{LOCATOR_SUFFIX}"),
            format!("{LOCATOR_PREFIX}{body}={LOCATOR_SUFFIX}"),
            format!(
                "{LOCATOR_PREFIX}{}+{LOCATOR_SUFFIX}",
                &body[..body.len() - 1]
            ),
            format!(
                "{LOCATOR_PREFIX}{}/x{LOCATOR_SUFFIX}",
                &body[..body.len() - 2]
            ),
            format!("{LOCATOR_PREFIX}{LOCATOR_SUFFIX}"),
        ];
        for case in &cases {
            assert_eq!(
                PublicLocator::parse(case).expect_err("must reject"),
                RuntimeError::ReferenceInvalid,
                "accepted malformed locator {case:?}"
            );
        }
    }

    /// ADR-0016 §1: two occurrences of the same value receive two unrelated
    /// locators. Equality of the underlying value must not be observable
    /// from the markers, so `generate` takes no value and no two mints agree.
    #[test]
    fn two_locators_for_identical_values_are_unrelated() {
        let value = "jane.doe+spam@example.co.uk";
        let first = PublicLocator::generate().expect("csprng");
        let second = PublicLocator::generate().expect("csprng");
        assert_ne!(first, second, "same value must not correlate locators");
        assert_ne!(first.to_external(), second.to_external());

        let mut externals: Vec<String> = (0..256)
            .map(|_| PublicLocator::generate().expect("csprng").to_external())
            .collect();
        externals.sort();
        let before = externals.len();
        externals.dedup();
        assert_eq!(externals.len(), before, "locator collision");
        let mut bodies: Vec<&str> = externals
            .iter()
            .map(|e| {
                e.strip_prefix(LOCATOR_PREFIX)
                    .and_then(|v| v.strip_suffix(LOCATOR_SUFFIX))
                    .expect("valid shape")
            })
            .collect();
        bodies.sort_unstable();
        // No two identifier bodies collide, and none shares a long prefix
        // with another. The constant wire prefix is excluded: everything
        // shares that by construction.
        for pair in bodies.windows(2) {
            let shared = pair[0]
                .chars()
                .zip(pair[1].chars())
                .take_while(|(a, b)| a == b)
                .count();
            assert!(shared < 8, "locators share a {shared}-character prefix");
        }
        let _ = value;
    }

    #[test]
    fn debug_never_shows_the_id() {
        let locator = PublicLocator::generate().expect("csprng");
        let rendered = format!("{locator:?}");
        assert_eq!(rendered, "PublicLocator([REDACTED])");
        assert!(!rendered.contains(&locator.to_external()));
    }

    /// The existence-oracle defense: an unknown locator, a revoked registry
    /// entry, and a revoked resource are indistinguishable on the surfaced
    /// surface (Display and code). Only the aggregate-limit reason may look
    /// different, and only after an authenticated lookup succeeded.
    #[test]
    fn unknown_and_revoked_are_indistinguishable_on_the_surfaced_error() {
        let (mut ledger, locator) = mapped_ledger("res-oracle", Some(8));

        // 1. Unknown: never mapped.
        let stranger = PublicLocator::generate().expect("csprng");
        let unknown = ledger.exchange(&stranger).expect_err("unknown must fail");

        // 2. Registry entry revoked.
        ledger.revoke_entry(&locator);
        let entry_revoked = ledger.exchange(&locator).expect_err("revoked must fail");

        // 3. Resource revoked (fresh live mapping, resource-level revocation).
        let (mut ledger2, locator2) = mapped_ledger("res-oracle-2", Some(8));
        ledger2.revoke_resource(&InternalResourceId::from("res-oracle-2"));
        let resource_revoked = ledger2.exchange(&locator2).expect_err("must fail");

        for error in [unknown, entry_revoked, resource_revoked] {
            assert_eq!(error.to_string(), UNAVAILABLE_MESSAGE);
            assert_eq!(error.code(), "locator_unavailable");
        }

        // The limit reason is a different axis and may be distinguishable.
        let (mut ledger3, locator3) = mapped_ledger("res-oracle-3", Some(0));
        assert_eq!(
            ledger3.exchange(&locator3).expect_err("exhausted"),
            LocatorExchangeError::Exhausted
        );
        assert_ne!(
            LocatorExchangeError::Exhausted.to_string(),
            UNAVAILABLE_MESSAGE
        );

        // No surfaced error echoes locator material.
        let external = locator.to_external();
        assert!(!unknown.to_string().contains(&external));
    }

    /// ADR-0016 §2: re-exchanging a locator does not reset aggregate limits.
    /// The counter lives on the resource, has no setter, and only moves
    /// through successful exchange, so a caller cannot hand back a stale
    /// number.
    #[test]
    fn re_exchange_never_resets_aggregate_limits() {
        let (mut ledger, locator) = mapped_ledger("res-capped", Some(2));
        let resource = InternalResourceId::from("res-capped");

        ledger.exchange(&locator).expect("first exchange");
        ledger.exchange(&locator).expect("second exchange");
        assert_eq!(ledger.use_count(&resource), Some(2));

        for _ in 0..3 {
            assert!(
                matches!(
                    ledger.exchange(&locator),
                    Err(LocatorExchangeError::Exhausted)
                ),
                "cap must hold no matter how often the same locator is reused"
            );
        }
        // Failed attempts never move the counter, in either direction.
        assert_eq!(ledger.use_count(&resource), Some(2));

        // A second locator naming the same resource draws on the SAME
        // aggregate: limits are the resource's, not the marker's.
        let other = PublicLocator::generate().expect("csprng");
        ledger.map(&other, resource.clone()).expect("map");
        assert!(matches!(
            ledger.exchange(&other),
            Err(LocatorExchangeError::Exhausted)
        ));
        assert_eq!(ledger.use_count(&resource), Some(2));
    }

    #[test]
    fn map_refuses_remapping_a_published_locator() {
        let mut ledger = LocatorLedger::new();
        let locator = PublicLocator::generate().expect("csprng");
        ledger
            .map(&locator, InternalResourceId::from("r1"))
            .expect("first map");
        assert!(ledger
            .map(&locator, InternalResourceId::from("r2"))
            .is_err());
        assert_eq!(
            ledger.resource_of(&locator),
            Some(&InternalResourceId::from("r1")),
            "a published marker must never be silently relocated"
        );
    }
}
