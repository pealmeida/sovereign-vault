//! What is being approved, and its digest (ADR-0025 §6.3).
//!
//! The digest is the contract between the prompt and the commit: the
//! finisher only commits when the digest the verification was granted for
//! equals the digest of the operation as it stands now. The prompt text is
//! derived from the same description, never supplied by the renderer.

use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"sv-presence-op-v1";
/// Longest field value shown in a native prompt, in characters.
pub(crate) const MAX_FIELD_CHARS: usize = 48;
/// Longest native prompt text, in characters.
pub(crate) const MAX_PROMPT_CHARS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Field {
    name: &'static str,
    value: String,
    /// Shown in the native prompt. Bound-only fields are part of the digest
    /// and never displayed (ids, digests, epochs).
    shown: bool,
}

/// A complete, immutable description of one protected operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpDescriptor {
    kind: &'static str,
    fields: Vec<Field>,
}

/// SHA-256 over a length-prefixed encoding of an [`OpDescriptor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpDigest([u8; 32]);

impl OpDigest {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl OpDescriptor {
    pub fn new(kind: &'static str) -> Self {
        Self {
            kind,
            fields: Vec::new(),
        }
    }

    /// Add a field that is bound into the digest AND shown in the prompt.
    #[must_use]
    pub fn field(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.fields.push(Field {
            name,
            value: value.into(),
            shown: true,
        });
        self
    }

    /// Add a field that is bound into the digest but never shown.
    #[must_use]
    pub fn bind(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.fields.push(Field {
            name,
            value: value.into(),
            shown: false,
        });
        self
    }

    pub fn kind(&self) -> &'static str {
        self.kind
    }

    pub fn digest(&self) -> OpDigest {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        put(&mut hasher, self.kind.as_bytes());
        hasher.update((self.fields.len() as u64).to_be_bytes());
        for field in &self.fields {
            hasher.update([u8::from(field.shown)]);
            put(&mut hasher, field.name.as_bytes());
            put(&mut hasher, field.value.as_bytes());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        OpDigest(out)
    }

    /// Native prompt text: fixed words, then each shown field as
    /// `name "value"`, with control characters stripped, double quotes
    /// replaced, values truncated, and the whole bounded.
    pub fn prompt_text(&self) -> String {
        let mut text = format!("approve {}", self.kind.replace('_', " "));
        let shown: Vec<String> = self
            .fields
            .iter()
            .filter(|f| f.shown)
            .map(|f| format!("{} \"{}\"", f.name, sanitize(&f.value)))
            .collect();
        if !shown.is_empty() {
            text.push_str(" — ");
            text.push_str(&shown.join(", "));
        }
        truncate(&text, MAX_PROMPT_CHARS)
    }
}

fn put(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn sanitize(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == '"' { '\'' } else { c })
        .collect();
    truncate(&cleaned, MAX_FIELD_CHARS)
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut out: String = value.chars().take(max - 1).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_stable_for_equal_descriptions() {
        let a = OpDescriptor::new("read_file")
            .field("container", "notes")
            .field("file", "a.txt");
        let b = OpDescriptor::new("read_file")
            .field("container", "notes")
            .field("file", "a.txt");
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn digest_changes_with_any_field_kind_or_binding() {
        let base = OpDescriptor::new("read_file")
            .field("container", "notes")
            .bind("request_id", "1");
        assert_ne!(
            base.digest(),
            OpDescriptor::new("export_file")
                .field("container", "notes")
                .bind("request_id", "1")
                .digest()
        );
        assert_ne!(
            base.digest(),
            OpDescriptor::new("read_file")
                .field("container", "other")
                .bind("request_id", "1")
                .digest()
        );
        assert_ne!(
            base.digest(),
            OpDescriptor::new("read_file")
                .field("container", "notes")
                .bind("request_id", "2")
                .digest()
        );
    }

    #[test]
    fn digest_is_unambiguous_across_field_boundaries() {
        let a = OpDescriptor::new("k").field("x", "ab").field("y", "c");
        let b = OpDescriptor::new("k").field("x", "a").field("y", "bc");
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn shown_and_bound_fields_are_not_interchangeable() {
        let shown = OpDescriptor::new("k").field("x", "1");
        let bound = OpDescriptor::new("k").bind("x", "1");
        assert_ne!(shown.digest(), bound.digest());
    }

    #[test]
    fn prompt_text_strips_controls_and_quotes_and_truncates() {
        let op = OpDescriptor::new("read_file")
            .field("file", "evil\u{7}\n\"name\"")
            .field("container", "x".repeat(100))
            .bind("secret_binding", "never-shown");
        let text = op.prompt_text();
        assert!(!text.chars().any(char::is_control));
        assert!(!text.contains("never-shown"));
        assert!(text.starts_with("approve read file"));
        assert!(text.contains("file \"evil'name'\""));
        assert!(text.contains('…'));
        assert!(text.chars().count() <= MAX_PROMPT_CHARS);
    }
}
