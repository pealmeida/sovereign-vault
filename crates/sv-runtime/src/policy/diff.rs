//! Semantic diff between two validated policy snapshots.

use crate::policy::document::{AccessEffect, LimitsDocument, PolicyDocument, RuleDocument};
use crate::policy::snapshot::PolicySnapshot;
use crate::types::{ConsentMode, ExposureClass, RuleExposure};
use std::collections::{BTreeSet, HashMap};

/// One semantic change between two validated policy snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyChange {
    /// A rule present in the new snapshot only.  Field is the rule id.
    RuleAdded {
        /// Identifier of the added rule.
        rule_id: String,
    },
    /// A rule present in the old snapshot only.  Field is the rule id.
    RuleRemoved {
        /// Identifier of the removed rule.
        rule_id: String,
    },
    /// A rule whose match or effect changed.  Field is the rule id.
    RuleChanged {
        /// Identifier of the changed rule.
        rule_id: String,
    },
    /// A deny rule that no longer exists.  Field is the rule id.
    DenyRemoved {
        /// Identifier of the deny rule that no longer exists.
        rule_id: String,
    },
    /// A destination kind newly reachable by some allow rule.  Field is the kind.
    DestinationNewlyAllowed {
        /// Destination kind an allow rule now reaches.
        destination_kind: String,
    },
    /// A rule whose exposure moved toward release.  Field is the rule id.
    TransformationWeakened {
        /// Identifier of the rule whose exposure moved toward release.
        rule_id: String,
    },
    /// A rule whose exposure moved away from release.  Field is the rule id.
    TransformationStrengthened {
        /// Identifier of the rule whose exposure moved away from release.
        rule_id: String,
    },
    /// A rule whose consent requirement weakened.  Field is the rule id.
    ConsentWeakened {
        /// Identifier of the rule whose consent requirement weakened.
        rule_id: String,
    },
    /// A rule whose consent requirement strengthened.  Field is the rule id.
    ConsentStrengthened {
        /// Identifier of the rule whose consent requirement strengthened.
        rule_id: String,
    },
    /// A limit that became more permissive.  Field is the limit field name.
    LimitLoosened {
        /// Name of the limit field that became more permissive.
        field: &'static str,
    },
    /// A limit that became more restrictive.  Field is the limit field name.
    LimitTightened {
        /// Name of the limit field that became more restrictive.
        field: &'static str,
    },
    /// A registration present in the new snapshot only.  Fields are kind and id.
    RegistrationAdded {
        /// Registration kind, e.g. `provider_route`.
        kind: &'static str,
        /// Identifier of the added registration.
        id: String,
    },
    /// A registration present in the old snapshot only.  Fields are kind and id.
    RegistrationRemoved {
        /// Registration kind, e.g. `provider_route`.
        kind: &'static str,
        /// Identifier of the removed registration.
        id: String,
    },
}

/// The complete semantic difference between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyDiff {
    /// Every change, ordered highest-risk first.
    pub changes: Vec<PolicyChange>,
}

impl PolicyDiff {
    /// Returns whether the diff contains a change that widens what is allowed.
    pub fn has_risk_increase(&self) -> bool {
        self.changes.iter().any(|c| {
            matches!(
                c,
                PolicyChange::DenyRemoved { .. }
                    | PolicyChange::DestinationNewlyAllowed { .. }
                    | PolicyChange::TransformationWeakened { .. }
                    | PolicyChange::ConsentWeakened { .. }
                    | PolicyChange::LimitLoosened { .. }
            )
        })
    }
}

/// Computes the semantic difference between `old` and `new`.
pub fn diff(old: &PolicySnapshot, new: &PolicySnapshot) -> PolicyDiff {
    let mut changes = Vec::new();
    diff_rules(&mut changes, old.document(), new.document());
    diff_limits(&mut changes, &old.document().limits, &new.document().limits);
    diff_registrations(&mut changes, old.document(), new.document());
    changes.sort_by_key(risk_key);
    PolicyDiff { changes }
}

fn risk_key(c: &PolicyChange) -> u8 {
    match c {
        PolicyChange::DenyRemoved { .. } => 0,
        PolicyChange::DestinationNewlyAllowed { .. } => 1,
        PolicyChange::TransformationWeakened { .. } => 2,
        PolicyChange::ConsentWeakened { .. } => 3,
        PolicyChange::LimitLoosened { .. } => 4,
        _ => 5,
    }
}

fn diff_rules(changes: &mut Vec<PolicyChange>, old: &PolicyDocument, new: &PolicyDocument) {
    let old_map: HashMap<&String, &RuleDocument> = old.rule.iter().map(|r| (&r.id, r)).collect();
    let new_map: HashMap<&String, &RuleDocument> = new.rule.iter().map(|r| (&r.id, r)).collect();

    for (id, rule) in &old_map {
        if !new_map.contains_key(id) {
            changes.push(PolicyChange::RuleRemoved {
                rule_id: id.to_string(),
            });
            if rule.effect.access == AccessEffect::Deny {
                changes.push(PolicyChange::DenyRemoved {
                    rule_id: id.to_string(),
                });
            }
        }
    }

    for id in new_map.keys() {
        if !old_map.contains_key(id) {
            changes.push(PolicyChange::RuleAdded {
                rule_id: id.to_string(),
            });
        }
    }

    for id in old_map.keys() {
        if let (Some(o), Some(n)) = (old_map.get(id), new_map.get(id)) {
            if o.match_ != n.match_ || o.effect != n.effect {
                changes.push(PolicyChange::RuleChanged {
                    rule_id: id.to_string(),
                });
            }
            let old_class = o
                .effect
                .exposure
                .map(RuleExposure::class)
                .unwrap_or(ExposureClass::Raw);
            let new_class = n
                .effect
                .exposure
                .map(RuleExposure::class)
                .unwrap_or(ExposureClass::Raw);
            match new_class.cmp(&old_class) {
                std::cmp::Ordering::Less => {
                    changes.push(PolicyChange::TransformationWeakened {
                        rule_id: id.to_string(),
                    });
                }
                std::cmp::Ordering::Greater => {
                    changes.push(PolicyChange::TransformationStrengthened {
                        rule_id: id.to_string(),
                    });
                }
                _ => {}
            }
            let old_consent = o.effect.consent.unwrap_or(ConsentMode::None);
            let new_consent = n.effect.consent.unwrap_or(ConsentMode::None);
            match new_consent.cmp(&old_consent) {
                std::cmp::Ordering::Less => {
                    changes.push(PolicyChange::ConsentWeakened {
                        rule_id: id.to_string(),
                    });
                }
                std::cmp::Ordering::Greater => {
                    changes.push(PolicyChange::ConsentStrengthened {
                        rule_id: id.to_string(),
                    });
                }
                _ => {}
            }
        }
    }

    let old_allowed = allowed_kinds(&old.rule);
    let new_allowed = allowed_kinds(&new.rule);
    for kind in new_allowed.difference(&old_allowed) {
        changes.push(PolicyChange::DestinationNewlyAllowed {
            destination_kind: kind.clone(),
        });
    }
}

fn allowed_kinds(rules: &[RuleDocument]) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for r in rules {
        if r.effect.access == AccessEffect::Allow {
            if let Some(ref kinds) = r.match_.destination_kinds {
                for k in kinds {
                    set.insert(k.clone());
                }
            }
        }
    }
    set
}

fn diff_limits(changes: &mut Vec<PolicyChange>, old: &LimitsDocument, new: &LimitsDocument) {
    fn push<T: Ord>(changes: &mut Vec<PolicyChange>, old: T, new: T, field: &'static str) {
        match new.cmp(&old) {
            std::cmp::Ordering::Greater => changes.push(PolicyChange::LimitLoosened { field }),
            std::cmp::Ordering::Less => changes.push(PolicyChange::LimitTightened { field }),
            _ => {}
        }
    }
    push(
        changes,
        old.request_bytes,
        new.request_bytes,
        "request_bytes",
    );
    push(
        changes,
        old.fragment_bytes,
        new.fragment_bytes,
        "fragment_bytes",
    );
    push(
        changes,
        old.response_bytes,
        new.response_bytes,
        "response_bytes",
    );
    push(
        changes,
        old.concurrent_requests_per_principal,
        new.concurrent_requests_per_principal,
        "concurrent_requests_per_principal",
    );
    push(
        changes,
        old.request_timeout_ms,
        new.request_timeout_ms,
        "request_timeout_ms",
    );
    push(
        changes,
        old.consent_timeout_ms,
        new.consent_timeout_ms,
        "consent_timeout_ms",
    );
    push(
        changes,
        old.stream_boundary_bytes,
        new.stream_boundary_bytes,
        "stream_boundary_bytes",
    );
}

macro_rules! reg_diff {
    ($changes:expr, $old:expr, $new:expr, $kind:expr) => {{
        let old_ids: BTreeSet<&str> = $old.iter().map(|x| x.id.as_str()).collect();
        let new_ids: BTreeSet<&str> = $new.iter().map(|x| x.id.as_str()).collect();
        for id in new_ids.difference(&old_ids) {
            $changes.push(PolicyChange::RegistrationAdded {
                kind: $kind,
                id: id.to_string(),
            });
        }
        for id in old_ids.difference(&new_ids) {
            $changes.push(PolicyChange::RegistrationRemoved {
                kind: $kind,
                id: id.to_string(),
            });
        }
    }};
}

fn diff_registrations(changes: &mut Vec<PolicyChange>, old: &PolicyDocument, new: &PolicyDocument) {
    reg_diff!(
        changes,
        old.provider_route,
        new.provider_route,
        "provider_route"
    );
    reg_diff!(changes, old.mcp_server, new.mcp_server, "mcp_server");
    reg_diff!(
        changes,
        old.process_profile,
        new.process_profile,
        "process_profile"
    );
    reg_diff!(
        changes,
        old.reference_class,
        new.reference_class,
        "reference_class"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::document::parse;
    use crate::policy::snapshot::validate;
    use crate::types::PolicyVersion;

    fn snap(toml: &str) -> PolicySnapshot {
        let doc = parse(toml).expect("parse");
        validate(doc, PolicyVersion(1)).expect("validate")
    }

    fn base(extra: &str) -> String {
        format!(
            r#"schema = 1
            default_effect = "deny"
            policy_id = "policy.test"

            [limits]
            request_bytes = 1
            fragment_bytes = 1
            response_bytes = 1
            concurrent_requests_per_principal = 1
            request_timeout_ms = 1
            consent_timeout_ms = 1
            stream_boundary_bytes = 1
            {}"#,
            extra
        )
    }

    fn rule_tmpl(
        id: &str,
        access: &str,
        exposure: Option<&str>,
        consent: Option<&str>,
        kinds: &[&str],
    ) -> String {
        let mut s = format!(
            r#"[[rule]]
id = "{}"
priority = 1
[rule.match]
destination_kinds = {:?}
[rule.effect]
access = "{}"
audit = "required"
"#,
            id, kinds, access
        );
        if let Some(e) = exposure {
            s.push_str(&format!("exposure = \"{}\"\n", e));
        }
        if let Some(c) = consent {
            s.push_str(&format!("consent = \"{}\"\n", c));
        }
        s
    }

    fn provider(id: &str, base_url: &str, credential: &str) -> String {
        format!(
            r#"[[provider_route]]
id = "{}"
protocol = "https"
base_url = "{}"
credential_ref = "{}"
allowed_models = ["*"]
allowed_methods = ["POST"]
allowed_path_prefixes = ["/"]
follow_redirects = false
request_timeout_ms = 1000
max_response_bytes = 1000
"#,
            id, base_url, credential
        )
    }

    fn profile(id: &str, executable: &str) -> String {
        format!(
            r#"[[process_profile]]
id = "{}"
executable = "{}"
allow_children = false
timeout_ms = 1000
max_stdout_bytes = 1000
max_stderr_bytes = 1000
"#,
            id, executable
        )
    }

    #[test]
    fn identical_snapshots_have_no_changes() {
        let s = snap(&base(""));
        let d = diff(&s, &s);
        assert!(d.changes.is_empty());
        assert!(!d.has_risk_increase());
    }

    #[test]
    fn added_and_removed_rules_are_reported() {
        let old = snap(&base(&rule_tmpl("r1", "allow", None, None, &["files"])));
        let new = snap(&base(&rule_tmpl("r2", "allow", None, None, &["db"])));
        let d = diff(&old, &new);
        assert!(d.changes.contains(&PolicyChange::RuleRemoved {
            rule_id: "r1".into()
        }));
        assert!(d.changes.contains(&PolicyChange::RuleAdded {
            rule_id: "r2".into()
        }));
    }

    #[test]
    fn removing_a_deny_is_reported_as_deny_removed() {
        let old = snap(&base(&rule_tmpl("block", "deny", None, None, &["files"])));
        let new = snap(&base(""));
        let d = diff(&old, &new);
        assert!(d.changes.contains(&PolicyChange::DenyRemoved {
            rule_id: "block".into()
        }));
        assert!(d.has_risk_increase());
    }

    #[test]
    fn changed_rule_is_reported() {
        let old = snap(&base(&rule_tmpl("r1", "allow", None, None, &["files"])));
        let new = snap(&base(&rule_tmpl("r1", "allow", None, None, &["db"])));
        let d = diff(&old, &new);
        assert!(d.changes.contains(&PolicyChange::RuleChanged {
            rule_id: "r1".into()
        }));
    }

    #[test]
    fn weakened_and_strengthened_transformations_are_distinguished() {
        let old = snap(&base(&rule_tmpl(
            "r1",
            "allow",
            Some("reference-only"),
            None,
            &["files"],
        )));
        let new = snap(&base(&rule_tmpl(
            "r1",
            "allow",
            Some("redact"),
            None,
            &["files"],
        )));
        assert!(diff(&old, &new)
            .changes
            .contains(&PolicyChange::TransformationWeakened {
                rule_id: "r1".into()
            }));
        assert!(diff(&new, &old)
            .changes
            .contains(&PolicyChange::TransformationStrengthened {
                rule_id: "r1".into()
            }));
    }

    #[test]
    fn dropping_an_exposure_constraint_is_a_weakening() {
        let old = snap(&base(&rule_tmpl(
            "r1",
            "allow",
            Some("redact"),
            None,
            &["files"],
        )));
        let new = snap(&base(&rule_tmpl("r1", "allow", None, None, &["files"])));
        let d = diff(&old, &new);
        assert!(d.changes.contains(&PolicyChange::TransformationWeakened {
            rule_id: "r1".into()
        }));
    }

    #[test]
    fn weakened_and_strengthened_consent_are_distinguished() {
        let old = snap(&base(&rule_tmpl(
            "r1",
            "allow",
            None,
            Some("approval"),
            &["files"],
        )));
        let new = snap(&base(&rule_tmpl(
            "r1",
            "allow",
            None,
            Some("otp"),
            &["files"],
        )));
        assert!(diff(&old, &new)
            .changes
            .contains(&PolicyChange::ConsentStrengthened {
                rule_id: "r1".into()
            }));
        assert!(diff(&new, &old)
            .changes
            .contains(&PolicyChange::ConsentWeakened {
                rule_id: "r1".into()
            }));
    }

    #[test]
    fn loosened_and_tightened_limits_are_distinguished() {
        // Built directly rather than by substituting into `base`, so the
        // fixture cannot silently degenerate into two identical documents.
        let with_limits = |request_bytes: u64, concurrent: u32| {
            format!(
                r#"schema = 1
default_effect = "deny"
policy_id = "policy.test"

[limits]
request_bytes = {request_bytes}
fragment_bytes = 1
response_bytes = 1
concurrent_requests_per_principal = {concurrent}
request_timeout_ms = 1
consent_timeout_ms = 1
stream_boundary_bytes = 1
"#
            )
        };
        let old = snap(&with_limits(1, 1));
        let new = snap(&with_limits(2, 2));
        assert_ne!(old.digest(), new.digest(), "fixtures must actually differ");
        let fwd = diff(&old, &new);
        assert!(fwd.changes.contains(&PolicyChange::LimitLoosened {
            field: "request_bytes"
        }));
        assert!(fwd.changes.contains(&PolicyChange::LimitLoosened {
            field: "concurrent_requests_per_principal"
        }));
        let rev = diff(&new, &old);
        assert!(rev.changes.contains(&PolicyChange::LimitTightened {
            field: "request_bytes"
        }));
        assert!(rev.changes.contains(&PolicyChange::LimitTightened {
            field: "concurrent_requests_per_principal"
        }));
    }

    #[test]
    fn newly_allowed_destination_is_reported() {
        let old = snap(&base(&rule_tmpl("r1", "allow", None, None, &["files"])));
        let new = snap(&base(&rule_tmpl(
            "r1",
            "allow",
            None,
            None,
            &["files", "db"],
        )));
        let d = diff(&old, &new);
        assert!(d.changes.contains(&PolicyChange::DestinationNewlyAllowed {
            destination_kind: "db".into()
        }));
    }

    #[test]
    fn added_and_removed_registrations_are_reported() {
        let old = snap(&base(
            &(provider("p1", "https://a", "c1") + &profile("x1", "/bin/ls")),
        ));
        let new = snap(&base(
            &(provider("p2", "https://b", "c2") + &profile("x2", "/bin/cat")),
        ));
        let d = diff(&old, &new);
        assert!(d.changes.contains(&PolicyChange::RegistrationAdded {
            kind: "provider_route",
            id: "p2".into()
        }));
        assert!(d.changes.contains(&PolicyChange::RegistrationRemoved {
            kind: "provider_route",
            id: "p1".into()
        }));
        assert!(d.changes.contains(&PolicyChange::RegistrationAdded {
            kind: "process_profile",
            id: "x2".into()
        }));
        assert!(d.changes.contains(&PolicyChange::RegistrationRemoved {
            kind: "process_profile",
            id: "x1".into()
        }));
    }

    #[test]
    fn risk_increasing_changes_sort_first() {
        let old = snap(&base(
            &(rule_tmpl("deny1", "deny", None, None, &["files"])
                + &rule_tmpl("allow1", "allow", None, None, &["db"])),
        ));
        let new = snap(&base(&rule_tmpl("allow1", "allow", None, None, &["db"])));
        let d = diff(&old, &new);
        assert_eq!(
            d.changes[0],
            PolicyChange::DenyRemoved {
                rule_id: "deny1".into()
            }
        );
    }

    #[test]
    fn has_risk_increase_detects_widening() {
        let old = snap(&base(&rule_tmpl("deny1", "deny", None, None, &["files"])));
        let new = snap(&base(""));
        assert!(diff(&old, &new).has_risk_increase());

        // A tightened limit narrows what is permitted, so it is not a risk
        // increase. Built directly: substituting into `base` silently produced
        // two identical documents and the assertion passed vacuously.
        let with_request_bytes = |request_bytes: u64| {
            format!(
                r#"schema = 1
default_effect = "deny"
policy_id = "policy.test"

[limits]
request_bytes = {request_bytes}
fragment_bytes = 1
response_bytes = 1
concurrent_requests_per_principal = 1
request_timeout_ms = 1
consent_timeout_ms = 1
stream_boundary_bytes = 1
"#
            )
        };
        let t_old = snap(&with_request_bytes(2));
        let t_new = snap(&with_request_bytes(1));
        assert_ne!(t_old.digest(), t_new.digest(), "fixtures must differ");
        let tightened = diff(&t_old, &t_new);
        assert!(tightened.changes.contains(&PolicyChange::LimitTightened {
            field: "request_bytes"
        }));
        assert!(!tightened.has_risk_increase());
    }

    #[test]
    fn diff_never_leaks_credentials() {
        let old = snap(&base(&provider(
            "p1",
            "https://CANARY-2c55d.example",
            "CANARY-2c55d",
        )));
        let new = snap(&base(&profile("x1", "/CANARY-2c55d/bin/ls")));
        let d = diff(&old, &new);
        let rendered = format!("{:?}", d);
        assert!(!rendered.contains("CANARY-2c55d"));
    }
}
