//! Pack loading, validation, and engine tests.

use sv_patterns::{
    builtin_packs, load_builtin, match_all, MatchBudget, PackError, PatternPack, ValidatedPack,
};

/// Builds a minimal valid pack with the given id and one four-digit rule.
fn tiny_pack(id: &str) -> ValidatedPack {
    let src = format!(
        r#"schema = "1"
id = "{id}"
version = "0.1.0"
name = "test pack"
jurisdictions = ["XX"]

[[rules]]
name = "digits"
description = "four digits"
pattern = '\b[0-9]{{4}}\b'
confidence = "low"
examples_valid = ["1234"]
examples_invalid = ["12"]
"#
    );
    PatternPack::from_toml(&src).unwrap().validate().unwrap()
}

#[test]
fn every_builtin_pack_loads_and_conforms() {
    for source in builtin_packs() {
        let pack = PatternPack::from_toml(source).unwrap().validate().unwrap();
        assert!(!pack.rules.is_empty());
    }
    for id in ["br-lgpd", "eu-gdpr", "us"] {
        let pack = load_builtin(id).unwrap_or_else(|e| panic!("{id} failed: {e}"));
        assert_eq!(pack.id, id);
    }
}

#[test]
fn unsupported_schema_is_rejected() {
    let src = r#"
schema = "2"
id = "test-pack"
version = "0.1.0"
name = "t"
jurisdictions = ["XX"]

[[rules]]
name = "digits"
description = "d"
pattern = '\b[0-9]{4}\b'
confidence = "low"
examples_valid = ["1234"]
examples_invalid = ["12"]
"#;
    let err = PatternPack::from_toml(src).unwrap().validate().unwrap_err();
    assert!(matches!(err, PackError::InvalidSchema { .. }));
    assert!(err.to_string().contains('2'));
}

#[test]
fn failing_valid_example_is_rejected_naming_the_rule() {
    let src = r#"
schema = "1"
id = "test-pack"
version = "0.1.0"
name = "t"
jurisdictions = ["XX"]

[[rules]]
name = "bad_rule"
description = "d"
pattern = '\bAB\b'
confidence = "low"
examples_valid = ["ZZ"]
examples_invalid = ["CD"]
"#;
    let err = PatternPack::from_toml(src).unwrap().validate().unwrap_err();
    match err {
        PackError::ValidExampleFailed { rule, index } => {
            assert_eq!(rule, "bad_rule");
            assert_eq!(index, 0);
        }
        other => panic!("expected ValidExampleFailed, got {other:?}"),
    }
}

#[test]
fn matching_invalid_example_is_rejected_naming_the_rule() {
    let src = r#"
schema = "1"
id = "test-pack"
version = "0.1.0"
name = "t"
jurisdictions = ["XX"]

[[rules]]
name = "leaky_rule"
description = "d"
pattern = '\bAB\b'
confidence = "low"
examples_valid = ["AB"]
examples_invalid = ["AB"]
"#;
    let err = PatternPack::from_toml(src).unwrap().validate().unwrap_err();
    match err {
        PackError::InvalidExampleMatched { rule, index } => {
            assert_eq!(rule, "leaky_rule");
            assert_eq!(index, 0);
        }
        other => panic!("expected InvalidExampleMatched, got {other:?}"),
    }
}

#[test]
fn pattern_failing_to_compile_is_rejected() {
    let src = r#"
schema = "1"
id = "test-pack"
version = "0.1.0"
name = "t"
jurisdictions = ["XX"]

[[rules]]
name = "huge_rule"
description = "d"
pattern = '(?:a{1000}){1000}'
confidence = "low"
examples_valid = ["a"]
examples_invalid = ["b"]
"#;
    let err = PatternPack::from_toml(src).unwrap().validate().unwrap_err();
    match err {
        PackError::PatternCompile { rule, .. } => assert_eq!(rule, "huge_rule"),
        other => panic!("expected PatternCompile, got {other:?}"),
    }
}

#[test]
fn duplicate_rule_names_are_rejected() {
    let src = r#"
schema = "1"
id = "test-pack"
version = "0.1.0"
name = "t"
jurisdictions = ["XX"]

[[rules]]
name = "dup"
description = "d"
pattern = '\b[0-9]{4}\b'
confidence = "low"
examples_valid = ["1234"]
examples_invalid = ["12"]

[[rules]]
name = "dup"
description = "d again"
pattern = '\b[0-9]{5}\b'
confidence = "low"
examples_valid = ["12345"]
examples_invalid = ["12"]
"#;
    let err = PatternPack::from_toml(src).unwrap().validate().unwrap_err();
    match err {
        PackError::DuplicateRuleName { pack_id, rule } => {
            assert_eq!(pack_id, "test-pack");
            assert_eq!(rule, "dup");
        }
        other => panic!("expected DuplicateRuleName, got {other:?}"),
    }
}

#[test]
fn oversize_pattern_empty_rules_and_bad_id_are_rejected() {
    let long_pattern = "a".repeat(5000);
    let src = format!(
        r#"
schema = "1"
id = "test-pack"
version = "0.1.0"
name = "t"
jurisdictions = ["XX"]

[[rules]]
name = "long_rule"
description = "d"
pattern = "{long_pattern}"
confidence = "low"
examples_valid = ["aaaa"]
examples_invalid = ["b"]
"#
    );
    let err = PatternPack::from_toml(&src)
        .unwrap()
        .validate()
        .unwrap_err();
    assert!(matches!(
        err,
        PackError::PatternTooLarge { rule } if rule == "long_rule"
    ));

    let empty = r#"
schema = "1"
id = "test-pack"
version = "0.1.0"
name = "t"
jurisdictions = ["XX"]
"#;
    assert!(matches!(
        PatternPack::from_toml(empty).unwrap().validate(),
        Err(PackError::EmptyRules)
    ));

    let bad_id = r#"
schema = "1"
id = "Bad_ID!"
version = "0.1.0"
name = "t"
jurisdictions = ["XX"]

[[rules]]
name = "digits"
description = "d"
pattern = '\b[0-9]{4}\b'
confidence = "low"
examples_valid = ["1234"]
examples_invalid = ["12"]
"#;
    assert!(matches!(
        PatternPack::from_toml(bad_id).unwrap().validate(),
        Err(PackError::InvalidPackId { .. })
    ));

    assert!(matches!(
        PatternPack::from_toml("not = [valid"),
        Err(PackError::InvalidToml(_))
    ));
    assert!(matches!(
        load_builtin("no-such-pack"),
        Err(PackError::UnknownBuiltin { .. })
    ));
}

#[test]
fn match_budget_exhaustion_sets_truncated() {
    let pack = tiny_pack("test-pack");
    let input = "1234 5678 9012";

    let full = match_all(std::slice::from_ref(&pack), input, &MatchBudget::default());
    assert_eq!(full.matches.len(), 3);
    assert!(!full.truncated);

    let clipped = match_all(
        std::slice::from_ref(&pack),
        input,
        &MatchBudget {
            max_matches: 2,
            ..MatchBudget::default()
        },
    );
    assert_eq!(clipped.matches.len(), 2);
    assert!(clipped.truncated);

    let filler = "x".repeat(40);
    let long_input = format!("1234 {filler} 5678");
    let byte_clipped = match_all(
        &[pack],
        &long_input,
        &MatchBudget {
            max_input_bytes: 20,
            ..MatchBudget::default()
        },
    );
    assert!(byte_clipped.truncated);
    assert_eq!(byte_clipped.matches.len(), 1);
}

#[test]
fn more_than_max_enabled_packs_truncates() {
    let packs: Vec<ValidatedPack> = (0..65).map(|i| tiny_pack(&format!("p{i}"))).collect();
    let outcome = match_all(&packs, "1234", &MatchBudget::default());
    assert!(outcome.truncated);
    // Only the first 64 packs contribute.
    assert_eq!(outcome.matches.len(), 64);
    assert!(outcome.matches.iter().all(|m| m.pack_id != "p64"));
}

#[test]
fn overlapping_matches_from_two_packs_are_both_returned() {
    let a = tiny_pack("pack-a");
    let b = tiny_pack("pack-b");
    let outcome = match_all(&[a, b], "code 1234 end", &MatchBudget::default());
    assert_eq!(outcome.matches.len(), 2);
    let ids: Vec<&str> = outcome.matches.iter().map(|m| m.rule_id.as_str()).collect();
    assert!(ids.contains(&"pack-a/digits"));
    assert!(ids.contains(&"pack-b/digits"));
    assert!(outcome.matches.iter().all(|m| m.start == 5 && m.end == 9));
}

#[test]
fn multi_byte_utf8_input_is_safe_with_correct_offsets() {
    let pack = load_builtin("br-lgpd").unwrap();
    let token = "111.444.777-35";
    let content = format!("café ünïcode {token} 日本語 ends");
    let outcome = match_all(&[pack], &content, &MatchBudget::default());
    assert_eq!(outcome.matches.len(), 1);
    let m = &outcome.matches[0];
    let expected_start = content.find(token).unwrap();
    assert_eq!(m.start, expected_start);
    assert_eq!(m.end, expected_start + token.len());
    assert!(content.is_char_boundary(m.start));
    assert!(content.is_char_boundary(m.end));
    assert_eq!(m.rule_id, "br-lgpd/cpf");
}

#[test]
fn validator_failure_suppresses_the_candidate() {
    let pack = load_builtin("eu-gdpr").unwrap();
    let good = "DE89370400440532013000";
    let bad = "DE89370400440532013001";
    let content = format!("{good} and {bad}");
    let outcome = match_all(&[pack], &content, &MatchBudget::default());
    assert_eq!(outcome.matches.len(), 1);
    assert_eq!(outcome.matches[0].rule_id, "eu-gdpr/iban");
    assert_eq!(outcome.matches[0].validated, Some(true));
    assert_eq!(outcome.matches[0].start, 0);
}

#[test]
fn unvalidated_rules_report_none() {
    let pack = load_builtin("us").unwrap();
    let outcome = match_all(&[pack], "number 123-45-6789", &MatchBudget::default());
    assert_eq!(outcome.matches.len(), 1);
    assert_eq!(outcome.matches[0].rule_id, "us/ssn");
    assert_eq!(outcome.matches[0].validated, None);
}

#[test]
fn matching_is_deterministic_across_runs() {
    let packs = [load_builtin("br-lgpd").unwrap(), tiny_pack("zz-pack")];
    let content = "1234 cpf 111.444.777-35 cnpj 04.252.011/0001-10 trailing 1234";
    let first = match_all(&packs, content, &MatchBudget::default());
    let second = match_all(&packs, content, &MatchBudget::default());
    assert_eq!(first, second);
    assert!(first.matches.windows(2).all(|w| w[0].start <= w[1].start));
}
