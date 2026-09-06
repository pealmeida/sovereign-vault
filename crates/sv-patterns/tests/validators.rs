//! Test vectors for every named validator. All values are synthetic; the
//! checksummed ones were computed to pass their checksums.

use sv_patterns::ValidatorId;

fn assert_valid(v: ValidatorId, cases: &[&str]) {
    for case in cases {
        assert!(v.validate(case), "{v:?} should accept {case:?}");
    }
}

fn assert_invalid(v: ValidatorId, cases: &[&str]) {
    for case in cases {
        assert!(!v.validate(case), "{v:?} should reject {case:?}");
    }
}

#[test]
fn luhn_v1_vectors() {
    let v = ValidatorId::LuhnV1;
    assert_valid(v, &["79927398713", "12345678903", "7992 7398-713"]);
    assert_invalid(v, &["79927398714", "7992739871", "12345", "79927398713X"]);
}

#[test]
fn iban_v1_vectors() {
    let v = ValidatorId::IbanV1;
    assert_valid(
        v,
        &[
            "DE89370400440532013000",
            "GB33BUKB20201555555555",
            "NL91ABNA0417164300",
            "GB33 BUKB 2020 1555 5555 55",
        ],
    );
    assert_invalid(
        v,
        &[
            "DE89370400440532013001",
            "GB82WEST12345698765400",
            "DE89",
            "89DE370400440532013000DE",
        ],
    );
}

#[test]
fn verhoeff_v1_vectors() {
    let v = ValidatorId::VerhoeffV1;
    assert_valid(v, &["2363", "123412341234", "987654321096"]);
    assert_invalid(v, &["123412341230", "987654321099", "1", ""]);
}

#[test]
fn cpf_v1_vectors() {
    let v = ValidatorId::CpfV1;
    assert_valid(v, &["11144477735", "12345678909", "111.444.777-35"]);
    assert_invalid(
        v,
        &["11144477736", "11111111111", "1114447773", "1114447773a"],
    );
}

#[test]
fn cnpj_v1_vectors() {
    let v = ValidatorId::CnpjV1;
    assert_valid(
        v,
        &["11222333000181", "04252011000110", "11.222.333/0001-81"],
    );
    assert_invalid(v, &["11222333000182", "11111111111111", "1122233300018"]);
}

#[test]
fn dni_v1_vectors() {
    let v = ValidatorId::DniV1;
    assert_valid(v, &["12345678Z", "23456789D", "87654321X", "00000000T"]);
    assert_invalid(v, &["12345678X", "1234567Z", "12345678z", "12345678"]);
}

#[test]
fn nino_v1_vectors() {
    let v = ValidatorId::NinoV1;
    assert_valid(v, &["QQ123456A", "AB123456C", "qq 1234 56 a"]);
    assert_invalid(
        v,
        &[
            "ZZ123456A",
            "DB123456A",
            "QQ123456E",
            "QQ12345A",
            "OQ123456A",
            "QZ123456A",
        ],
    );
}

#[test]
fn steuer_id_v1_vectors() {
    let v = ValidatorId::SteuerIdV1;
    assert_valid(v, &["26954371821", "12345678912"]);
    assert_invalid(
        v,
        &["11111111111", "12345678901", "12345678888", "2695437182"],
    );
}

#[test]
fn codice_fiscale_v1_vectors() {
    let v = ValidatorId::CodiceFiscaleV1;
    assert_valid(
        v,
        &["MRTMTT25D09F205Z", "ABCDEF12G34H567S", "RSSMRA80A01H501U"],
    );
    assert_invalid(
        v,
        &[
            "MRTMTT25D09F205Y",
            "MRTMTT25D09F205",
            "ABCDEF12G34H56",
            "MRTMTT25D09F2051",
        ],
    );
}

#[test]
fn none_validator_accepts_everything() {
    let v = ValidatorId::None;
    assert_valid(v, &["anything", "", "12 34"]);
}

#[test]
fn builtin_pack_vectors_double_as_validator_vectors() {
    // The bundled packs execute these same values at load time; loading them
    // again here ties the two test files together.
    for source in sv_patterns::builtin_packs() {
        sv_patterns::PatternPack::from_toml(source)
            .unwrap()
            .validate()
            .unwrap();
    }
}
