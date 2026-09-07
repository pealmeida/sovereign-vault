//! Named, versioned checksum validators for national identifiers.
//!
//! Per ADR-0018 a bare `Mod11`/`Mod97` enum does not specify a validator:
//! normalisation, weighting, excluded sentinel values, and checksum position
//! differ per identifier. Each validator here is a distinct, versioned
//! variant with its own test vectors. Where the published algorithm could
//! not be sourced with confidence, the validator enforces structure only and
//! says so in its doc comment — a guessed checksum would silently reject
//! real identifiers, which is worse than no checksum.

use serde::Deserialize;

/// The known validators a pack rule may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorId {
    /// Luhn (mod-10) over the digits, ignoring separators. Cards, CA SIN.
    /// Source: Luhn, H.P., "Computer for Verifying Numbers", US Patent
    /// 2,950,048 (1960) — the standard right-to-left doubling variant.
    LuhnV1,
    /// IBAN: mod-97-10 over the rearranged, letter-mapped string
    /// (ISO 13616). Source: ISO 13616-1 §6.2, check digit generation by
    /// `98 - (value mod 97)`, validation by remainder 1.
    IbanV1,
    /// Verhoeff dihedral checksum. India Aadhaar. Source: Verhoeff (1969),
    /// "Error Detecting Decimal Codes", using the published d/p/inv tables.
    VerhoeffV1,
    /// Brazilian CPF: the two mod-11 check digits, rejecting repdigits.
    /// Source: Receita Federal check-digit specification; repdigits pass the
    /// arithmetic but are never real (matches `sv-privacy`'s behaviour).
    CpfV1,
    /// Brazilian CNPJ: the two mod-11 check digits with the standard weights
    /// (5,4,3,2,9,8,7,6,5,4,3,2 / 6,...,2), rejecting repdigits.
    /// Source: Receita Federal specification.
    CnpjV1,
    /// Spanish DNI: the check LETTER from `number mod 23` mapped through
    /// "TRWAGMYFPDXBNJZSQVHLCKE". Source: Spanish DNI letter algorithm
    /// (publicly documented by the Dirección General de la Policía).
    DniV1,
    /// UK NINO: prefix-letter and suffix-letter STRUCTURAL rules only.
    /// NINO has no checksum. Enforced: ordinary prefixes drawn from A-Z
    /// excluding D, F, I, Q, U, V; O additionally excluded in the first
    /// position; the prohibited prefix pairs BG, GB, NK, KN, TN, NT, ZZ;
    /// the official "QQ" temporary-NINO prefix; six digits; suffix A-D.
    /// No numeric-pair rules are enforced. Source: HMRC / DWP published
    /// NINO format guidance.
    NinoV1,
    /// German Steuer-ID: STRUCTURAL rules only — 11 digits, and among the
    /// first ten exactly one digit value appears exactly twice while every
    /// other value appears exactly once. The published mod-11 check digit
    /// (Bundesfinanzministerium specification, 2011 revision) is NOT
    /// verified here: implementing it from memory risks silently rejecting
    /// real Steuer-IDs, so it is left unverified deliberately.
    SteuerIdV1,
    /// Italian Codice Fiscale: the final check character from the odd/even
    /// character maps, summed mod 26 into A-Z. Source: Agenzia delle
    /// Entrate Codice Fiscale derivation rules (published odd/even tables).
    CodiceFiscaleV1,
    /// No validation: the pattern alone decides.
    None,
}

impl ValidatorId {
    /// Validate one candidate. Returns false when the candidate is
    /// structurally invalid for this identifier type.
    pub fn validate(self, candidate: &str) -> bool {
        match self {
            ValidatorId::LuhnV1 => validate_luhn(candidate),
            ValidatorId::IbanV1 => validate_iban(candidate),
            ValidatorId::VerhoeffV1 => validate_verhoeff(candidate),
            ValidatorId::CpfV1 => validate_cpf(candidate),
            ValidatorId::CnpjV1 => validate_cnpj(candidate),
            ValidatorId::DniV1 => validate_dni(candidate),
            ValidatorId::NinoV1 => validate_nino(candidate),
            ValidatorId::SteuerIdV1 => validate_steuer_id(candidate),
            ValidatorId::CodiceFiscaleV1 => validate_codice_fiscale(candidate),
            ValidatorId::None => true,
        }
    }
}

/// Strips separator characters, keeping only ASCII digits; rejects any other
/// character. Used by digit-only validators with their own separator policy.
fn digits_only(candidate: &str, separators: &[char]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for c in candidate.chars() {
        if let Some(d) = c.to_digit(10) {
            out.push(d as u8);
        } else if !separators.contains(&c) {
            return None;
        }
    }
    Some(out)
}

/// Luhn mod-10 over the digits, ignoring spaces and hyphens.
fn validate_luhn(candidate: &str) -> bool {
    let Some(digits) = digits_only(candidate, &[' ', '-']) else {
        return false;
    };
    if digits.len() < 2 {
        return false;
    }
    let mut total: u32 = 0;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut v = d as u32;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        total += v;
        double = !double;
    }
    total.is_multiple_of(10)
}

/// IBAN mod-97-10 over the rearranged, letter-mapped string. Spaces and
/// hyphens are stripped; letters are upper-cased first.
fn validate_iban(candidate: &str) -> bool {
    let s: String = candidate
        .chars()
        .filter(|c| !matches!(c, ' ' | '-'))
        .collect();
    let s = s.to_ascii_uppercase();
    let bytes = s.as_bytes();
    if bytes.len() < 15 || bytes.len() > 34 {
        return false;
    }
    if !bytes[0].is_ascii_uppercase()
        || !bytes[1].is_ascii_uppercase()
        || !bytes[2].is_ascii_digit()
        || !bytes[3].is_ascii_digit()
    {
        return false;
    }
    if !bytes.iter().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    // Rearrange: move the first four chars to the end, map A-Z to 10-35,
    // stream the digits through the modulus (no bignum needed).
    let rearranged: Vec<u8> = bytes[4..].iter().chain(&bytes[..4]).copied().collect();
    let mut remainder: u32 = 0;
    for &b in &rearranged {
        let mapped: String = if b.is_ascii_digit() {
            (b - b'0').to_string()
        } else {
            (b - b'A' + 10).to_string()
        };
        for d in mapped.bytes() {
            remainder = (remainder * 10 + u32::from(d - b'0')) % 97;
        }
    }
    remainder == 1
}

/// Verhoeff dihedral check over the digits, ignoring spaces and hyphens.
fn validate_verhoeff(candidate: &str) -> bool {
    /// Dihedral group D5 addition table.
    const D: [[u8; 10]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];
    /// Permutation table, cycled by position index.
    const P: [[u8; 10]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];
    let Some(digits) = digits_only(candidate, &[' ', '-']) else {
        return false;
    };
    if digits.len() < 2 {
        return false;
    }
    let mut c: u8 = 0;
    for (i, &d) in digits.iter().rev().enumerate() {
        c = D[usize::from(c)][usize::from(P[i % 8][usize::from(d)])];
    }
    c == 0
}

/// CPF: 11 digits (dots and hyphen ignored), two mod-11 check digits,
/// repdigits rejected.
fn validate_cpf(candidate: &str) -> bool {
    let Some(d) = digits_only(candidate, &['.', '-', ' ']) else {
        return false;
    };
    if d.len() != 11 {
        return false;
    }
    if d.iter().all(|&x| x == d[0]) {
        return false;
    }
    let check = |slice: &[u8], weight_start: u32| -> u8 {
        let sum: u32 = slice
            .iter()
            .enumerate()
            .map(|(i, &x)| u32::from(x) * (weight_start - i as u32))
            .sum();
        let r = sum % 11;
        if r < 2 {
            0
        } else {
            (11 - r) as u8
        }
    };
    check(&d[..9], 10) == d[9] && check(&d[..10], 11) == d[10]
}

/// CNPJ: 14 digits (dots, slash, hyphen ignored), two mod-11 check digits
/// with the standard 5,4,3,2,9,8,7,6,5,4,3,2 weights, repdigits rejected.
fn validate_cnpj(candidate: &str) -> bool {
    let Some(d) = digits_only(candidate, &['.', '/', '-', ' ']) else {
        return false;
    };
    if d.len() != 14 {
        return false;
    }
    if d.iter().all(|&x| x == d[0]) {
        return false;
    }
    const W: [u32; 12] = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    let cd = |slice: &[u8], weights: &[u32]| -> u8 {
        let sum: u32 = slice
            .iter()
            .zip(weights)
            .map(|(&x, &w)| u32::from(x) * w)
            .sum();
        let r = sum % 11;
        if r < 2 {
            0
        } else {
            (11 - r) as u8
        }
    };
    let cd1 = cd(&d[..12], &W);
    if cd1 != d[12] {
        return false;
    }
    let mut w2 = Vec::with_capacity(13);
    w2.push(6);
    w2.extend_from_slice(&W);
    let cd2 = cd(&d[..13], &w2);
    cd2 == d[13]
}

/// Spanish DNI: 8 digits plus the mod-23 check letter.
fn validate_dni(candidate: &str) -> bool {
    let s: String = candidate
        .chars()
        .filter(|c| !matches!(c, ' ' | '-'))
        .collect();
    let bytes = s.as_bytes();
    if bytes.len() != 9 {
        return false;
    }
    if !bytes[..8].iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let letter = bytes[8];
    if !letter.is_ascii_uppercase() {
        return false;
    }
    let Ok(number) = s[..8].parse::<u64>() else {
        return false;
    };
    const LETTERS: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";
    LETTERS[(number % 23) as usize] == letter
}

/// UK NINO structural rules (documented on the variant; no checksum exists).
fn validate_nino(candidate: &str) -> bool {
    let s: String = candidate
        .chars()
        .filter(|c| !matches!(c, ' ' | '-'))
        .collect::<String>()
        .to_ascii_uppercase();
    let bytes = s.as_bytes();
    if bytes.len() != 9 {
        return false;
    }
    let first = bytes[0];
    let second = bytes[1];
    if !first.is_ascii_uppercase() || !second.is_ascii_uppercase() {
        return false;
    }
    if first == b'Q' && second == b'Q' {
        // "QQ" is the official temporary-NINO prefix and is allowed through
        // despite Q being excluded from ordinary prefixes.
    } else {
        const EXCLUDED: &[u8] = b"DFIQUV";
        if EXCLUDED.contains(&first) || EXCLUDED.contains(&second) || first == b'O' {
            return false;
        }
        const PROHIBITED: &[&[u8; 2]] = &[b"BG", b"GB", b"NK", b"KN", b"TN", b"NT", b"ZZ"];
        if PROHIBITED.contains(&&[first, second]) {
            return false;
        }
    }
    if !bytes[2..8].iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    (b'A'..=b'D').contains(&bytes[8])
}

/// German Steuer-ID structural rules (documented on the variant).
fn validate_steuer_id(candidate: &str) -> bool {
    let Some(d) = digits_only(candidate, &[]) else {
        return false;
    };
    if d.len() != 11 {
        return false;
    }
    let mut counts = [0usize; 10];
    for &digit in &d[..10] {
        counts[usize::from(digit)] += 1;
    }
    // Exactly one digit value appears exactly twice; every other value that
    // appears does so exactly once.
    let twice = counts.iter().filter(|&&c| c == 2).count();
    let more_than_twice = counts.iter().any(|&c| c > 2);
    twice == 1 && !more_than_twice
}

/// Italian Codice Fiscale: 15 body characters plus the mod-26 check letter.
fn validate_codice_fiscale(candidate: &str) -> bool {
    let s: String = candidate
        .chars()
        .filter(|c| !matches!(c, ' ' | '-'))
        .collect::<String>()
        .to_ascii_uppercase();
    let bytes = s.as_bytes();
    if bytes.len() != 16 {
        return false;
    }
    if !bytes[..15].iter().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    let check = bytes[15];
    if !check.is_ascii_uppercase() {
        return false;
    }
    /// Value of a character in an ODD (1-indexed) position.
    const ODD: [u32; 36] = [
        1, 0, 5, 7, 9, 13, 15, 17, 19, 21, // '0'..'9'
        1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24,
        23, // 'A'..'Z'
    ];
    let value = |b: u8| -> Option<u32> {
        match b {
            b'0'..=b'9' => Some(u32::from(b - b'0')),
            b'A'..=b'Z' => Some(u32::from(b - b'A' + 10)),
            _ => None,
        }
    };
    // Even (1-indexed) map: digits keep their value, letters use their
    // alphabet position 0-25. Odd positions use the published odd table.
    let even_value = |b: u8| -> Option<u32> {
        match b {
            b'0'..=b'9' => Some(u32::from(b - b'0')),
            b'A'..=b'Z' => Some(u32::from(b - b'A')),
            _ => None,
        }
    };
    let mut sum: u32 = 0;
    for (i, &b) in bytes[..15].iter().enumerate() {
        sum += if i % 2 == 0 {
            let Some(v) = value(b) else {
                return false;
            };
            ODD[v as usize]
        } else {
            let Some(v) = even_value(b) else {
                return false;
            };
            v
        };
    }
    let expected = b'A' + (sum % 26) as u8;
    expected == check
}
