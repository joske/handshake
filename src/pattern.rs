use std::str::FromStr;
use strum::EnumString;

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum Pattern {
    E,
    S,
    EE,
    ES,
    SE,
    SS,
    PSK,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString)]
pub enum Patterns {
    NN,
    NK,
    NX,
    XN,
    XK,
    XX,
    KN,
    KK,
    KX,
    IN,
    IK,
    IX,
}

/// parse the handshake name into a list of patterns
/// assumes only fundamental patterns exist (2 letters)
/// only XX is implemented
#[must_use]
pub fn parse_handshake_patterns(name: &str) -> Vec<Vec<Pattern>> {
    let mut patterns = Vec::new();
    let mut bits = name.split('_');
    if let Some(p) = bits.nth(1) {
        let s = &p[..2];
        let from_str = Patterns::from_str(s);
        if let Ok(p) = from_str {
            patterns = match p {
                Patterns::XX => {
                    vec![
                        vec![Pattern::E],
                        vec![Pattern::E, Pattern::EE, Pattern::S, Pattern::ES],
                        vec![Pattern::S, Pattern::SE, Pattern::PSK],
                    ]
                }
                _ => Vec::new(),
            };
        }
    }

    patterns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern() {
        let expected = vec![
            vec![Pattern::E],
            vec![Pattern::E, Pattern::EE, Pattern::S, Pattern::ES],
            vec![Pattern::S, Pattern::SE, Pattern::PSK],
        ];

        let handshake = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";
        let patterns = parse_handshake_patterns(handshake);
        assert_eq!(expected, patterns);
    }

    #[test]
    fn test_empty_pattern() {
        let handshake = "";
        let patterns = parse_handshake_patterns(handshake);
        assert_eq!(Vec::<Vec<Pattern>>::new(), patterns);
    }
}
