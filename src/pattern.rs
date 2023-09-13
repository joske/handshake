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
/// does not support K patterns and other modifiers than pskx
#[must_use]
#[rustfmt::skip]
pub fn parse_handshake_patterns(name: &str) -> Vec<Vec<Pattern>> {
    let mut patterns = Vec::new();
    let mut bits = name.split('_');
    if let Some(p) = bits.nth(1) {
        let s = &p[..2];
        let from_str = Patterns::from_str(s);
        if let Ok(p) = from_str {
            patterns = match p {
                Patterns::NN => {
                    vec![
                        vec![Pattern::E],
                        vec![Pattern::E, Pattern::EE]
                    ]
                }
                Patterns::NX => {
                    vec![
                        vec![Pattern::E],
                        vec![Pattern::E, Pattern::EE, Pattern::S, Pattern::ES],
                    ]
                }
                Patterns::XN => {
                    vec![
                        vec![Pattern::E],
                        vec![Pattern::E, Pattern::EE],
                        vec![Pattern::S, Pattern::SE],
                    ]
                }
                Patterns::IN => {
                    vec![
                        vec![Pattern::E, Pattern::S],
                        vec![Pattern::E, Pattern::EE, Pattern::SE],
                    ]
                }
                Patterns::IX => {
                    vec![
                        vec![Pattern::E, Pattern::S],
                        vec![Pattern::E, Pattern::EE, Pattern::SE, Pattern::S, Pattern::ES],
                    ]
                }
                Patterns::XX => {
                    vec![
                        vec![Pattern::E],
                        vec![Pattern::E, Pattern::EE, Pattern::S, Pattern::ES],
                        vec![Pattern::S, Pattern::SE],
                    ]
                }
                _ => Vec::new(),
            };
        }
        let modifiers = &p[2..];
        if let Some(psk) = modifiers.strip_prefix("psk") {
            if let Ok(n) = psk.parse::<usize>() {
                if n == 0 {
                    // psk0 means at the start of the first message
                    patterns[0].insert(0, Pattern::PSK);
                } else {
                    // all other cases, add at the end
                    patterns[n - 1].push(Pattern::PSK);
                }
            }
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
            vec![Pattern::S, Pattern::SE],
        ];

        let handshake = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
        let patterns = parse_handshake_patterns(handshake);
        assert_eq!(expected, patterns);
    }

    #[test]
    fn test_pattern_psk0() {
        let expected = vec![
            vec![Pattern::PSK, Pattern::E],
            vec![Pattern::E, Pattern::EE, Pattern::S, Pattern::ES],
            vec![Pattern::S, Pattern::SE],
        ];

        let handshake = "Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s";
        let patterns = parse_handshake_patterns(handshake);
        assert_eq!(expected, patterns);
    }

    #[test]
    fn test_pattern_psk1() {
        let expected = vec![
            vec![Pattern::E, Pattern::PSK],
            vec![Pattern::E, Pattern::EE, Pattern::S, Pattern::ES],
            vec![Pattern::S, Pattern::SE],
        ];

        let handshake = "Noise_XXpsk1_25519_ChaChaPoly_BLAKE2s";
        let patterns = parse_handshake_patterns(handshake);
        assert_eq!(expected, patterns);
    }

    #[test]
    fn test_pattern_psk2() {
        let expected = vec![
            vec![Pattern::E],
            vec![Pattern::E, Pattern::EE, Pattern::S, Pattern::ES, Pattern::PSK],
            vec![Pattern::S, Pattern::SE],
        ];

        let handshake = "Noise_XXpsk2_25519_ChaChaPoly_BLAKE2s";
        let patterns = parse_handshake_patterns(handshake);
        assert_eq!(expected, patterns);
    }

    #[test]
    fn test_pattern_psk3() {
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
