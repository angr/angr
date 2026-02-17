//! Symbol types for automata transitions.

/// A symbol identifier represented as a u32.
/// The special value `EPSILON` represents an epsilon (empty) transition.
pub type SymbolId = u32;

/// Special symbol ID representing epsilon (empty) transitions.
/// We use u32::MAX as the epsilon marker.
pub const EPSILON: SymbolId = u32::MAX;

/// Check if a symbol is an epsilon transition.
#[inline]
pub fn is_epsilon(symbol: SymbolId) -> bool {
    symbol == EPSILON
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epsilon() {
        assert!(is_epsilon(EPSILON));
        assert!(!is_epsilon(0));
        assert!(!is_epsilon(100));
    }
}
