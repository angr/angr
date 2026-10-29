//! State types for automata.

use fixedbitset::FixedBitSet;
use std::fmt;
use std::hash::{Hash, Hasher};

/// A state identifier represented as a u32.
pub type StateId = u32;

/// A set of states implemented using a fixed-size bit set for efficiency.
///
/// Equality and hashing ignore capacity (`FixedBitSet`'s own impls compare its length).
#[derive(Clone)]
pub struct StateSet {
    bits: FixedBitSet,
}

impl PartialEq for StateSet {
    fn eq(&self, other: &Self) -> bool {
        self.bits.ones().eq(other.bits.ones())
    }
}

impl Eq for StateSet {}

impl Hash for StateSet {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // the length makes the member sequence prefix-free
        self.len().hash(state);
        for member in self.iter() {
            member.hash(state);
        }
    }
}

impl StateSet {
    /// Create a new empty state set with the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bits: FixedBitSet::with_capacity(capacity),
        }
    }

    /// Create a state set containing a single state.
    pub fn singleton(state: StateId, capacity: usize) -> Self {
        let mut set = Self::with_capacity(capacity);
        set.insert(state);
        set
    }

    /// Insert a state into the set.
    pub fn insert(&mut self, state: StateId) {
        let idx = state as usize;
        if idx >= self.bits.len() {
            self.bits.grow(idx + 1);
        }
        self.bits.insert(idx);
    }

    /// Check if the set contains a state.
    pub fn contains(&self, state: StateId) -> bool {
        let idx = state as usize;
        if idx >= self.bits.len() {
            false
        } else {
            self.bits.contains(idx)
        }
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.bits.is_clear()
    }

    /// Get the number of states in the set.
    pub fn len(&self) -> usize {
        self.bits.count_ones(..)
    }

    /// Iterate over all states in the set.
    pub fn iter(&self) -> impl Iterator<Item = StateId> + '_ {
        self.bits.ones().map(|i| i as StateId)
    }

    /// Union this set with another, modifying self in place.
    pub fn union_with(&mut self, other: &StateSet) {
        if other.bits.len() > self.bits.len() {
            self.bits.grow(other.bits.len());
        }
        self.bits.union_with(&other.bits);
    }

    /// Check if this set intersects with another.
    pub fn intersects(&self, other: &StateSet) -> bool {
        self.bits.intersection(&other.bits).next().is_some()
    }

    /// Create a new set that is the intersection of this set and another.
    pub fn intersection(&self, other: &StateSet) -> StateSet {
        let mut result = self.clone();
        let max_len = std::cmp::max(result.bits.len(), other.bits.len());
        result.bits.grow(max_len);
        result.bits.intersect_with(&other.bits);
        result
    }

    /// Create a new set with states not in other.
    pub fn difference(&self, other: &StateSet) -> StateSet {
        let mut result = self.clone();
        result.bits.difference_with(&other.bits);
        result
    }

    /// Remove a state from the set.
    pub fn remove(&mut self, state: StateId) {
        let idx = state as usize;
        if idx < self.bits.len() {
            self.bits.set(idx, false);
        }
    }

    /// Clear all states from the set.
    pub fn clear(&mut self) {
        self.bits.clear();
    }

    /// Get a canonical representation for hashing (as a sorted vec).
    pub fn to_vec(&self) -> Vec<StateId> {
        self.iter().collect()
    }
}

impl fmt::Debug for StateSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl FromIterator<StateId> for StateSet {
    fn from_iter<I: IntoIterator<Item = StateId>>(iter: I) -> Self {
        let items: Vec<StateId> = iter.into_iter().collect();
        let capacity = items.iter().copied().max().map_or(0, |m| m as usize + 1);
        let mut set = Self::with_capacity(capacity);
        for state in items {
            set.insert(state);
        }
        set
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_set_basic() {
        let mut set = StateSet::with_capacity(10);
        assert!(set.is_empty());

        set.insert(3);
        set.insert(7);
        assert!(!set.is_empty());
        assert_eq!(set.len(), 2);
        assert!(set.contains(3));
        assert!(set.contains(7));
        assert!(!set.contains(5));
    }

    #[test]
    fn test_state_set_union() {
        let mut set1 = StateSet::with_capacity(10);
        set1.insert(1);
        set1.insert(3);

        let mut set2 = StateSet::with_capacity(10);
        set2.insert(2);
        set2.insert(3);

        set1.union_with(&set2);
        assert_eq!(set1.len(), 3);
        assert!(set1.contains(1));
        assert!(set1.contains(2));
        assert!(set1.contains(3));
    }

    #[test]
    fn test_state_set_intersection() {
        let mut set1 = StateSet::with_capacity(10);
        set1.insert(1);
        set1.insert(3);
        set1.insert(5);

        let mut set2 = StateSet::with_capacity(10);
        set2.insert(2);
        set2.insert(3);
        set2.insert(5);

        let inter = set1.intersection(&set2);
        assert_eq!(inter.len(), 2);
        assert!(inter.contains(3));
        assert!(inter.contains(5));
    }

    #[test]
    fn test_state_set_singleton() {
        let set = StateSet::singleton(5, 10);
        assert_eq!(set.len(), 1);
        assert!(set.contains(5));
    }

    #[test]
    fn test_state_set_eq_and_hash_ignore_capacity() {
        use std::collections::HashSet;
        use std::hash::DefaultHasher;

        fn hash_of(set: &StateSet) -> u64 {
            let mut hasher = DefaultHasher::new();
            set.hash(&mut hasher);
            hasher.finish()
        }

        let mut small = StateSet::with_capacity(16);
        small.insert(3);
        let large = StateSet::singleton(3, 100);
        assert_eq!(small, large);
        assert_eq!(hash_of(&small), hash_of(&large));

        // a set that grew and shrank back is equal to one that never grew
        let mut grown = StateSet::with_capacity(4);
        grown.insert(3);
        grown.insert(64);
        grown.remove(64);
        assert_eq!(grown, small);
        assert_eq!(hash_of(&grown), hash_of(&small));

        assert_eq!(StateSet::with_capacity(0), StateSet::with_capacity(256));

        // different members still differ
        assert_ne!(small, StateSet::singleton(4, 100));
        assert_ne!(small, StateSet::from_iter([3, 4]));

        let keys: HashSet<StateSet> = [small, large, grown].into_iter().collect();
        assert_eq!(keys.len(), 1);
    }
}
