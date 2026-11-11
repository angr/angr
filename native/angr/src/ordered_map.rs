//! An insertion-ordered map with O(1) removal.
//!
//! Iteration order is the order of insertion, like a Python dict or `IndexMap` with `shift_remove`; a removed key
//! that is inserted again goes to the end. Removal leaves a tombstone that later compactions drop, so removing is
//! amortized O(1) instead of `IndexMap::shift_remove`'s O(n).

use std::hash::Hash;
use std::ops::Index;

use rustc_hash::FxHashMap;

#[derive(Clone, Debug)]
pub struct OrderedMap<K, V> {
    slots: Vec<Option<(K, V)>>,
    index: FxHashMap<K, usize>,
}

impl<K, V> Default for OrderedMap<K, V> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            index: FxHashMap::default(),
        }
    }
}

impl<K: Copy + Eq + Hash, V> OrderedMap<K, V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn contains_key(&self, k: &K) -> bool {
        self.index.contains_key(k)
    }

    pub fn get(&self, k: &K) -> Option<&V> {
        let i = *self.index.get(k)?;
        self.slots[i].as_ref().map(|(_, v)| v)
    }

    pub fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        let i = *self.index.get(k)?;
        self.slots[i].as_mut().map(|(_, v)| v)
    }

    /// The value of `k`, inserting `f()` at the end first if `k` is missing.
    pub fn get_or_insert_with(&mut self, k: K, f: impl FnOnce() -> V) -> &mut V {
        let i = match self.index.get(&k) {
            Some(&i) => i,
            None => {
                let i = self.slots.len();
                self.slots.push(Some((k, f())));
                self.index.insert(k, i);
                i
            }
        };
        &mut self.slots[i].as_mut().expect("indexed slot is live").1
    }

    pub fn get_or_insert_default(&mut self, k: K) -> &mut V
    where
        V: Default,
    {
        self.get_or_insert_with(k, V::default)
    }

    /// Inserts or replaces; a replaced value keeps its position. Returns the old value.
    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        match self.index.get(&k) {
            Some(&i) => self.slots[i].replace((k, v)).map(|(_, old)| old),
            None => {
                self.index.insert(k, self.slots.len());
                self.slots.push(Some((k, v)));
                None
            }
        }
    }

    /// Removes `k` and keeps the order of the remaining entries.
    pub fn shift_remove(&mut self, k: &K) -> Option<V> {
        let i = self.index.remove(k)?;
        let v = self.slots[i].take().map(|(_, v)| v);
        if self.slots.len() > 32 && self.slots.len() > 2 * self.index.len() {
            self.compact();
        }
        v
    }

    fn compact(&mut self) {
        self.slots.retain(Option::is_some);
        for (i, slot) in self.slots.iter().enumerate() {
            let (k, _) = slot.as_ref().expect("retained slot is live");
            self.index.insert(*k, i);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.slots
            .iter()
            .filter_map(|s| s.as_ref().map(|(k, v)| (k, v)))
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.iter().map(|(k, _)| k)
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.iter().map(|(_, v)| v)
    }
}

impl<'a, K: Copy + Eq + Hash, V> IntoIterator for &'a OrderedMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = Box<dyn Iterator<Item = (&'a K, &'a V)> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

impl<K: Copy + Eq + Hash, V> Index<&K> for OrderedMap<K, V> {
    type Output = V;

    fn index(&self, k: &K) -> &V {
        self.get(k).expect("key not in OrderedMap")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_insertion_order_across_removals() {
        let mut m: OrderedMap<u64, u64> = OrderedMap::new();
        for i in 0..100 {
            m.insert(i, i * 10);
        }
        for i in (0..100).step_by(3) {
            assert_eq!(m.shift_remove(&i), Some(i * 10));
        }
        m.insert(0, 7);
        m.insert(1, 11);
        let keys: Vec<u64> = m.keys().copied().collect();
        let mut expected: Vec<u64> = (0..100).filter(|i| i % 3 != 0).collect();
        expected.push(0);
        assert_eq!(keys, expected);
        assert_eq!(m[&1], 11);
        assert_eq!(m.len(), expected.len());
        assert_eq!(m.shift_remove(&1000), None);
    }
}
