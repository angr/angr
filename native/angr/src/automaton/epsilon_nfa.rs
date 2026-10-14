//! Epsilon Non-deterministic Finite Automaton (ε-NFA) implementation.

use crate::automaton::state::{StateId, StateSet};
use crate::automaton::symbol::{EPSILON, SymbolId, is_epsilon};
use indexmap::IndexMap;
use std::collections::{HashSet, VecDeque};

/// An Epsilon Non-deterministic Finite Automaton.
#[derive(Debug, Clone)]
pub struct EpsilonNFA {
    /// Number of states (states are numbered 0..num_states)
    num_states: StateId,
    /// Start states
    start_states: StateSet,
    /// Final (accepting) states
    final_states: StateSet,
    /// Labeled out-edges per source state: (symbol, destination)
    out: Vec<Vec<(SymbolId, StateId)>>,
    /// Epsilon out-edges per source state
    eps: Vec<Vec<StateId>>,
    /// Deduplicates (source, symbol, destination)
    edge_set: HashSet<(StateId, SymbolId, StateId)>,
    /// All symbols used (excluding epsilon)
    alphabet: HashSet<SymbolId>,
}

impl EpsilonNFA {
    /// Create a new empty epsilon-NFA.
    pub fn new() -> Self {
        Self {
            num_states: 0,
            start_states: StateSet::with_capacity(16),
            final_states: StateSet::with_capacity(16),
            out: Vec::new(),
            eps: Vec::new(),
            edge_set: HashSet::new(),
            alphabet: HashSet::new(),
        }
    }

    /// Ensure a state exists, expanding num_states if needed.
    fn ensure_state(&mut self, state: StateId) {
        if state >= self.num_states {
            self.num_states = state + 1;
            self.out.resize_with(self.num_states as usize, Vec::new);
            self.eps.resize_with(self.num_states as usize, Vec::new);
        }
    }

    /// Add a transition from source to destination on the given symbol.
    pub fn add_transition(&mut self, source: StateId, symbol: SymbolId, destination: StateId) {
        self.ensure_state(source);
        self.ensure_state(destination);

        if !self.edge_set.insert((source, symbol, destination)) {
            return;
        }
        if is_epsilon(symbol) {
            self.eps[source as usize].push(destination);
        } else {
            self.alphabet.insert(symbol);
            self.out[source as usize].push((symbol, destination));
        }
    }

    /// Add an epsilon transition from source to destination.
    pub fn add_epsilon_transition(&mut self, source: StateId, destination: StateId) {
        self.add_transition(source, EPSILON, destination);
    }

    /// Add a start state.
    pub fn add_start_state(&mut self, state: StateId) {
        self.ensure_state(state);
        self.start_states.insert(state);
    }

    /// Add a final (accepting) state.
    pub fn add_final_state(&mut self, state: StateId) {
        self.ensure_state(state);
        self.final_states.insert(state);
    }

    /// Get the number of states.
    pub fn num_states(&self) -> StateId {
        self.num_states
    }

    /// Get the start states.
    pub fn start_states(&self) -> &StateSet {
        &self.start_states
    }

    /// Get the final states.
    pub fn final_states(&self) -> &StateSet {
        &self.final_states
    }

    /// Get the alphabet (all symbols except epsilon).
    pub fn alphabet(&self) -> &HashSet<SymbolId> {
        &self.alphabet
    }

    /// Labeled out-edges of a state.
    pub fn out_edges(&self, state: StateId) -> &[(SymbolId, StateId)] {
        &self.out[state as usize]
    }

    /// Epsilon closure of `seeds`, appended to `closure` (unsorted). `mark` must hold num_states entries;
    /// a state is visited iff its mark equals `stamp`.
    pub fn closure_into(
        &self,
        seeds: impl IntoIterator<Item = StateId>,
        mark: &mut [u32],
        stamp: u32,
        closure: &mut Vec<StateId>,
    ) {
        let base = closure.len();
        for s in seeds {
            if mark[s as usize] != stamp {
                mark[s as usize] = stamp;
                closure.push(s);
            }
        }
        let mut i = base;
        while i < closure.len() {
            let s = closure[i];
            i += 1;
            for &d in &self.eps[s as usize] {
                if mark[d as usize] != stamp {
                    mark[d as usize] = stamp;
                    closure.push(d);
                }
            }
        }
    }

    /// Get the epsilon closure of a set of states.
    pub fn epsilon_closure(&self, states: &StateSet) -> StateSet {
        let mut mark = vec![0u32; self.num_states as usize];
        let mut closure = Vec::new();
        self.closure_into(
            states.iter().filter(|&s| s < self.num_states),
            &mut mark,
            1,
            &mut closure,
        );
        closure.into_iter().collect()
    }

    /// Get the states reachable from a set of states on a given symbol.
    /// Returns the epsilon closure of the reached states.
    pub fn move_on_symbol(&self, states: &StateSet, symbol: SymbolId) -> StateSet {
        assert!(!is_epsilon(symbol), "Use epsilon_closure for epsilon moves");

        let mut reached = StateSet::with_capacity(self.num_states as usize);
        for state in states.iter().filter(|&s| s < self.num_states) {
            for &(sym, dst) in &self.out[state as usize] {
                if sym == symbol {
                    reached.insert(dst);
                }
            }
        }
        self.epsilon_closure(&reached)
    }

    /// Check if the NFA accepts any string (i.e., if the language is non-empty).
    pub fn is_empty(&self) -> bool {
        if self.start_states.is_empty() {
            return true;
        }

        let mut visited = vec![false; self.num_states as usize];
        let mut queue: VecDeque<StateId> = VecDeque::new();
        for s in self.start_states.iter() {
            if !visited[s as usize] {
                visited[s as usize] = true;
                queue.push_back(s);
            }
        }

        while let Some(state) = queue.pop_front() {
            if self.final_states.contains(state) {
                return false;
            }
            let labeled = self.out[state as usize].iter().map(|&(_, d)| d);
            for dest in labeled.chain(self.eps[state as usize].iter().copied()) {
                if !visited[dest as usize] {
                    visited[dest as usize] = true;
                    queue.push_back(dest);
                }
            }
        }

        true
    }

    /// Get all transitions as an iterator.
    pub fn transitions(&self) -> impl Iterator<Item = (StateId, SymbolId, StateId)> + '_ {
        let labeled = self
            .out
            .iter()
            .enumerate()
            .flat_map(|(src, es)| es.iter().map(move |&(sym, dst)| (src as StateId, sym, dst)));
        let epsilon = self
            .eps
            .iter()
            .enumerate()
            .flat_map(|(src, ds)| ds.iter().map(move |&dst| (src as StateId, EPSILON, dst)));
        labeled.chain(epsilon)
    }

    /// Convert to a map representation for debugging.
    pub fn to_transition_map(&self) -> IndexMap<StateId, IndexMap<SymbolId, Vec<StateId>>> {
        let mut map: IndexMap<StateId, IndexMap<SymbolId, Vec<StateId>>> = IndexMap::new();

        for (src, sym, dst) in self.transitions() {
            map.entry(src)
                .or_default()
                .entry(sym)
                .or_default()
                .push(dst);
        }

        map
    }
}

impl Default for EpsilonNFA {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epsilon_nfa_basic() {
        let mut nfa = EpsilonNFA::new();

        // Create a simple NFA: 0 -a-> 1 -ε-> 2 (final)
        nfa.add_transition(0, 0, 1); // symbol 0 = 'a'
        nfa.add_epsilon_transition(1, 2);
        nfa.add_start_state(0);
        nfa.add_final_state(2);

        assert_eq!(nfa.num_states(), 3);
        assert!(!nfa.is_empty());
    }

    #[test]
    fn test_epsilon_closure() {
        let mut nfa = EpsilonNFA::new();

        // 0 -ε-> 1 -ε-> 2
        nfa.add_epsilon_transition(0, 1);
        nfa.add_epsilon_transition(1, 2);
        nfa.add_start_state(0);

        let start = StateSet::singleton(0, 3);
        let closure = nfa.epsilon_closure(&start);

        assert!(closure.contains(0));
        assert!(closure.contains(1));
        assert!(closure.contains(2));
        assert_eq!(closure.len(), 3);
    }

    #[test]
    fn test_move_on_symbol() {
        let mut nfa = EpsilonNFA::new();

        // 0 -a-> 1, 0 -a-> 2, 1 -ε-> 3
        nfa.add_transition(0, 0, 1); // 'a' = 0
        nfa.add_transition(0, 0, 2);
        nfa.add_epsilon_transition(1, 3);

        let start = StateSet::singleton(0, 4);
        let reached = nfa.move_on_symbol(&start, 0);

        assert!(reached.contains(1));
        assert!(reached.contains(2));
        assert!(reached.contains(3)); // via epsilon from 1
        assert_eq!(reached.len(), 3);
    }

    #[test]
    fn test_empty_nfa() {
        let mut nfa = EpsilonNFA::new();
        nfa.add_start_state(0);
        nfa.add_final_state(1);
        // No transitions - NFA is empty (no path from 0 to 1)
        assert!(nfa.is_empty());

        // Add transition
        nfa.add_transition(0, 0, 1);
        assert!(!nfa.is_empty());
    }
}
