//! Epsilon Non-deterministic Finite Automaton (ε-NFA) implementation.

use crate::formlang::state::{StateId, StateSet};
use crate::formlang::symbol::{EPSILON, SymbolId, is_epsilon};
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet, VecDeque};

/// An Epsilon Non-deterministic Finite Automaton.
#[derive(Debug, Clone)]
pub struct EpsilonNFA {
    /// Number of states (states are numbered 0..num_states)
    num_states: StateId,
    /// Start states
    start_states: StateSet,
    /// Final (accepting) states
    final_states: StateSet,
    /// Transitions: (source, symbol) -> set of destination states
    /// For epsilon transitions, symbol == EPSILON
    transitions: HashMap<(StateId, SymbolId), StateSet>,
    /// All symbols used (excluding epsilon)
    alphabet: HashSet<SymbolId>,
    /// Cached epsilon closures for each state
    epsilon_closures: Option<Vec<StateSet>>,
}

impl EpsilonNFA {
    /// Create a new empty epsilon-NFA.
    pub fn new() -> Self {
        Self {
            num_states: 0,
            start_states: StateSet::with_capacity(16),
            final_states: StateSet::with_capacity(16),
            transitions: HashMap::new(),
            alphabet: HashSet::new(),
            epsilon_closures: None,
        }
    }

    /// Ensure a state exists, expanding num_states if needed.
    fn ensure_state(&mut self, state: StateId) {
        if state >= self.num_states {
            self.num_states = state + 1;
            // Invalidate cached epsilon closures
            self.epsilon_closures = None;
        }
    }

    /// Add a transition from source to destination on the given symbol.
    pub fn add_transition(&mut self, source: StateId, symbol: SymbolId, destination: StateId) {
        self.ensure_state(source);
        self.ensure_state(destination);

        if !is_epsilon(symbol) {
            self.alphabet.insert(symbol);
        }

        self.transitions
            .entry((source, symbol))
            .or_insert_with(|| StateSet::with_capacity(self.num_states as usize))
            .insert(destination);

        // Invalidate cached epsilon closures
        self.epsilon_closures = None;
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

    /// Compute the epsilon closure of a single state using DFS.
    fn epsilon_closure_single(&self, state: StateId) -> StateSet {
        let mut closure = StateSet::with_capacity(self.num_states as usize);
        let mut stack = vec![state];

        while let Some(s) = stack.pop() {
            if closure.contains(s) {
                continue;
            }
            closure.insert(s);

            // Follow epsilon transitions
            if let Some(destinations) = self.transitions.get(&(s, EPSILON)) {
                for dest in destinations.iter() {
                    if !closure.contains(dest) {
                        stack.push(dest);
                    }
                }
            }
        }

        closure
    }

    /// Compute epsilon closures for all states (cached).
    pub fn compute_epsilon_closures(&mut self) {
        if self.epsilon_closures.is_some() {
            return;
        }

        let mut closures = Vec::with_capacity(self.num_states as usize);
        for state in 0..self.num_states {
            closures.push(self.epsilon_closure_single(state));
        }
        self.epsilon_closures = Some(closures);
    }

    /// Get the epsilon closure of a set of states.
    pub fn epsilon_closure(&self, states: &StateSet) -> StateSet {
        let mut closure = StateSet::with_capacity(self.num_states as usize);

        if let Some(cached) = &self.epsilon_closures {
            // Use cached closures
            for state in states.iter() {
                if (state as usize) < cached.len() {
                    closure.union_with(&cached[state as usize]);
                }
            }
        } else {
            // Compute on-the-fly using DFS
            let mut stack: Vec<StateId> = states.iter().collect();

            while let Some(s) = stack.pop() {
                if closure.contains(s) {
                    continue;
                }
                closure.insert(s);

                if let Some(destinations) = self.transitions.get(&(s, EPSILON)) {
                    for dest in destinations.iter() {
                        if !closure.contains(dest) {
                            stack.push(dest);
                        }
                    }
                }
            }
        }

        closure
    }

    /// Get the states reachable from a set of states on a given symbol.
    /// Returns the epsilon closure of the reached states.
    pub fn move_on_symbol(&self, states: &StateSet, symbol: SymbolId) -> StateSet {
        assert!(!is_epsilon(symbol), "Use epsilon_closure for epsilon moves");

        let mut reached = StateSet::with_capacity(self.num_states as usize);

        for state in states.iter() {
            if let Some(destinations) = self.transitions.get(&(state, symbol)) {
                reached.union_with(destinations);
            }
        }

        self.epsilon_closure(&reached)
    }

    /// Check if the NFA accepts any string (i.e., if the language is non-empty).
    /// Uses BFS from start states following all transitions.
    pub fn is_empty(&self) -> bool {
        if self.start_states.is_empty() {
            return true;
        }

        let mut visited = StateSet::with_capacity(self.num_states as usize);
        let mut queue: VecDeque<StateId> = VecDeque::new();

        // Start from epsilon closure of start states
        let start_closure = self.epsilon_closure(&self.start_states);
        for state in start_closure.iter() {
            queue.push_back(state);
        }

        while let Some(state) = queue.pop_front() {
            if visited.contains(state) {
                continue;
            }
            visited.insert(state);

            // Check if we reached a final state
            if self.final_states.contains(state) {
                return false;
            }

            // Explore all transitions
            for &symbol in &self.alphabet {
                if let Some(destinations) = self.transitions.get(&(state, symbol)) {
                    let closure = self.epsilon_closure(destinations);
                    for dest in closure.iter() {
                        if !visited.contains(dest) {
                            queue.push_back(dest);
                        }
                    }
                }
            }
        }

        true
    }

    /// Get all transitions as an iterator.
    pub fn transitions(&self) -> impl Iterator<Item = (StateId, SymbolId, StateId)> + '_ {
        self.transitions
            .iter()
            .flat_map(|(&(src, sym), dests)| dests.iter().map(move |dst| (src, sym, dst)))
    }

    /// Convert to a map representation for debugging.
    pub fn to_transition_map(&self) -> IndexMap<StateId, IndexMap<SymbolId, Vec<StateId>>> {
        let mut map: IndexMap<StateId, IndexMap<SymbolId, Vec<StateId>>> = IndexMap::new();

        for ((src, sym), dests) in &self.transitions {
            map.entry(*src)
                .or_default()
                .entry(*sym)
                .or_default()
                .extend(dests.iter());
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
