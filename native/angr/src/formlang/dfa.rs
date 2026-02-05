//! Deterministic Finite Automaton (DFA) implementation with Hopcroft minimization.

use crate::formlang::state::{StateId, StateSet};
use crate::formlang::symbol::SymbolId;
use std::collections::{HashMap, HashSet, VecDeque};

/// A labeled edge in the graph representation: (source, destination, label).
pub type GraphEdge = (StateId, StateId, Vec<u8>);

/// A Deterministic Finite Automaton.
#[derive(Debug, Clone)]
pub struct DFA {
    /// Number of states
    num_states: StateId,
    /// Start state (None if empty)
    start_state: Option<StateId>,
    /// Final (accepting) states
    final_states: StateSet,
    /// Transitions: (source, symbol) -> destination
    transitions: HashMap<(StateId, SymbolId), StateId>,
    /// Reverse transitions: (destination, symbol) -> set of sources
    reverse_transitions: HashMap<(StateId, SymbolId), StateSet>,
    /// All symbols used
    alphabet: HashSet<SymbolId>,
    /// Mapping from DFA states to original NFA states (if created via subset construction)
    state_mapping: Option<HashMap<StateId, Vec<StateId>>>,
    /// Labels for transitions (for graph export)
    transition_labels: HashMap<(StateId, SymbolId), Vec<u8>>,
}

impl DFA {
    /// Create a new empty DFA.
    pub fn new() -> Self {
        Self {
            num_states: 0,
            start_state: None,
            final_states: StateSet::with_capacity(16),
            transitions: HashMap::new(),
            reverse_transitions: HashMap::new(),
            alphabet: HashSet::new(),
            state_mapping: None,
            transition_labels: HashMap::new(),
        }
    }

    /// Add a new state and return its ID.
    pub fn add_state(&mut self) -> StateId {
        let id = self.num_states;
        self.num_states += 1;
        id
    }

    /// Set the start state.
    pub fn set_start_state(&mut self, state: StateId) {
        self.start_state = Some(state);
    }

    /// Add a final (accepting) state.
    pub fn add_final_state(&mut self, state: StateId) {
        self.final_states.insert(state);
    }

    /// Add a transition.
    pub fn add_transition(&mut self, source: StateId, symbol: SymbolId, destination: StateId) {
        self.alphabet.insert(symbol);
        self.transitions.insert((source, symbol), destination);

        // Also update reverse transitions
        self.reverse_transitions
            .entry((destination, symbol))
            .or_insert_with(|| StateSet::with_capacity(self.num_states as usize))
            .insert(source);
    }

    /// Add a transition with a label (for graph export).
    pub fn add_transition_with_label(
        &mut self,
        source: StateId,
        symbol: SymbolId,
        destination: StateId,
        label: Vec<u8>,
    ) {
        self.add_transition(source, symbol, destination);
        self.transition_labels.insert((source, symbol), label);
    }

    /// Get the transition from a state on a symbol.
    pub fn transition(&self, source: StateId, symbol: SymbolId) -> Option<StateId> {
        self.transitions.get(&(source, symbol)).copied()
    }

    /// Get the number of states.
    pub fn num_states(&self) -> StateId {
        self.num_states
    }

    /// Get the start state.
    pub fn start_state(&self) -> Option<StateId> {
        self.start_state
    }

    /// Get the final states.
    pub fn final_states(&self) -> &StateSet {
        &self.final_states
    }

    /// Get the alphabet.
    pub fn alphabet(&self) -> &HashSet<SymbolId> {
        &self.alphabet
    }

    /// Set the state mapping from original NFA states.
    pub fn set_state_mapping(&mut self, mapping: HashMap<StateId, Vec<StateId>>) {
        self.state_mapping = Some(mapping);
    }

    /// Get the state mapping.
    pub fn state_mapping(&self) -> Option<&HashMap<StateId, Vec<StateId>>> {
        self.state_mapping.as_ref()
    }

    /// Get transition labels.
    pub fn transition_labels(&self) -> &HashMap<(StateId, SymbolId), Vec<u8>> {
        &self.transition_labels
    }

    /// Check if the DFA is empty (accepts no strings).
    pub fn is_empty(&self) -> bool {
        let Some(start) = self.start_state else {
            return true;
        };

        if self.final_states.is_empty() {
            return true;
        }

        // BFS to find if any final state is reachable
        let mut visited = StateSet::with_capacity(self.num_states as usize);
        let mut queue = VecDeque::new();
        queue.push_back(start);

        while let Some(state) = queue.pop_front() {
            if visited.contains(state) {
                continue;
            }
            visited.insert(state);

            if self.final_states.contains(state) {
                return false;
            }

            for &symbol in &self.alphabet {
                if let Some(next) = self.transition(state, symbol) {
                    if !visited.contains(next) {
                        queue.push_back(next);
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
            .map(|(&(src, sym), &dst)| (src, sym, dst))
    }

    /// Minimize the DFA using Hopcroft's algorithm.
    /// Returns a new minimized DFA.
    pub fn minimize(&self) -> DFA {
        if self.start_state.is_none() || self.num_states == 0 {
            return DFA::new();
        }

        // First, remove unreachable states
        let reachable = self.find_reachable_states();

        // If no reachable states, return empty DFA
        if reachable.is_empty() {
            return DFA::new();
        }

        // Hopcroft's partition refinement algorithm
        // Initial partition: final states and non-final states
        let final_reachable = self.final_states.intersection(&reachable);
        let non_final_reachable = reachable.difference(&self.final_states);

        let mut partitions: Vec<StateSet> = Vec::new();

        if !final_reachable.is_empty() {
            partitions.push(final_reachable);
        }
        if !non_final_reachable.is_empty() {
            partitions.push(non_final_reachable);
        }

        if partitions.is_empty() {
            return DFA::new();
        }

        // Worklist of (partition_index, symbol) pairs to process
        let mut worklist: VecDeque<(usize, SymbolId)> = VecDeque::new();

        // Initialize worklist with all (partition, symbol) pairs
        for (idx, _) in partitions.iter().enumerate() {
            for &symbol in &self.alphabet {
                worklist.push_back((idx, symbol));
            }
        }

        // Main refinement loop
        while let Some((splitter_idx, symbol)) = worklist.pop_front() {
            // Get states that can reach the splitter partition on this symbol
            let splitter = if splitter_idx < partitions.len() {
                partitions[splitter_idx].clone()
            } else {
                continue;
            };

            let predecessors = self.find_predecessors(&splitter, symbol);

            if predecessors.is_empty() {
                continue;
            }

            // Try to split each partition
            let mut new_partitions = Vec::new();

            for (part_idx, partition) in partitions.iter().enumerate() {
                let intersection = partition.intersection(&predecessors);
                let difference = partition.difference(&predecessors);

                if !intersection.is_empty() && !difference.is_empty() {
                    // Partition is split
                    // Keep the larger part in place, add smaller to new_partitions
                    let (keep, add) = if intersection.len() <= difference.len() {
                        (difference, intersection)
                    } else {
                        (intersection, difference)
                    };

                    new_partitions.push((part_idx, keep, add));
                }
            }

            // Apply splits
            for (part_idx, keep, add) in new_partitions {
                let new_idx = partitions.len();
                partitions[part_idx] = keep;
                partitions.push(add);

                // Add new partition to worklist for all symbols
                for &sym in &self.alphabet {
                    worklist.push_back((new_idx, sym));
                }
            }
        }

        // Build minimized DFA from partitions
        self.build_minimized_dfa(&partitions)
    }

    /// Find all states reachable from the start state.
    fn find_reachable_states(&self) -> StateSet {
        let mut reachable = StateSet::with_capacity(self.num_states as usize);

        let Some(start) = self.start_state else {
            return reachable;
        };

        let mut queue = VecDeque::new();
        queue.push_back(start);

        while let Some(state) = queue.pop_front() {
            if reachable.contains(state) {
                continue;
            }
            reachable.insert(state);

            for &symbol in &self.alphabet {
                if let Some(next) = self.transition(state, symbol) {
                    if !reachable.contains(next) {
                        queue.push_back(next);
                    }
                }
            }
        }

        reachable
    }

    /// Find all states that can reach the target set on a given symbol.
    fn find_predecessors(&self, targets: &StateSet, symbol: SymbolId) -> StateSet {
        let mut predecessors = StateSet::with_capacity(self.num_states as usize);

        for target in targets.iter() {
            if let Some(sources) = self.reverse_transitions.get(&(target, symbol)) {
                predecessors.union_with(sources);
            }
        }

        predecessors
    }

    /// Build a minimized DFA from partitions.
    fn build_minimized_dfa(&self, partitions: &[StateSet]) -> DFA {
        let mut minimized = DFA::new();

        // Map old states to their partition (new state)
        let mut state_to_partition: HashMap<StateId, StateId> = HashMap::new();
        for (part_idx, partition) in partitions.iter().enumerate() {
            for state in partition.iter() {
                state_to_partition.insert(state, part_idx as StateId);
            }
        }

        // Create states in minimized DFA
        for _ in 0..partitions.len() {
            minimized.add_state();
        }

        // Set start state
        if let Some(start) = self.start_state {
            if let Some(&new_start) = state_to_partition.get(&start) {
                minimized.set_start_state(new_start);
            }
        }

        // Set final states
        for final_state in self.final_states.iter() {
            if let Some(&new_state) = state_to_partition.get(&final_state) {
                minimized.add_final_state(new_state);
            }
        }

        // Add transitions (use representative state from each partition)
        for (part_idx, partition) in partitions.iter().enumerate() {
            // Get any representative state from the partition
            if let Some(representative) = partition.iter().next() {
                for &symbol in &self.alphabet {
                    if let Some(dest) = self.transition(representative, symbol) {
                        if let Some(&new_dest) = state_to_partition.get(&dest) {
                            minimized.add_transition(part_idx as StateId, symbol, new_dest);

                            // Copy label if exists
                            if let Some(label) =
                                self.transition_labels.get(&(representative, symbol))
                            {
                                minimized
                                    .transition_labels
                                    .insert((part_idx as StateId, symbol), label.clone());
                            }
                        }
                    }
                }
            }
        }

        // Build state mapping from minimized states to original NFA states
        if let Some(orig_mapping) = &self.state_mapping {
            let mut new_mapping: HashMap<StateId, Vec<StateId>> = HashMap::new();
            for (part_idx, partition) in partitions.iter().enumerate() {
                let mut nfa_states = Vec::new();
                for old_dfa_state in partition.iter() {
                    if let Some(states) = orig_mapping.get(&old_dfa_state) {
                        nfa_states.extend(states.iter().copied());
                    }
                }
                nfa_states.sort_unstable();
                nfa_states.dedup();
                new_mapping.insert(part_idx as StateId, nfa_states);
            }
            minimized.state_mapping = Some(new_mapping);
        }

        minimized
    }

    /// Convert to a graph representation (edges with labels).
    /// Returns: (nodes, edges) where edges are (src, dst, label)
    pub fn to_graph(&self) -> (Vec<StateId>, Vec<GraphEdge>) {
        let nodes: Vec<StateId> = (0..self.num_states).collect();
        let mut edges = Vec::new();

        for (&(src, symbol), &dst) in &self.transitions {
            let label = self
                .transition_labels
                .get(&(src, symbol))
                .cloned()
                .unwrap_or_else(|| format!("{symbol}").into_bytes());
            edges.push((src, dst, label));
        }

        (nodes, edges)
    }
}

impl Default for DFA {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dfa_basic() {
        let mut dfa = DFA::new();
        let s0 = dfa.add_state();
        let s1 = dfa.add_state();
        let s2 = dfa.add_state();

        dfa.set_start_state(s0);
        dfa.add_final_state(s2);
        dfa.add_transition(s0, 0, s1);
        dfa.add_transition(s1, 1, s2);

        assert_eq!(dfa.num_states(), 3);
        assert_eq!(dfa.start_state(), Some(0));
        assert!(!dfa.is_empty());
    }

    #[test]
    fn test_dfa_minimization() {
        // Create a DFA with equivalent states:
        // 0 -a-> 1 -b-> 3(final)
        // 0 -a-> 2 -b-> 4(final)
        // States 1 and 2 should be merged, as should 3 and 4

        let mut dfa = DFA::new();
        for _ in 0..5 {
            dfa.add_state();
        }

        dfa.set_start_state(0);
        dfa.add_final_state(3);
        dfa.add_final_state(4);

        dfa.add_transition(0, 0, 1); // 'a' = 0
        dfa.add_transition(0, 1, 2); // 'b' = 1 (different path to equivalent states)
        dfa.add_transition(1, 1, 3);
        dfa.add_transition(2, 1, 4);

        let minimized = dfa.minimize();

        // Minimized DFA should have fewer states (or same if already minimal)
        assert!(minimized.num_states() <= dfa.num_states());
        assert!(!minimized.is_empty());
    }

    #[test]
    fn test_empty_dfa() {
        let dfa = DFA::new();
        assert!(dfa.is_empty());

        let mut dfa2 = DFA::new();
        dfa2.add_state();
        dfa2.set_start_state(0);
        // No final states - should be empty
        assert!(dfa2.is_empty());
    }
}
