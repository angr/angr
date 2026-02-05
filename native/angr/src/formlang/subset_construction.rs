//! Subset construction algorithm for converting ε-NFA to DFA.

use crate::formlang::dfa::DFA;
use crate::formlang::epsilon_nfa::EpsilonNFA;
use crate::formlang::state::{StateId, StateSet};
use indexmap::IndexMap;
use std::collections::HashMap;

/// Convert an epsilon-NFA to a DFA using the powerset construction algorithm.
pub fn subset_construction(nfa: &EpsilonNFA) -> DFA {
    // Each DFA state corresponds to a set of NFA states
    // We map sets of NFA states to DFA state IDs
    let mut state_mapping: IndexMap<Vec<StateId>, StateId> = IndexMap::new();
    let mut dfa = DFA::new();

    // Queue of DFA states to process (as NFA state sets)
    let mut worklist: Vec<StateSet> = Vec::new();

    // Initial DFA state is the epsilon closure of NFA start states
    let initial_set = nfa.epsilon_closure(nfa.start_states());

    if initial_set.is_empty() {
        // No reachable states - return empty DFA
        return dfa;
    }

    let initial_vec = initial_set.to_vec();
    let initial_dfa_state = 0;
    state_mapping.insert(initial_vec, initial_dfa_state);
    dfa.add_state();
    dfa.set_start_state(initial_dfa_state);

    // Check if initial state is final
    if initial_set.intersects(nfa.final_states()) {
        dfa.add_final_state(initial_dfa_state);
    }

    worklist.push(initial_set);

    while let Some(current_nfa_set) = worklist.pop() {
        let current_vec = current_nfa_set.to_vec();
        let current_dfa_state = *state_mapping.get(&current_vec).unwrap();

        // For each symbol in the alphabet
        for &symbol in nfa.alphabet() {
            // Compute the set of NFA states reachable on this symbol
            let next_nfa_set = nfa.move_on_symbol(&current_nfa_set, symbol);

            if next_nfa_set.is_empty() {
                // No transition on this symbol - skip (DFA will have no transition)
                continue;
            }

            let next_vec = next_nfa_set.to_vec();

            // Check if we've seen this DFA state before
            let next_dfa_state = if let Some(&existing) = state_mapping.get(&next_vec) {
                existing
            } else {
                // Create new DFA state
                let new_state = dfa.add_state();
                state_mapping.insert(next_vec, new_state);

                // Check if this new state is final
                if next_nfa_set.intersects(nfa.final_states()) {
                    dfa.add_final_state(new_state);
                }

                worklist.push(next_nfa_set);
                new_state
            };

            // Add transition
            dfa.add_transition(current_dfa_state, symbol, next_dfa_state);
        }
    }

    // Store the NFA-to-DFA state mapping in the DFA for later use
    let inverse_mapping: HashMap<StateId, Vec<StateId>> = state_mapping
        .into_iter()
        .map(|(nfa_states, dfa_state)| (dfa_state, nfa_states))
        .collect();
    dfa.set_state_mapping(inverse_mapping);

    dfa
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subset_construction_basic() {
        // NFA: 0 -a-> 1, 0 -a-> 2, 1 -b-> 3(final), 2 -b-> 3(final)
        let mut nfa = EpsilonNFA::new();
        nfa.add_transition(0, 0, 1); // 'a' = 0
        nfa.add_transition(0, 0, 2);
        nfa.add_transition(1, 1, 3); // 'b' = 1
        nfa.add_transition(2, 1, 3);
        nfa.add_start_state(0);
        nfa.add_final_state(3);

        let dfa = subset_construction(&nfa);

        assert!(dfa.start_state().is_some());
        assert!(!dfa.final_states().is_empty());
    }

    #[test]
    fn test_subset_construction_with_epsilon() {
        // NFA: 0 -ε-> 1 -a-> 2(final)
        let mut nfa = EpsilonNFA::new();
        nfa.add_epsilon_transition(0, 1);
        nfa.add_transition(1, 0, 2); // 'a' = 0
        nfa.add_start_state(0);
        nfa.add_final_state(2);

        let dfa = subset_construction(&nfa);

        // DFA should recognize "a"
        assert!(dfa.start_state().is_some());
        assert!(!dfa.final_states().is_empty());

        // Initial DFA state should be {0, 1} (epsilon closure of {0})
        // Should have transition on 'a' to a final state
    }

    #[test]
    fn test_empty_nfa() {
        let nfa = EpsilonNFA::new();
        let dfa = subset_construction(&nfa);
        assert!(dfa.start_state().is_none());
    }
}
