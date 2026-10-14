//! Subset construction algorithm for converting ε-NFA to DFA.

use crate::automaton::dfa::DFA;
use crate::automaton::epsilon_nfa::EpsilonNFA;
use crate::automaton::state::StateId;
use crate::automaton::symbol::SymbolId;
use std::collections::HashMap;

/// Convert an epsilon-NFA to a DFA using the powerset construction algorithm.
///
/// Only symbols that label an out-edge of the current NFA state set are visited, so the cost is proportional to
/// the transitions actually taken rather than to |DFA states| x |alphabet|.
pub fn subset_construction(nfa: &EpsilonNFA) -> DFA {
    let mut dfa = DFA::new();
    let n = nfa.num_states() as usize;

    let mut mark = vec![0u32; n];
    let mut stamp: u32 = 1;

    // sorted NFA state set -> DFA state
    let mut state_mapping: HashMap<Vec<StateId>, StateId> = HashMap::new();
    let mut dfa_sets: Vec<Vec<StateId>> = Vec::new();

    let mut initial = Vec::new();
    nfa.closure_into(nfa.start_states().iter(), &mut mark, stamp, &mut initial);
    if initial.is_empty() {
        return dfa;
    }
    initial.sort_unstable();

    let initial_dfa_state = dfa.add_state();
    dfa.set_start_state(initial_dfa_state);
    if initial.iter().any(|&s| nfa.final_states().contains(s)) {
        dfa.add_final_state(initial_dfa_state);
    }
    state_mapping.insert(initial.clone(), initial_dfa_state);
    dfa_sets.push(initial);

    let mut worklist: Vec<StateId> = vec![initial_dfa_state];
    let mut moves: Vec<(SymbolId, StateId)> = Vec::new();
    let mut next: Vec<StateId> = Vec::new();

    while let Some(current_dfa_state) = worklist.pop() {
        moves.clear();
        for &s in &dfa_sets[current_dfa_state as usize] {
            moves.extend_from_slice(nfa.out_edges(s));
        }
        moves.sort_unstable();
        moves.dedup();

        let mut i = 0;
        while i < moves.len() {
            let symbol = moves[i].0;
            let mut j = i;
            while j < moves.len() && moves[j].0 == symbol {
                j += 1;
            }

            stamp = stamp.wrapping_add(1);
            if stamp == 0 {
                mark.fill(0);
                stamp = 1;
            }
            next.clear();
            nfa.closure_into(
                moves[i..j].iter().map(|&(_, d)| d),
                &mut mark,
                stamp,
                &mut next,
            );
            next.sort_unstable();
            i = j;

            let next_dfa_state = if let Some(&existing) = state_mapping.get(&next) {
                existing
            } else {
                let new_state = dfa.add_state();
                if next.iter().any(|&s| nfa.final_states().contains(s)) {
                    dfa.add_final_state(new_state);
                }
                state_mapping.insert(next.clone(), new_state);
                dfa_sets.push(next.clone());
                worklist.push(new_state);
                new_state
            };

            dfa.add_transition(current_dfa_state, symbol, next_dfa_state);
        }
    }

    // Store the DFA-to-NFA state mapping in the DFA for later use
    let inverse_mapping: HashMap<StateId, Vec<StateId>> = dfa_sets
        .into_iter()
        .enumerate()
        .map(|(dfa_state, nfa_states)| (dfa_state as StateId, nfa_states))
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

    fn nfa_accepts(nfa: &EpsilonNFA, word: &[SymbolId]) -> bool {
        let mut cur = nfa.epsilon_closure(nfa.start_states());
        for &sym in word {
            cur = nfa.move_on_symbol(&cur, sym);
        }
        cur.intersects(nfa.final_states())
    }

    fn dfa_accepts(dfa: &DFA, word: &[SymbolId]) -> bool {
        let Some(mut cur) = dfa.start_state() else {
            return false;
        };
        for &sym in word {
            match dfa.transition(cur, sym) {
                Some(next) => cur = next,
                None => return false,
            }
        }
        dfa.final_states().contains(cur)
    }

    #[test]
    fn test_subset_construction_random_words() {
        let mut seed: u64 = 0xdead_beef;
        let mut next = |bound: u32| {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((seed >> 33) % bound as u64) as u32
        };
        for _ in 0..200 {
            let n = 2 + next(12);
            let mut nfa = EpsilonNFA::new();
            for _ in 0..(n * 2) {
                let (src, dst) = (next(n), next(n));
                if next(4) == 0 {
                    nfa.add_epsilon_transition(src, dst);
                } else {
                    nfa.add_transition(src, next(3), dst);
                }
            }
            nfa.add_start_state(next(n));
            nfa.add_final_state(next(n));
            let dfa = subset_construction(&nfa);
            let minimized = dfa.minimize();
            // every word of length <= 5 over {0, 1, 2}
            let mut word = Vec::new();
            for len in 0..=5u32 {
                for code in 0..3u32.pow(len) {
                    word.clear();
                    let mut c = code;
                    for _ in 0..len {
                        word.push(c % 3);
                        c /= 3;
                    }
                    let expected = nfa_accepts(&nfa, &word);
                    assert_eq!(dfa_accepts(&dfa, &word), expected);
                    assert_eq!(dfa_accepts(&minimized, &word), expected);
                }
            }
        }
    }
}
