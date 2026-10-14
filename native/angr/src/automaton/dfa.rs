//! Deterministic Finite Automaton (DFA) implementation with Hopcroft minimization.

use crate::automaton::state::{StateId, StateSet};
use crate::automaton::symbol::SymbolId;
use std::collections::{HashMap, HashSet};

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
        if self.start_state.is_none() || self.final_states.is_empty() {
            return true;
        }
        let reachable = self.find_reachable_states(&self.out_adjacency());
        !reachable.iter().any(|s| self.final_states.contains(s))
    }

    /// Labeled out-edges per state.
    fn out_adjacency(&self) -> Vec<Vec<(SymbolId, StateId)>> {
        let mut adj: Vec<Vec<(SymbolId, StateId)>> = vec![Vec::new(); self.num_states as usize];
        for (&(src, sym), &dst) in &self.transitions {
            adj[src as usize].push((sym, dst));
        }
        adj
    }

    /// Get all transitions as an iterator.
    pub fn transitions(&self) -> impl Iterator<Item = (StateId, SymbolId, StateId)> + '_ {
        self.transitions
            .iter()
            .map(|(&(src, sym), &dst)| (src, sym, dst))
    }

    /// Minimize the DFA using Hopcroft's algorithm.
    /// Returns a new minimized DFA.
    ///
    /// Missing transitions are kept implicit (no dead state is added), so two states are only merged when they
    /// define transitions on exactly the same symbols. Splitters are processed per block over the incoming
    /// transitions of that block, which runs in O(m log n) for m transitions.
    pub fn minimize(&self) -> DFA {
        let Some(start) = self.start_state else {
            return DFA::new();
        };
        if self.num_states == 0 {
            return DFA::new();
        }

        let adj = self.out_adjacency();
        let reachable = self.find_reachable_states(&adj);
        if reachable.is_empty() {
            return DFA::new();
        }

        // dense indices over reachable states
        let states: Vec<StateId> = reachable.iter().collect();
        let n = states.len();
        let mut dense = vec![u32::MAX; self.num_states as usize];
        for (i, &s) in states.iter().enumerate() {
            dense[s as usize] = i as u32;
        }
        // incoming transitions: (symbol, source); successors of reachable states are reachable
        let mut incoming: Vec<Vec<(SymbolId, u32)>> = vec![Vec::new(); n];
        for (i, &s) in states.iter().enumerate() {
            for &(sym, dst) in &adj[s as usize] {
                incoming[dense[dst as usize] as usize].push((sym, i as u32));
            }
        }

        // partition refinement: each block is a contiguous range of `elems`
        let mut elems: Vec<u32> = Vec::with_capacity(n);
        elems.extend((0..n as u32).filter(|&i| self.final_states.contains(states[i as usize])));
        let num_final = elems.len();
        elems.extend((0..n as u32).filter(|&i| !self.final_states.contains(states[i as usize])));
        let mut loc: Vec<u32> = vec![0; n];
        for (pos, &e) in elems.iter().enumerate() {
            loc[e as usize] = pos as u32;
        }
        let mut block_start: Vec<u32> = Vec::new();
        let mut block_end: Vec<u32> = Vec::new();
        let mut block_of: Vec<u32> = vec![0; n];
        for (lo, hi) in [(0, num_final), (num_final, n)] {
            if lo < hi {
                let b = block_start.len() as u32;
                block_start.push(lo as u32);
                block_end.push(hi as u32);
                for &e in &elems[lo..hi] {
                    block_of[e as usize] = b;
                }
            }
        }
        let mut marked: Vec<u32> = vec![0; block_start.len()];

        // every initial block is a splitter; required for partial DFAs
        let mut worklist: Vec<u32> = (0..block_start.len() as u32).collect();
        let mut trans: Vec<(SymbolId, u32)> = Vec::new();
        let mut touched: Vec<u32> = Vec::new();

        while let Some(b) = worklist.pop() {
            trans.clear();
            for pos in block_start[b as usize]..block_end[b as usize] {
                trans.extend_from_slice(&incoming[elems[pos as usize] as usize]);
            }
            trans.sort_unstable();
            trans.dedup();

            let mut i = 0;
            while i < trans.len() {
                let symbol = trans[i].0;
                // mark predecessors on `symbol` by moving them to the front of their blocks
                while i < trans.len() && trans[i].0 == symbol {
                    let src = trans[i].1 as usize;
                    i += 1;
                    let c = block_of[src] as usize;
                    if marked[c] == 0 {
                        touched.push(c as u32);
                    }
                    let target = block_start[c] + marked[c];
                    let pos = loc[src];
                    let other = elems[target as usize];
                    elems.swap(pos as usize, target as usize);
                    loc[other as usize] = pos;
                    loc[src] = target;
                    marked[c] += 1;
                }
                for &c in &touched {
                    let c = c as usize;
                    let m = marked[c];
                    marked[c] = 0;
                    let (lo, hi) = (block_start[c], block_end[c]);
                    if m == hi - lo {
                        continue;
                    }
                    // the smaller half becomes the new block and goes to the worklist; this covers both the
                    // "c already pending" and the "c done" cases of Hopcroft's algorithm
                    let nb = block_start.len() as u32;
                    let (nlo, nhi) = if m <= hi - lo - m {
                        block_start[c] = lo + m;
                        (lo, lo + m)
                    } else {
                        block_end[c] = lo + m;
                        (lo + m, hi)
                    };
                    block_start.push(nlo);
                    block_end.push(nhi);
                    marked.push(0);
                    for pos in nlo..nhi {
                        block_of[elems[pos as usize] as usize] = nb;
                    }
                    worklist.push(nb);
                }
                touched.clear();
            }
        }

        // build the minimized DFA
        let num_blocks = block_start.len();
        let mut minimized = DFA::new();
        for _ in 0..num_blocks {
            minimized.add_state();
        }
        minimized.set_start_state(block_of[dense[start as usize] as usize]);
        for i in 0..n {
            if self.final_states.contains(states[i]) {
                minimized.add_final_state(block_of[i]);
            }
        }
        for b in 0..num_blocks {
            let rep = states[elems[block_start[b] as usize] as usize];
            for &(symbol, dest) in &adj[rep as usize] {
                let new_dest = block_of[dense[dest as usize] as usize];
                minimized.add_transition(b as StateId, symbol, new_dest);
                if let Some(label) = self.transition_labels.get(&(rep, symbol)) {
                    minimized
                        .transition_labels
                        .insert((b as StateId, symbol), label.clone());
                }
            }
        }

        // Build state mapping from minimized states to original NFA states
        if let Some(orig_mapping) = &self.state_mapping {
            let mut new_mapping: HashMap<StateId, Vec<StateId>> = HashMap::new();
            for b in 0..num_blocks {
                let mut nfa_states = Vec::new();
                for pos in block_start[b]..block_end[b] {
                    let old_dfa_state = states[elems[pos as usize] as usize];
                    if let Some(st) = orig_mapping.get(&old_dfa_state) {
                        nfa_states.extend(st.iter().copied());
                    }
                }
                nfa_states.sort_unstable();
                nfa_states.dedup();
                new_mapping.insert(b as StateId, nfa_states);
            }
            minimized.state_mapping = Some(new_mapping);
        }

        minimized
    }

    /// Find all states reachable from the start state.
    fn find_reachable_states(&self, adj: &[Vec<(SymbolId, StateId)>]) -> StateSet {
        let mut reachable = StateSet::with_capacity(self.num_states as usize);

        let Some(start) = self.start_state else {
            return reachable;
        };

        let mut stack = vec![start];
        reachable.insert(start);
        while let Some(state) = stack.pop() {
            for &(_, next) in &adj[state as usize] {
                if !reachable.contains(next) {
                    reachable.insert(next);
                    stack.push(next);
                }
            }
        }

        reachable
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

    /// Tiny deterministic PRNG for randomized tests.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self, bound: u32) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((self.0 >> 33) % bound as u64) as u32
        }
    }

    /// Number of classes of the coarsest partition by naive signature refinement over reachable states.
    fn reference_num_classes(dfa: &DFA) -> usize {
        let adj = dfa.out_adjacency();
        let reachable: Vec<StateId> = dfa.find_reachable_states(&adj).iter().collect();
        let mut class: HashMap<StateId, usize> = reachable
            .iter()
            .map(|&s| (s, usize::from(dfa.final_states.contains(s))))
            .collect();
        loop {
            let mut sigs: HashMap<(usize, Vec<(SymbolId, usize)>), usize> = HashMap::new();
            let mut new_class = HashMap::new();
            for &s in &reachable {
                let mut sig: Vec<(SymbolId, usize)> = adj[s as usize]
                    .iter()
                    .map(|&(sym, d)| (sym, class[&d]))
                    .collect();
                sig.sort_unstable();
                let n = sigs.len();
                new_class.insert(s, *sigs.entry((class[&s], sig)).or_insert(n));
            }
            let old_n = class.values().collect::<HashSet<_>>().len();
            class = new_class;
            if sigs.len() == old_n {
                return old_n;
            }
        }
    }

    /// Both DFAs are partial; check they are bisimilar from their start states.
    fn assert_equivalent(a: &DFA, b: &DFA) {
        let (adj_a, adj_b) = (a.out_adjacency(), b.out_adjacency());
        let start = (a.start_state.unwrap(), b.start_state.unwrap());
        let mut seen = HashSet::from([start]);
        let mut stack = vec![start];
        while let Some((x, y)) = stack.pop() {
            assert_eq!(a.final_states.contains(x), b.final_states.contains(y));
            let mut ex = adj_a[x as usize].clone();
            let mut ey = adj_b[y as usize].clone();
            ex.sort_unstable();
            ey.sort_unstable();
            assert_eq!(ex.len(), ey.len());
            for (&(sa, da), &(sb, db)) in ex.iter().zip(ey.iter()) {
                assert_eq!(sa, sb);
                if seen.insert((da, db)) {
                    stack.push((da, db));
                }
            }
        }
    }

    #[test]
    fn test_minimize_random_against_reference() {
        let mut rng = Lcg(0x1234_5678);
        for _ in 0..500 {
            let n = 1 + rng.next(40);
            let num_symbols = 1 + rng.next(4);
            let mut dfa = DFA::new();
            for _ in 0..n {
                dfa.add_state();
            }
            dfa.set_start_state(rng.next(n));
            for s in 0..n {
                if rng.next(3) == 0 {
                    dfa.add_final_state(s);
                }
                for sym in 0..num_symbols {
                    // partial DFA: leave some transitions undefined
                    if rng.next(3) != 0 {
                        dfa.add_transition(s, sym, rng.next(n));
                    }
                }
            }
            let minimized = dfa.minimize();
            assert_eq!(minimized.num_states() as usize, reference_num_classes(&dfa));
            assert_equivalent(&dfa, &minimized);
        }
    }
}
