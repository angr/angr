//! PyO3 bindings for the automaton module.
//!
//! Provides a pyautomaton-compatible API for Python.

use crate::automaton::dfa::DFA;
use crate::automaton::epsilon_nfa::EpsilonNFA as RustEpsilonNFA;
use crate::automaton::state::StateId;
use crate::automaton::subset_construction::subset_construction;
use crate::automaton::symbol::{EPSILON, SymbolId};
use indexmap::IndexMap;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PySet;

/// A State wrapper that holds any Python object.
#[pyclass(
    name = "State",
    module = "angr.rustylib.automaton",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct PyState {
    /// The underlying Python value
    value: Py<PyAny>,
}

#[pymethods]
impl PyState {
    #[new]
    fn new(value: Py<PyAny>) -> Self {
        Self { value }
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let repr = self.value.bind(py).repr()?;
        Ok(format!("State({repr})"))
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>, py: Python<'_>) -> PyResult<bool> {
        if let Ok(other_state) = other.extract::<PyRef<PyState>>() {
            self.value.bind(py).eq(other_state.value.bind(py))
        } else {
            Ok(false)
        }
    }

    fn __hash__(&self, py: Python<'_>) -> PyResult<isize> {
        self.value.bind(py).hash()
    }

    #[getter]
    fn value(&self) -> Py<PyAny> {
        self.value.clone()
    }
}

/// A Symbol wrapper that holds any Python object.
#[pyclass(
    name = "Symbol",
    module = "angr.rustylib.automaton",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct PySymbol {
    /// The underlying Python value
    value: Py<PyAny>,
}

#[pymethods]
impl PySymbol {
    #[new]
    fn new(value: Py<PyAny>) -> Self {
        Self { value }
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let repr = self.value.bind(py).repr()?;
        Ok(format!("Symbol({repr})"))
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>, py: Python<'_>) -> PyResult<bool> {
        if let Ok(other_sym) = other.extract::<PyRef<PySymbol>>() {
            self.value.bind(py).eq(other_sym.value.bind(py))
        } else {
            Ok(false)
        }
    }

    fn __hash__(&self, py: Python<'_>) -> PyResult<isize> {
        self.value.bind(py).hash()
    }

    #[getter]
    fn value(&self) -> Py<PyAny> {
        self.value.clone()
    }
}

/// Marker for epsilon transitions.
#[pyclass(
    name = "Epsilon",
    module = "angr.rustylib.automaton",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct PyEpsilon;

#[pymethods]
impl PyEpsilon {
    #[new]
    fn new() -> Self {
        Self
    }

    fn __repr__(&self) -> &'static str {
        "Epsilon()"
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other.is_instance_of::<PyEpsilon>()
    }

    fn __hash__(&self) -> isize {
        // Consistent hash for all Epsilon instances
        EPSILON_HASH as isize
    }
}

const EPSILON_HASH: u64 = 0xDEAD_BEEF_CAFE_BABE;

/// Helper struct for tracking Python object to ID mappings.
#[derive(Clone)]
struct ObjectMapper {
    /// Maps Python object hash + repr to state IDs
    state_to_id: IndexMap<(isize, String), StateId>,
    /// Maps state IDs back to Python objects
    id_to_state: Vec<Py<PyAny>>,
    /// Maps Python object hash + repr to symbol IDs
    symbol_to_id: IndexMap<(isize, String), SymbolId>,
    /// Maps symbol IDs back to Python objects
    id_to_symbol: Vec<Py<PyAny>>,
}

impl ObjectMapper {
    fn new() -> Self {
        Self {
            state_to_id: IndexMap::new(),
            id_to_state: Vec::new(),
            symbol_to_id: IndexMap::new(),
            id_to_symbol: Vec::new(),
        }
    }

    fn get_or_create_state_id(&mut self, py: Python<'_>, state: &PyState) -> PyResult<StateId> {
        let hash = state.value.bind(py).hash()?;
        let repr = state.value.bind(py).repr()?.to_string();
        let key = (hash, repr);

        if let Some(&id) = self.state_to_id.get(&key) {
            Ok(id)
        } else {
            let id = self.id_to_state.len() as StateId;
            self.state_to_id.insert(key, id);
            self.id_to_state.push(state.value.clone());
            Ok(id)
        }
    }

    #[allow(dead_code)]
    fn get_state_by_id(&self, id: StateId) -> Option<&Py<PyAny>> {
        self.id_to_state.get(id as usize)
    }

    fn get_or_create_symbol_id(&mut self, py: Python<'_>, symbol: &PySymbol) -> PyResult<SymbolId> {
        let hash = symbol.value.bind(py).hash()?;
        let repr = symbol.value.bind(py).repr()?.to_string();
        let key = (hash, repr);

        if let Some(&id) = self.symbol_to_id.get(&key) {
            Ok(id)
        } else {
            let id = self.id_to_symbol.len() as SymbolId;
            // Reserve EPSILON (u32::MAX) for epsilon transitions
            if id == EPSILON {
                return Err(PyValueError::new_err("Too many symbols"));
            }
            self.symbol_to_id.insert(key, id);
            self.id_to_symbol.push(symbol.value.clone());
            Ok(id)
        }
    }

    fn get_symbol_by_id(&self, id: SymbolId) -> Option<&Py<PyAny>> {
        if id == EPSILON {
            None
        } else {
            self.id_to_symbol.get(id as usize)
        }
    }
}

/// An Epsilon Non-deterministic Finite Automaton.
#[pyclass(name = "EpsilonNFA", module = "angr.rustylib.automaton")]
pub struct PyEpsilonNFA {
    /// The underlying Rust NFA
    nfa: RustEpsilonNFA,
    /// Object mapper for Python <-> ID conversions
    mapper: ObjectMapper,
}

#[pymethods]
impl PyEpsilonNFA {
    #[new]
    fn new() -> Self {
        Self {
            nfa: RustEpsilonNFA::new(),
            mapper: ObjectMapper::new(),
        }
    }

    /// Add a transition.
    /// The symbol can be a Symbol or Epsilon.
    #[pyo3(signature = (source, symbol, destination))]
    fn add_transition(
        &mut self,
        py: Python<'_>,
        source: &PyState,
        symbol: &Bound<'_, PyAny>,
        destination: &PyState,
    ) -> PyResult<()> {
        let src_id = self.mapper.get_or_create_state_id(py, source)?;
        let dst_id = self.mapper.get_or_create_state_id(py, destination)?;

        if symbol.is_instance_of::<PyEpsilon>() {
            self.nfa.add_epsilon_transition(src_id, dst_id);
        } else if let Ok(sym) = symbol.extract::<PySymbol>() {
            let sym_id = self.mapper.get_or_create_symbol_id(py, &sym)?;
            self.nfa.add_transition(src_id, sym_id, dst_id);
        } else {
            return Err(PyValueError::new_err(
                "symbol must be a Symbol or Epsilon instance",
            ));
        }

        Ok(())
    }

    /// Add a start state.
    fn add_start_state(&mut self, py: Python<'_>, state: &PyState) -> PyResult<()> {
        let state_id = self.mapper.get_or_create_state_id(py, state)?;
        self.nfa.add_start_state(state_id);
        Ok(())
    }

    /// Add a final (accepting) state.
    fn add_final_state(&mut self, py: Python<'_>, state: &PyState) -> PyResult<()> {
        let state_id = self.mapper.get_or_create_state_id(py, state)?;
        self.nfa.add_final_state(state_id);
        Ok(())
    }

    /// Check if the NFA's language is empty.
    fn is_empty(&self) -> bool {
        self.nfa.is_empty()
    }

    /// Minimize the NFA by converting to DFA and minimizing.
    /// Returns a DeterministicFiniteAutomaton.
    fn minimize(&mut self) -> PyResult<PyDFA> {
        // Compute epsilon closures for efficiency
        self.nfa.compute_epsilon_closures();

        // Convert to DFA via subset construction
        let dfa = subset_construction(&self.nfa);

        // Minimize the DFA
        let minimized = dfa.minimize();

        Ok(PyDFA {
            dfa: minimized,
            mapper: self.mapper.clone(),
        })
    }
}

/// A Deterministic Finite Automaton.
#[pyclass(
    name = "DeterministicFiniteAutomaton",
    module = "angr.rustylib.automaton"
)]
pub struct PyDFA {
    /// The underlying Rust DFA
    dfa: DFA,
    /// Object mapper for Python <-> ID conversions
    mapper: ObjectMapper,
}

#[pymethods]
impl PyDFA {
    /// Get the start state as an integer index.
    #[getter]
    fn start_state(&self) -> Option<u32> {
        self.dfa.start_state()
    }

    /// Get the final states as a set of integer indices.
    #[getter]
    fn final_states(&self, py: Python<'_>) -> PyResult<Py<PySet>> {
        let set = PySet::empty(py)?;
        for state in self.dfa.final_states().iter() {
            set.add(state)?;
        }
        Ok(set.unbind())
    }

    /// Check if the DFA's language is empty.
    fn is_empty(&self) -> bool {
        self.dfa.is_empty()
    }

    /// Convert to a NetworkX MultiDiGraph.
    fn to_networkx<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        // Import networkx
        let nx = py.import("networkx")?;
        let graph = nx.call_method0("MultiDiGraph")?;

        // Add nodes
        for state in 0..self.dfa.num_states() {
            graph.call_method1("add_node", (state,))?;
        }

        // Add edges with labels
        for (src, sym, dst) in self.dfa.transitions() {
            // Get the original Python symbol for the label
            let label: Bound<'py, PyAny> =
                if let Some(py_symbol) = self.mapper.get_symbol_by_id(sym) {
                    py_symbol.bind(py).clone()
                } else {
                    // Fallback to symbol ID if no mapping
                    sym.into_pyobject(py)?.into_any()
                };

            // Create kwargs dict with label
            let kwargs = pyo3::types::PyDict::new(py);
            kwargs.set_item("label", label)?;

            graph.call_method("add_edge", (src, dst), Some(&kwargs))?;
        }

        Ok(graph)
    }

    /// Minimize the DFA (returns a new minimized DFA).
    fn minimize(&self) -> PyDFA {
        PyDFA {
            dfa: self.dfa.minimize(),
            mapper: self.mapper.clone(),
        }
    }
}

/// Register the automaton submodule.
pub fn automaton(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyState>()?;
    m.add_class::<PySymbol>()?;
    m.add_class::<PyEpsilon>()?;
    m.add_class::<PyEpsilonNFA>()?;
    m.add_class::<PyDFA>()?;
    Ok(())
}
