use std::borrow::Cow;

use libafl::{
    Error,
    corpus::CorpusId,
    inputs::BytesInput,
    mutators::{
        HavocMutationsType, HavocScheduledMutator, MutationResult, Mutator, havoc_mutations,
    },
};
use libafl_bolts::Named;
use pyo3::{exceptions::PyTypeError, prelude::*};

use crate::fuzzer::S;

/// A deterministic mutator that cycles through a predefined sequence of byte values.
///
/// On each call to `mutate`, replaces the input with the next value in the sequence,
/// wrapping around when the end is reached. Useful for writing tests with predictable
/// mutation outputs.
pub struct DeterministicMutator {
    values: Vec<Vec<u8>>,
    index: usize,
    name: Cow<'static, str>,
}

impl DeterministicMutator {
    pub fn new(values: Vec<Vec<u8>>) -> Self {
        Self {
            values,
            index: 0,
            name: Cow::Borrowed("DeterministicMutator"),
        }
    }
}

impl Named for DeterministicMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl Mutator<BytesInput, S> for DeterministicMutator {
    fn mutate(&mut self, _state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        if self.values.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let value = &self.values[self.index % self.values.len()];
        self.index += 1;
        *input = BytesInput::new(value.clone());
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

/// A dynamic mutator enum that can hold either a Havoc mutator or a Deterministic mutator.
pub enum DynMutator {
    Havoc(HavocScheduledMutator<HavocMutationsType>),
    Deterministic(DeterministicMutator),
}

impl Named for DynMutator {
    fn name(&self) -> &Cow<'static, str> {
        match self {
            DynMutator::Havoc(m) => m.name(),
            DynMutator::Deterministic(m) => m.name(),
        }
    }
}

impl Mutator<BytesInput, S> for DynMutator {
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        match self {
            DynMutator::Havoc(m) => m.mutate(state, input),
            DynMutator::Deterministic(m) => m.mutate(state, input),
        }
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        match self {
            DynMutator::Havoc(m) => m.post_exec(state, new_corpus_id),
            DynMutator::Deterministic(m) => m.post_exec(state, new_corpus_id),
        }
    }
}

/// Python-exposed configuration for the standard Havoc mutator.
#[pyclass(module = "angr.rustylib.fuzzer", name = "HavocMutator", from_py_object)]
#[derive(Clone, Debug)]
pub struct PyHavocMutator {
    pub max_stack_pow: Option<usize>,
}

#[pymethods]
impl PyHavocMutator {
    #[new]
    #[pyo3(signature = (max_stack_pow=None))]
    fn py_new(max_stack_pow: Option<usize>) -> Self {
        PyHavocMutator { max_stack_pow }
    }
}

impl PyHavocMutator {
    pub fn build(&self) -> HavocScheduledMutator<HavocMutationsType> {
        match self.max_stack_pow {
            Some(pow) => HavocScheduledMutator::with_max_stack_pow(havoc_mutations(), pow),
            None => HavocScheduledMutator::new(havoc_mutations()),
        }
    }
}

/// Python-exposed deterministic mutator that returns a fixed sequence of values.
#[pyclass(
    module = "angr.rustylib.fuzzer",
    name = "DeterministicMutator",
    from_py_object
)]
#[derive(Clone, Debug)]
pub struct PyDeterministicMutator {
    pub values: Vec<Vec<u8>>,
}

#[pymethods]
impl PyDeterministicMutator {
    #[new]
    fn py_new(values: Vec<Vec<u8>>) -> PyResult<Self> {
        if values.is_empty() {
            return Err(PyTypeError::new_err(
                "DeterministicMutator requires at least one value",
            ));
        }
        Ok(PyDeterministicMutator { values })
    }
}

impl PyDeterministicMutator {
    pub fn build(&self) -> DeterministicMutator {
        DeterministicMutator::new(self.values.clone())
    }
}

/// Build a DynMutator from an optional Python mutator object.
/// If None, uses the default Havoc mutator.
pub fn build_mutator(py_mutator: Option<&Bound<PyAny>>) -> PyResult<DynMutator> {
    match py_mutator {
        None => Ok(DynMutator::Havoc(HavocScheduledMutator::new(
            havoc_mutations(),
        ))),
        Some(obj) => {
            if let Ok(havoc) = obj.extract::<PyHavocMutator>() {
                Ok(DynMutator::Havoc(havoc.build()))
            } else if let Ok(det) = obj.extract::<PyDeterministicMutator>() {
                Ok(DynMutator::Deterministic(det.build()))
            } else {
                Err(PyTypeError::new_err(
                    "Expected mutator to be HavocMutator or DeterministicMutator",
                ))
            }
        }
    }
}
