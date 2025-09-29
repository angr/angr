pub mod corpus;
pub mod executor;
pub mod monitor;

use std::time::Duration;

use libafl::{
    NopInputFilter, StdFuzzer,
    events::SimpleEventManager,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    inputs::{BytesInput, NopBytesConverter},
    mutators::{HavocMutationsType, HavocScheduledMutator, havoc_mutations},
    observers::OwnedMapObserver,
    schedulers::QueueScheduler,
    stages::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{
    rands::StdRand,
    tuples::{tuple_list, tuple_list_type},
};
use pyo3::exceptions::PyRuntimeError;
use pyo3::{exceptions::PyTypeError, prelude::*};

use crate::fuzzer::{corpus::PyInMemoryCorpus, executor::PyExecutorInner, monitor::DynMonitor};

// LibAFL uses a LOT of generics. To try and make it easier to read, these
// alias are used to match the generic type names used in LibAFL.
pub(crate) type C = PyInMemoryCorpus;
pub(crate) type I = BytesInput;
pub(crate) type S = StdState<C, I, StdRand, C>;
pub(crate) type MT = DynMonitor;
pub(crate) type EM = SimpleEventManager<I, MT, S>;
pub(crate) type O = OwnedMapObserver<u8>;
pub(crate) type OT = tuple_list_type!(O);
pub(crate) type Z = StdFuzzer<
    QueueScheduler,
    MaxMapFeedback<O, O>,
    NopBytesConverter,
    NopInputFilter,
    CrashFeedback,
>;
pub(crate) type E = PyExecutorInner<S>;
pub(crate) type M = HavocScheduledMutator<HavocMutationsType>;

#[pyclass(module = "angr.rustylib.fuzzer", unsendable)]
struct Fuzzer {
    fuzzer_state: S,
    fuzzer: Z,
    stages: tuple_list_type!(StdMutationalStage<E, EM, I, I, M, S, Z>),
    executor: PyExecutorInner<S>,
}

#[pymethods]
impl Fuzzer {
    #[new]
    fn py_new(
        base_state: Bound<PyAny>,
        corpus: PyInMemoryCorpus,
        solutions: PyInMemoryCorpus,
        apply_fn: Bound<PyAny>,
        timeout: Option<u64>,
        seed: u64,
    ) -> PyResult<Self> {
        if !apply_fn.is_callable() {
            return Err(PyTypeError::new_err("Expected a callable harness function"));
        }

        let observer = OwnedMapObserver::new("", vec![0u8; 65536]);
        let mut feedback = MaxMapFeedback::new(&observer);
        let mut objective = CrashFeedback::default();

        let fuzzer_state = StdState::new(
            StdRand::with_seed(seed),
            corpus,
            solutions,
            &mut feedback,
            &mut objective,
        )
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        let fuzzer: StdFuzzer<
            QueueScheduler,
            MaxMapFeedback<OwnedMapObserver<u8>, OwnedMapObserver<u8>>,
            NopBytesConverter,
            NopInputFilter,
            CrashFeedback,
        > = StdFuzzer::new(QueueScheduler::new(), feedback, objective);

        let stages = tuple_list!(StdMutationalStage::new(HavocScheduledMutator::new(
            havoc_mutations()
        )),);

        let executor = PyExecutorInner::new(
            base_state,
            apply_fn,
            tuple_list!(observer),
            Some(Duration::from_millis(timeout.unwrap_or(0))),
        )
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        Ok(Fuzzer {
            fuzzer_state,
            fuzzer,
            stages,
            executor,
        })
    }

    #[pyo3(signature = (monitor = None))]
    fn run_once(&mut self, monitor: Option<DynMonitor>) -> PyResult<usize> {
        libafl::Fuzzer::fuzz_one(
            &mut self.fuzzer,
            &mut self.stages,
            &mut self.executor,
            &mut self.fuzzer_state,
            &mut SimpleEventManager::new(monitor.unwrap_or_default()),
        )
        .map(|corpus_id| corpus_id.0)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}

#[pymodule]
pub fn fuzzer(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Fuzzer>()?;
    m.add_class::<corpus::PyInMemoryCorpus>()?;
    m.add_class::<monitor::PyMonitor>()?;
    m.add_class::<monitor::NopMonitor>()?;
    m.add_class::<monitor::StderrMonitor>()?;
    Ok(())
}
