pub mod corpus;
pub mod executor;
pub mod monitor;

use std::time::Duration;

use libafl::{
    NopInputFilter, StdFuzzer,
    events::SimpleEventManager,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    inputs::{BytesInput, NopToTargetBytes},
    mutators::{HavocMutationsType, HavocScheduledMutator, havoc_mutations},
    observers::OwnedMapObserver,
    schedulers::QueueScheduler,
    stages::StdMutationalStage,
    state::{HasCorpus, HasSolutions, StdState},
};
use libafl_bolts::{
    rands::StdRand,
    tuples::{tuple_list, tuple_list_type},
};
use pyo3::exceptions::PyRuntimeError;
use pyo3::{Py, exceptions::PyTypeError, prelude::*};

use crate::fuzzer::{
    corpus::{DynCorpus, PyInMemoryCorpus, PyOnDiskCorpus},
    executor::PyExecutorInner,
    monitor::CallbackMonitor,
};

// LibAFL uses a LOT of generics. To try and make it easier to read, these
// alias are used to match the generic type names used in LibAFL.
pub(crate) type I = BytesInput;
pub(crate) type C = DynCorpus<I>;
pub(crate) type S = StdState<C, I, StdRand, C>;
pub(crate) type MT = CallbackMonitor;
pub(crate) type EM = SimpleEventManager<I, MT, S>;
pub(crate) type O = OwnedMapObserver<u8>;
pub(crate) type OT = tuple_list_type!(O);
pub(crate) type Z = StdFuzzer<
    QueueScheduler,
    MaxMapFeedback<O, O>,
    NopToTargetBytes,
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
        corpus: Bound<PyAny>,
        solutions: Bound<PyAny>,
        apply_fn: Bound<PyAny>,
        timeout: Option<u64>,
        seed: u64,
    ) -> PyResult<Self> {
        if !apply_fn.is_callable() {
            return Err(PyTypeError::new_err("Expected a callable harness function"));
        }

        let observer = OwnedMapObserver::new("", vec![0u8; 65536]);
        let mut feedback = MaxMapFeedback::with_name("edges", &observer);
        let mut objective = CrashFeedback::default();

        // Convert Python corpus wrappers into dynamic corpus variants
        let corpus: C = if let Ok(py_ondisk) = corpus.extract::<PyOnDiskCorpus>() {
            DynCorpus::OnDisk(py_ondisk.inner.clone())
        } else if let Ok(py_inmem) = corpus.extract::<PyInMemoryCorpus>() {
            DynCorpus::try_from(&py_inmem)?
        } else {
            return Err(PyTypeError::new_err(
                "Expected corpus to be OnDiskCorpus or InMemoryCorpus",
            ));
        };

        let solutions: C = if let Ok(py_ondisk) = solutions.extract::<PyOnDiskCorpus>() {
            DynCorpus::OnDisk(py_ondisk.inner.clone())
        } else if let Ok(py_inmem) = solutions.extract::<PyInMemoryCorpus>() {
            DynCorpus::try_from(&py_inmem)?
        } else {
            return Err(PyTypeError::new_err(
                "Expected solutions to be OnDiskCorpus or InMemoryCorpus",
            ));
        };

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
            NopToTargetBytes,
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

    fn corpus(&self) -> PyResult<Py<PyAny>> {
        Python::attach(|py| self.fuzzer_state.corpus().to_py(py))
    }

    fn solutions(&self) -> PyResult<Py<PyAny>> {
        Python::attach(|py| self.fuzzer_state.solutions().to_py(py))
    }

    #[pyo3(signature = (progress_callback = None))]
    fn run_once(&mut self, progress_callback: Option<CallbackMonitor>) -> PyResult<usize> {
        libafl::Fuzzer::fuzz_one(
            &mut self.fuzzer,
            &mut self.stages,
            &mut self.executor,
            &mut self.fuzzer_state,
            &mut SimpleEventManager::new(progress_callback.unwrap_or_default()),
        )
        .map(|corpus_id| corpus_id.0)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    #[pyo3(signature = (progress_callback = None, iterations = None))]
    fn run(
        &mut self,
        progress_callback: Option<CallbackMonitor>,
        iterations: Option<u64>,
    ) -> PyResult<()> {
        if let Some(iters) = iterations {
            libafl::Fuzzer::fuzz_loop_for(
                &mut self.fuzzer,
                &mut self.stages,
                &mut self.executor,
                &mut self.fuzzer_state,
                &mut SimpleEventManager::new(progress_callback.unwrap_or_default()),
                iters,
            )
            .map(|_| ())
        } else {
            libafl::Fuzzer::fuzz_loop(
                &mut self.fuzzer,
                &mut self.stages,
                &mut self.executor,
                &mut self.fuzzer_state,
                &mut SimpleEventManager::new(progress_callback.unwrap_or_default()),
            )
        }
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}

#[pymodule]
pub fn fuzzer(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Fuzzer>()?;
    m.add_class::<corpus::PyInMemoryCorpus>()?;
    m.add_class::<corpus::PyOnDiskCorpus>()?;
    m.add_class::<monitor::ClientStats>()?;
    Ok(())
}
