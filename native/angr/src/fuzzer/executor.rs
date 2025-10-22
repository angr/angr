use std::time::Duration;

use backtrace::Backtrace;
use libafl::{
    executors::{Executor, ExitKind, HasObservers, HasTimeout},
    observers::MapObserver,
    state::HasExecutions,
};
use libafl_bolts::{AsSliceMut, tuples::RefIndexable};
use pyo3::{exceptions::PyRuntimeError, prelude::*};

use crate::fuzzer::{EM, I, OT, S, Z};

pub struct PyExecutorInner<S> {
    base_state: Py<PyAny>,
    apply_fn: Py<PyAny>,
    observers: OT,
    timeout: Option<Duration>,
    phantom: std::marker::PhantomData<S>,
}

impl<S> PyExecutorInner<S> {
    pub fn new(
        base_state: Bound<PyAny>,
        apply_fn: Bound<PyAny>,
        observers: OT,
        timeout: Option<Duration>,
    ) -> PyResult<Self> {
        if !apply_fn.is_callable() {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Expected a callable function",
            ));
        }
        Ok(PyExecutorInner {
            base_state: base_state.unbind(),
            apply_fn: apply_fn.unbind(),
            observers,
            timeout,
            phantom: std::marker::PhantomData,
        })
    }
}

impl Executor<EM, I, S, Z> for PyExecutorInner<S> {
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, libafl::Error> {
        *state.executions_mut() += 1;

        let (emulator, exit) =
            Python::attach(|py| {
                || -> _ {
                // Step 1: Copy the base state and run the apply function
                // Copy base state by calling python copy function
                let copied_state = self.base_state.bind(py).getattr("copy")?.call0()?;

                // Call apply_fn on the state with the input
                let apply_fn = self.apply_fn.bind(py);
                apply_fn.call1((&copied_state, input.as_ref()))?;

                // Step 2: Use an emulator to run the target
                let project = copied_state.getattr("project")?;
                let icicle_engine = py
                    .import("angr.engines.icicle")?
                    .getattr("UberIcicleEngine")?
                    .call1((project,))?;
                let emulator = py
                    .import("angr.emulator")?
                    .getattr("Emulator")?
                    .call1((icicle_engine, &copied_state))?;

                // Step 2.5: Set return address as breakpoint to detect normal returns
                let calling_convention = self.base_state.getattr(py, "project")?
                    .getattr(py, "factory")?
                    .getattr(py, "cc")?
                    .call0(py)?;
                let return_addr = calling_convention
                    .getattr(py, "return_addr")?
                    .getattr(py, "get_value")?
                    .call1(py, (copied_state,))?
                    .getattr(py, "concrete_value")?
                    .extract::<u64>(py).map_err(|_| {
                        PyRuntimeError::new_err(
                            "Failed to extract return address, is it symbolic?".to_string(),
                        )
                    })?;

                emulator.call_method1("add_breakpoint", (return_addr,))?;
                emulator.call_method1("add_breakpoint", (return_addr & !1,))?;

                let exit = emulator
                    .getattr("run")?
                    .call0()?
                    .getattr("name")?
                    .extract::<String>()?;

                Ok((emulator.unbind(), exit))
            }()
            .map_err(|e: PyErr| {
                if let Some(traceback) = e.traceback(py) {
                    if let Ok(traceback_str) = traceback.format() {
                        libafl::Error::Unknown(
                            format!("Python error building emulator: {e}\n{traceback_str:?}"),
                            Backtrace::new(),
                        )
                    } else {
                        libafl::Error::Unknown(
                            format!(
                                "Python error building emulator (traceback formatting failed): {e}"
                            ),
                            Backtrace::new(),
                        )
                    }
                } else {
                    libafl::Error::Unknown(
                        format!("Python error building emulator (no traceback available): {e}"),
                        Backtrace::new(),
                    )
                }
            })
            })?;

        // Step 3: Handle the result
        let result = match exit.as_str() {
            "INSTRUCTION_LIMIT" => Ok(ExitKind::Timeout),
            "BREAKPOINT" => Ok(ExitKind::Ok),
            "NO_SUCCESSORS" => Err(libafl::Error::Unknown(
                "No successors found".to_string(),
                Backtrace::new(),
            )),
            "MEMORY_ERROR" => Ok(ExitKind::Crash),
            "FAILURE" => Err(libafl::Error::Unknown(
                "Unexpected exit reason".to_string(),
                Backtrace::new(),
            )),
            "EXIT" => Ok(ExitKind::Ok),
            _ => Err(libafl::Error::Unknown(
                "Unexpected exit reason".to_string(),
                Backtrace::new(),
            )),
        };

        // Step 4: Copy the edge map from state.history to the observer to provide feedback
        let py_hitmap: Vec<u8> = Python::attach(|py| {
            emulator
                .bind(py)
                .getattr("state")?
                .getattr("history")?
                .getattr("last_edge_hitmap")?
                .extract()
        })
        .map_err(|e| {
            libafl::Error::Unknown(
                format!("Python error extracting hitmap: {e}"),
                Backtrace::new(),
            )
        })?;
        if py_hitmap.len() != self.observers.0.usable_count() {
            return Err(libafl::Error::Unknown(
                format!(
                    "Hitmap length {} does not match observer length {}",
                    py_hitmap.len(),
                    self.observers.0.usable_count()
                ),
                Backtrace::new(),
            ));
        }
        self.observers.0.as_slice_mut().copy_from_slice(&py_hitmap);

        result
    }
}

impl<S> HasObservers for PyExecutorInner<S> {
    type Observers = OT;

    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}

impl<S> HasTimeout for PyExecutorInner<S> {
    fn timeout(&self) -> Duration {
        self.timeout.unwrap_or(Duration::ZERO)
    }

    fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = Some(timeout);
    }
}
