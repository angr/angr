use std::time::Duration;

use libafl::monitors::Monitor;
use libafl_bolts::current_time;
use pyo3::{exceptions::PyTypeError, prelude::*};

/// Python view into libafl client statistics
#[pyclass(module = "angr.rustylib.fuzzer")]
pub struct ClientStats {
    inner: libafl::monitors::stats::ClientStats,
}

#[pymethods]
impl ClientStats {
    #[getter]
    pub fn enabled(&self) -> bool {
        self.inner.enabled()
    }

    #[getter]
    pub fn corpus_size(&self) -> u64 {
        self.inner.corpus_size()
    }

    #[getter]
    pub fn last_corpus_time(&self) -> Duration {
        self.inner.last_corpus_time()
    }

    #[getter]
    pub fn executions(&self) -> u64 {
        self.inner.executions()
    }

    #[getter]
    pub fn prev_state_executions(&self) -> u64 {
        self.inner.prev_state_executions()
    }

    #[getter]
    pub fn objective_size(&self) -> u64 {
        self.inner.objective_size()
    }

    #[getter]
    pub fn last_objective_time(&self) -> Duration {
        self.inner.last_objective_time()
    }

    #[getter]
    pub fn last_window_time(&self) -> Duration {
        self.inner.last_window_time()
    }

    #[getter]
    pub fn start_time(&self) -> Duration {
        self.inner.start_time()
    }

    #[getter]
    pub fn execs_per_sec(&mut self) -> f64 {
        self.inner.execs_per_sec(current_time())
    }

    #[getter]
    pub fn execs_per_sec_pretty(&mut self) -> String {
        self.inner.execs_per_sec_pretty(current_time())
    }

    #[getter]
    pub fn edges_hit(&self) -> Option<u64> {
        self.inner.edges_coverage().map(|c| c.edges_hit)
    }

    #[getter]
    pub fn edges_total(&self) -> Option<u64> {
        self.inner.edges_coverage().map(|c| c.edges_total)
    }
}

#[derive(Default)]
pub struct CallbackMonitor {
    callback: Option<Py<PyAny>>,
}

impl<'py> FromPyObject<'_, 'py> for CallbackMonitor {
    type Error = PyErr;

    fn extract(obj: Borrowed<'_, 'py, PyAny>) -> Result<Self, Self::Error> {
        if !obj.is_callable() {
            return Err(PyTypeError::new_err("Expected a callable monitor function"));
        }
        Ok(CallbackMonitor {
            callback: Some(obj.into()),
        })
    }
}

impl Monitor for CallbackMonitor {
    fn display(
        &mut self,
        client_stats_manager: &mut libafl::monitors::stats::ClientStatsManager,
        event_msg: &str,
        sender_id: libafl_bolts::ClientId,
    ) -> Result<(), libafl::Error> {
        Python::attach(|py| {
            let stats = ClientStats {
                inner: client_stats_manager.client_stats_for(sender_id)?.clone(),
            };
            if let Some(self_callback) = &self.callback {
                self_callback
                    .call1(py, (stats, event_msg.to_string(), sender_id.0))
                    .unwrap(); // FIXME: Remove unwrap
            }
            Ok(())
        })
    }
}
