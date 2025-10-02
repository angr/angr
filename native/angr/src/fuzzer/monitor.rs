use std::fmt::Debug;

use libafl::monitors::Monitor;
use pyo3::prelude::*;

#[pyclass(name = "Monitor", module = "angr.rustylib.fuzzer.monitor", subclass)]
pub struct PyMonitor {}

#[pyclass(module = "angr.rustylib.fuzzer.monitor", extends = PyMonitor)]
pub struct NopMonitor {}

#[pymethods]
impl NopMonitor {
    #[new]
    fn py_new() -> (Self, PyMonitor) {
        (NopMonitor {}, PyMonitor {})
    }
}

#[pyclass(module = "angr.rustylib.fuzzer.monitor", extends = PyMonitor)]
pub struct StderrMonitor {}

#[pymethods]
impl StderrMonitor {
    #[new]
    fn py_new() -> (Self, PyMonitor) {
        (StderrMonitor {}, PyMonitor {})
    }
}

pub struct DynMonitor {
    name: String,
    monitor: Box<dyn Monitor>,
}

impl Debug for DynMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DynMonitor({})", self.name)
    }
}

impl Default for DynMonitor {
    fn default() -> Self {
        DynMonitor {
            name: "NopMonitor".to_string(),
            monitor: Box::new(libafl::monitors::NopMonitor::new()),
        }
    }
}

impl Monitor for DynMonitor {
    fn display(
        &mut self,
        client_stats_manager: &mut libafl::monitors::stats::ClientStatsManager,
        event_msg: &str,
        sender_id: libafl_bolts::ClientId,
    ) -> Result<(), libafl::Error> {
        self.monitor
            .display(client_stats_manager, event_msg, sender_id)
    }
}

impl FromPyObject<'_> for DynMonitor {
    fn extract_bound(ob: &Bound<'_, PyAny>) -> PyResult<Self> {
        if ob.is_instance_of::<NopMonitor>() {
            Ok(DynMonitor {
                name: "NopMonitor".to_string(),
                monitor: Box::new(libafl::monitors::NopMonitor::new()),
            })
        } else if ob.is_instance_of::<StderrMonitor>() {
            Ok(DynMonitor {
                name: "StderrMonitor".to_string(),
                monitor: Box::new(libafl::monitors::SimpleMonitor::new(|msg| {
                    eprintln!("{msg}");
                })),
            })
        } else {
            Err(pyo3::exceptions::PyTypeError::new_err(
                "Expected a subclass of Monitor",
            ))
        }
    }
}
