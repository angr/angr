use pyo3::{exceptions::PyTypeError, prelude::*};

/// An angr `SuccessorsEngine`, checked when it is extracted from Python.
pub struct PyEngine(Py<PyAny>);

impl PyEngine {
    /// Build the engine used when the caller does not provide one.
    pub fn icicle(project: &Bound<'_, PyAny>) -> PyResult<Self> {
        let engine = project
            .py()
            .import("angr.engines.icicle")?
            .getattr("UberIcicleEngine")?
            .call1((project,))?;
        Ok(PyEngine(engine.unbind()))
    }

    pub fn bind<'py>(&self, py: Python<'py>) -> &Bound<'py, PyAny> {
        self.0.bind(py)
    }
}

impl<'py> FromPyObject<'_, 'py> for PyEngine {
    type Error = PyErr;

    fn extract(obj: Borrowed<'_, 'py, PyAny>) -> Result<Self, Self::Error> {
        let engine_cls = obj
            .py()
            .import("angr.engines.successors")?
            .getattr("SuccessorsEngine")?;
        if !obj.is_instance(&engine_cls)? {
            return Err(PyTypeError::new_err(
                "Expected engine to be a SuccessorsEngine instance",
            ));
        }
        Ok(PyEngine(obj.into()))
    }
}
