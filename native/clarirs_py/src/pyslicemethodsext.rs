use pyo3::types::PySlice;

use crate::prelude::*;

pub trait PySliceMethodsExt {
    fn start(&self) -> PyResult<Option<isize>>;
    fn stop(&self) -> PyResult<Option<isize>>;
    fn step(&self) -> PyResult<Option<isize>>;
}

impl PySliceMethodsExt for Bound<'_, PySlice> {
    fn start(&self) -> PyResult<Option<isize>> {
        self.as_any().getattr("start")?.extract()
    }

    fn stop(&self) -> PyResult<Option<isize>> {
        self.as_any().getattr("stop")?.extract()
    }

    fn step(&self) -> PyResult<Option<isize>> {
        self.as_any().getattr("step")?.extract()
    }
}
