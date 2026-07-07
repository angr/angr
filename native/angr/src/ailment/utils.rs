//! Helpers shared across the ailment port.

use pyo3::prelude::*;
use pyo3::types::PyAnyMethods;

/// Call `x.deep_copy(manager)`. Used pervasively.
pub fn deep_copy_obj<'py>(
    obj: &Bound<'py, PyAny>,
    manager: &Bound<'py, PyAny>,
) -> PyResult<Py<PyAny>> {
    if obj.is_none() {
        return Ok(obj.clone().unbind());
    }
    let r = obj.call_method1("deep_copy", (manager,))?;
    Ok(r.unbind())
}
