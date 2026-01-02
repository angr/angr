use pyo3::prelude::*;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq)]
pub enum TagValue {
    Int(i64),
    Str(String),
}

impl TagValue {
    pub fn __repr__(&self) -> String {
        match self {
            TagValue::Int(i) => format!("{}", i),
            TagValue::Str(s) => format!("'{}'", s),
        }
    }
}

// Implement conversion from Python objects to TagValue
impl<'py> FromPyObject<'_, 'py> for TagValue {
    type Error = PyErr;

    fn extract(ob: Borrowed<'_, 'py, PyAny>) -> Result<Self, Self::Error> {
        if let Ok(i) = ob.extract::<i64>() {
            Ok(TagValue::Int(i))
        } else if let Ok(s) = ob.extract::<String>() {
            Ok(TagValue::Str(s))
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                "TagValue must be int or str"
            ))
        }
    }
}

// Implement conversion back to Python
impl<'py> IntoPyObject<'py> for TagValue {
    type Target = PyAny;
    type Output = Bound<'py, Self::Target>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        match self {
            TagValue::Int(i) => i.into_pyobject(py).map(|b| b.into_any()).map_err(|e| e.into()),
            TagValue::Str(s) => s.into_pyobject(py).map(|b| b.into_any()).map_err(|e| e.into()),
        }
    }
}

/// Type alias for the tags dictionary
pub type Tags = HashMap<String, TagValue>;