use std::path::PathBuf;

use libafl::{
    corpus::{Corpus, CorpusId, InMemoryCorpus, OnDiskCorpus, Testcase},
    inputs::BytesInput,
};
use pyo3::{
    exceptions::{PyRuntimeError, PyTypeError},
    prelude::*,
};
use serde::{Deserialize, Serialize};

// A Send+Sync wrapper of InMemoryCorpus for use in PyInMemoryCorpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializedCorpus<I> {
    data: Vec<u8>,
    _phantom: std::marker::PhantomData<I>,
}

impl<I: Serialize> TryFrom<&InMemoryCorpus<I>> for SerializedCorpus<I> {
    type Error = PyErr;

    fn try_from(value: &InMemoryCorpus<I>) -> Result<Self, Self::Error> {
        Ok(SerializedCorpus {
            data: postcard::to_stdvec(value).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to serialize corpus: {e}"
                ))
            })?,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<I: for<'de> Deserialize<'de>> TryFrom<&SerializedCorpus<I>> for InMemoryCorpus<I> {
    type Error = PyErr;

    fn try_from(value: &SerializedCorpus<I>) -> Result<Self, Self::Error> {
        let corpus: InMemoryCorpus<I> = postcard::from_bytes(&value.data).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to deserialize corpus: {e}"
            ))
        })?;
        Ok(corpus)
    }
}

#[pyclass(module = "angr.rustylib.fuzzer", name = "InMemoryCorpus")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PyInMemoryCorpus {
    inner: SerializedCorpus<BytesInput>,
}

impl TryFrom<&PyInMemoryCorpus> for InMemoryCorpus<BytesInput> {
    type Error = PyErr;

    fn try_from(value: &PyInMemoryCorpus) -> Result<Self, Self::Error> {
        InMemoryCorpus::<BytesInput>::try_from(&value.inner)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}

impl TryFrom<&InMemoryCorpus<BytesInput>> for PyInMemoryCorpus {
    type Error = PyErr;

    fn try_from(value: &InMemoryCorpus<BytesInput>) -> Result<Self, Self::Error> {
        let serialized = SerializedCorpus::try_from(value)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(PyInMemoryCorpus { inner: serialized })
    }
}

#[pymethods]
impl PyInMemoryCorpus {
    #[new]
    fn py_new() -> PyResult<Self> {
        PyInMemoryCorpus::try_from(&InMemoryCorpus::default())
    }

    #[staticmethod]
    fn from_list(list: Vec<Vec<u8>>) -> PyResult<Self> {
        let mut corpus = InMemoryCorpus::default();
        for item in list {
            corpus
                .add(Testcase::new(BytesInput::from(item)))
                .map_err(|e| PyTypeError::new_err(e.to_string()))?;
        }
        PyInMemoryCorpus::try_from(&corpus)
    }

    fn to_bytes_list(&self) -> PyResult<Vec<Vec<u8>>> {
        let deserialized = InMemoryCorpus::<BytesInput>::try_from(&self.inner)?;
        let mut result = Vec::new();
        for i in 0..deserialized.count() {
            let corpus_id = CorpusId::from(i);
            if let Ok(testcase_ref) = deserialized.get(corpus_id) {
                let testcase = testcase_ref.borrow();
                if let Some(input) = testcase.input() {
                    result.push(input.as_ref().to_vec());
                }
            }
        }
        Ok(result)
    }

    fn __getitem__(&self, id: usize) -> PyResult<Vec<u8>> {
        let deserialized = InMemoryCorpus::<BytesInput>::try_from(self)?;
        let corpus_id = CorpusId::from(id);
        let testcase_ref = deserialized
            .get(corpus_id)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let testcase = testcase_ref.borrow();
        match testcase.input().clone() {
            Some(input) => Ok(input.into_inner()),
            None => Err(PyRuntimeError::new_err("Testcase input is None")),
        }
    }

    fn __len__(&self) -> PyResult<usize> {
        Ok(InMemoryCorpus::<BytesInput>::try_from(self)?.count())
    }

    fn __getstate__(&self) -> PyResult<Vec<u8>> {
        postcard::to_stdvec(&self.inner).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    fn __setstate__(&mut self, state: Vec<u8>) -> PyResult<()> {
        self.inner =
            postcard::from_bytes(&state).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(())
    }
}

// On DiskCorpus wrapper
#[pyclass(module = "angr.rustylib.fuzzer", name = "OnDiskCorpus", unsendable)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PyOnDiskCorpus {
    pub(crate) inner: OnDiskCorpus<BytesInput>,
}

#[pymethods]
impl PyOnDiskCorpus {
    #[new]
    fn py_new(dir_path: String) -> PyResult<Self> {
        let corpus =
            OnDiskCorpus::new(&dir_path).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(PyOnDiskCorpus { inner: corpus })
    }

    fn add(&mut self, input: Vec<u8>) -> PyResult<usize> {
        let testcase = Testcase::new(BytesInput::from(input));
        let corpus_id = self
            .inner
            .add(testcase)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(corpus_id.into())
    }

    fn __getitem__(&self, id: usize) -> PyResult<Vec<u8>> {
        let corpus_id = CorpusId::from(id);
        let testcase_ref = self
            .inner
            .get(corpus_id)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let testcase = testcase_ref.borrow();
        match testcase.input() {
            Some(input) => Ok(input.as_ref().to_vec()),
            None => Err(PyRuntimeError::new_err("Testcase input is None")),
        }
    }

    fn __len__(&self) -> usize {
        self.inner.count()
    }

    fn to_bytes_list(&self) -> PyResult<Vec<Vec<u8>>> {
        let mut result = Vec::new();
        for i in 0..self.inner.count() {
            let corpus_id = CorpusId::from(i);
            if let Ok(testcase_ref) = self.inner.get(corpus_id) {
                let testcase = testcase_ref.borrow();
                if let Some(input) = testcase.input() {
                    result.push(input.as_ref().to_vec());
                }
            }
        }
        Ok(result)
    }

    fn __getstate__(&self) -> PyResult<PathBuf> {
        Ok(self.inner.dir_path().to_path_buf())
    }

    fn __setstate__(&mut self, state: PathBuf) -> PyResult<()> {
        self.inner = OnDiskCorpus::new(state.to_str().unwrap())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(())
    }
}
