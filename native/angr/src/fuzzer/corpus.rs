use std::{cell::RefCell, path::PathBuf};

use libafl::{
    corpus::{Corpus, CorpusId, InMemoryCorpus, OnDiskCorpus, Testcase},
    Error,
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

// Dynamic Corpus that can encapsulate InMemoryCorpus and OnDiskCorpus at runtime
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DynCorpus<I> {
    InMem(InMemoryCorpus<I>),
    OnDisk(OnDiskCorpus<I>),
}

// Have Dynamic Corpus implement Corpus<I> trait
impl<I> Corpus<I> for DynCorpus<I>
where
    I: libafl::inputs::Input,
{
    fn count(&self) -> usize {
        match self {
            DynCorpus::InMem(c) => c.count(),
            DynCorpus::OnDisk(c) => c.count(),
        }
    }

    fn count_disabled(&self) -> usize {
        match self {
            DynCorpus::InMem(c) => c.count_disabled(),
            DynCorpus::OnDisk(c) => c.count_disabled(),
        }
    }

    fn count_all(&self) -> usize {
        match self {
            DynCorpus::InMem(c) => c.count_all(),
            DynCorpus::OnDisk(c) => c.count_all(),
        }
    }

    fn add(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        match self {
            DynCorpus::InMem(c) => c.add(testcase),
            DynCorpus::OnDisk(c) => c.add(testcase),
        }
    }

    fn add_disabled(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        match self {
            DynCorpus::InMem(c) => c.add_disabled(testcase),
            DynCorpus::OnDisk(c) => c.add_disabled(testcase),
        }
    }

    fn replace(&mut self, id: CorpusId, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        match self {
            DynCorpus::InMem(c) => c.replace(id, testcase),
            DynCorpus::OnDisk(c) => c.replace(id, testcase),
        }
    }

    fn remove(&mut self, id: CorpusId) -> Result<Testcase<I>, Error> {
        match self {
            DynCorpus::InMem(c) => c.remove(id),
            DynCorpus::OnDisk(c) => c.remove(id),
        }
    }

    fn get(&self, id: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        match self {
            DynCorpus::InMem(c) => c.get(id),
            DynCorpus::OnDisk(c) => c.get(id),
        }
    }

    fn get_from_all(&self, id: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        match self {
            DynCorpus::InMem(c) => c.get_from_all(id),
            DynCorpus::OnDisk(c) => c.get_from_all(id),
        }
    }

    fn current(&self) -> &Option<CorpusId> {
        match self {
            DynCorpus::InMem(c) => c.current(),
            DynCorpus::OnDisk(c) => c.current(),
        }
    }

    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        match self {
            DynCorpus::InMem(c) => c.current_mut(),
            DynCorpus::OnDisk(c) => c.current_mut(),
        }
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        match self {
            DynCorpus::InMem(c) => c.next(id),
            DynCorpus::OnDisk(c) => c.next(id),
        }
    }

    fn peek_free_id(&self) -> CorpusId {
        match self {
            DynCorpus::InMem(c) => c.peek_free_id(),
            DynCorpus::OnDisk(c) => c.peek_free_id(),
        }
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        match self {
            DynCorpus::InMem(c) => c.prev(id),
            DynCorpus::OnDisk(c) => c.prev(id),
        }
    }

    fn first(&self) -> Option<CorpusId> {
        match self {
            DynCorpus::InMem(c) => c.first(),
            DynCorpus::OnDisk(c) => c.first(),
        }
    }

    fn last(&self) -> Option<CorpusId> {
        match self {
            DynCorpus::InMem(c) => c.last(),
            DynCorpus::OnDisk(c) => c.last(),
        }
    }

    fn nth_from_all(&self, nth: usize) -> CorpusId {
        match self {
            DynCorpus::InMem(c) => c.nth_from_all(nth),
            DynCorpus::OnDisk(c) => c.nth_from_all(nth),
        }
    }

    fn load_input_into(&self, testcase: &mut Testcase<I>) -> Result<(), Error> {
        match self {
            DynCorpus::InMem(c) => c.load_input_into(testcase),
            DynCorpus::OnDisk(c) => c.load_input_into(testcase),
        }
    }

    fn store_input_from(&self, testcase: &Testcase<I>) -> Result<(), Error> {
        match self {
            DynCorpus::InMem(c) => c.store_input_from(testcase),
            DynCorpus::OnDisk(c) => c.store_input_from(testcase),
        }
    }
}

// Converts python objects into Rust enum
impl TryFrom<&PyInMemoryCorpus> for DynCorpus<BytesInput> {
    type Error = PyErr;

    fn try_from(value: &PyInMemoryCorpus) -> Result<Self, Self::Error> {
        let inner: InMemoryCorpus<BytesInput> =
            InMemoryCorpus::<BytesInput>::try_from(value)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(DynCorpus::InMem(inner))
    }
}

impl TryFrom<&PyOnDiskCorpus> for DynCorpus<BytesInput> {
    type Error = PyErr;

    fn try_from(value: &PyOnDiskCorpus) -> Result<Self, Self::Error> {
        Ok(DynCorpus::OnDisk(value.inner.clone()))
    }
}

// Converts Rust enum back into python object
impl DynCorpus<BytesInput> {
    pub fn to_py<'py>(&self, py: Python<'py>) -> PyResult<Py<PyAny>> {
        match self {
            DynCorpus::InMem(inner) => {
                let py_inmem = PyInMemoryCorpus::try_from(inner)
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                let obj = Py::new(py, py_inmem)?; // Py<PyInMemoryCorpus>
                Ok(obj.into_bound(py).into_any().unbind())
            }
            DynCorpus::OnDisk(inner) => {
                let py_ondisk = PyOnDiskCorpus { inner: inner.clone() };
                let obj = Py::new(py, py_ondisk)?; // Py<PyOnDiskCorpus>
                Ok(obj.into_bound(py).into_any().unbind())
            }
        }
    }
}
