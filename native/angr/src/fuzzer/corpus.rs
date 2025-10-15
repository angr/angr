use libafl::{
    corpus::{Corpus, CorpusId, InMemoryCorpus, Testcase},
    inputs::BytesInput,
};
use pyo3::{
    exceptions::{PyRuntimeError, PyTypeError},
    prelude::*,
};
use serde::{Deserialize, Serialize};

#[pyclass(module = "angr.rustylib.fuzzer", name = "InMemoryCorpus", unsendable)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PyInMemoryCorpus {
    inner: InMemoryCorpus<BytesInput>,
}

#[pymethods]
impl PyInMemoryCorpus {
    #[new]
    fn py_new() -> Self {
        PyInMemoryCorpus {
            inner: InMemoryCorpus::default(),
        }
    }

    #[staticmethod]
    fn from_list(list: Vec<Vec<u8>>) -> PyResult<Self> {
        let mut corpus = InMemoryCorpus::default();
        for item in list {
            corpus
                .add(Testcase::new(BytesInput::from(item)))
                .map_err(|e| PyTypeError::new_err(e.to_string()))?;
        }
        Ok(PyInMemoryCorpus { inner: corpus })
    }

    fn to_bytes_list(&self) -> Vec<Vec<u8>> {
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
        result
    }

    fn __getitem__(&self, id: usize) -> PyResult<Vec<u8>> {
        let corpus_id = CorpusId::from(id);
        let testcase_ref = self
            .inner
            .get(corpus_id)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let testcase = testcase_ref.borrow();
        match testcase.input().clone() {
            Some(input) => Ok(input.into_inner()),
            None => Err(PyRuntimeError::new_err("Testcase input is None")),
        }
    }

    fn __len__(&self) -> usize {
        self.inner.count()
    }
}

impl Corpus<BytesInput> for PyInMemoryCorpus {
    fn count(&self) -> usize {
        self.inner.count()
    }

    fn count_disabled(&self) -> usize {
        self.inner.count_disabled()
    }

    fn count_all(&self) -> usize {
        self.inner.count_all()
    }

    fn add(
        &mut self,
        testcase: Testcase<BytesInput>,
    ) -> Result<libafl::corpus::CorpusId, libafl::Error> {
        self.inner.add(testcase)
    }

    fn add_disabled(
        &mut self,
        testcase: Testcase<BytesInput>,
    ) -> Result<libafl::corpus::CorpusId, libafl::Error> {
        self.inner.add_disabled(testcase)
    }

    fn replace(
        &mut self,
        id: libafl::corpus::CorpusId,
        testcase: Testcase<BytesInput>,
    ) -> Result<Testcase<BytesInput>, libafl::Error> {
        self.inner.replace(id, testcase)
    }

    fn remove(
        &mut self,
        id: libafl::corpus::CorpusId,
    ) -> Result<Testcase<BytesInput>, libafl::Error> {
        self.inner.remove(id)
    }

    fn get(
        &self,
        id: libafl::corpus::CorpusId,
    ) -> Result<&std::cell::RefCell<Testcase<BytesInput>>, libafl::Error> {
        self.inner.get(id)
    }

    fn get_from_all(
        &self,
        id: libafl::corpus::CorpusId,
    ) -> Result<&std::cell::RefCell<Testcase<BytesInput>>, libafl::Error> {
        self.inner.get_from_all(id)
    }

    fn current(&self) -> &Option<libafl::corpus::CorpusId> {
        self.inner.current()
    }

    fn current_mut(&mut self) -> &mut Option<libafl::corpus::CorpusId> {
        self.inner.current_mut()
    }

    fn next(&self, id: libafl::corpus::CorpusId) -> Option<libafl::corpus::CorpusId> {
        self.inner.next(id)
    }

    fn peek_free_id(&self) -> libafl::corpus::CorpusId {
        self.inner.peek_free_id()
    }

    fn prev(&self, id: libafl::corpus::CorpusId) -> Option<libafl::corpus::CorpusId> {
        self.inner.prev(id)
    }

    fn first(&self) -> Option<libafl::corpus::CorpusId> {
        self.inner.first()
    }

    fn last(&self) -> Option<libafl::corpus::CorpusId> {
        self.inner.last()
    }

    fn nth_from_all(&self, nth: usize) -> libafl::corpus::CorpusId {
        self.inner.nth_from_all(nth)
    }

    fn load_input_into(&self, testcase: &mut Testcase<BytesInput>) -> Result<(), libafl::Error> {
        self.inner.load_input_into(testcase)
    }

    fn store_input_from(&self, testcase: &Testcase<BytesInput>) -> Result<(), libafl::Error> {
        self.inner.store_input_from(testcase)
    }
}
