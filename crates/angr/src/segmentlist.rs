use std::collections::HashSet;

use pyo3::{exceptions::PyStopIteration, prelude::*, types::PyTuple};
use rangemap::RangeMap;

#[pyclass(module = "angr.rustylib.segmentlist")]
#[derive(Clone, Debug)]
pub struct Segment {
    #[pyo3(get)]
    start: u64,
    #[pyo3(get)]
    end: u64,
    #[pyo3(get)]
    sort: Option<String>,
}

#[pymethods]
impl Segment {
    #[new]
    pub fn new(start: u64, end: u64, sort: Option<String>) -> Self {
        Segment { start, end, sort }
    }

    pub fn __getnewargs__(&self) -> (u64, u64, Option<String>) {
        (self.start, self.end, self.sort.clone())
    }

    pub fn copy(&self) -> Self {
        self.clone()
    }

    #[getter]
    pub fn size(&self) -> u64 {
        self.end - self.start
    }

    fn __repr__(&self) -> String {
        format!(
            "[{:#x}-{:#x}, {}]",
            self.start,
            self.end,
            self.sort.clone().unwrap_or("None".to_string())
        )
    }
}

/// Should be called a SegmentMap!
#[derive(Clone, Default)]
#[pyclass(module = "angr.rustylib.segmentlist")]
pub struct SegmentList(RangeMap<u64, Option<String>>);

impl SegmentList {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get_segment(&self, address: u64) -> Option<(u64, u64, Option<String>)> {
        self.0
            .get_key_value(&address)
            .map(|(range, sort)| (range.start, range.end - range.start, sort.clone()))
    }
}

#[pymethods]
impl SegmentList {
    #[new]
    pub fn new() -> Self {
        Default::default()
    }

    pub fn __getnewargs__(&self, py: Python<'_>) -> Py<PyTuple> {
        PyTuple::empty(py).unbind()
    }

    pub fn __getstate__(&self) -> Vec<(u64, u64, Option<String>)> {
        self.0
            .iter()
            .map(|(r, sort)| (r.start, r.end - r.start, sort.clone()))
            .collect()
    }

    pub fn __setstate__(&mut self, state: Vec<(u64, u64, Option<String>)>) {
        self.0.clear();
        for (start, size, sort) in state {
            self.occupy(start, size, sort);
        }
    }

    pub fn __len__(&self) -> usize {
        self.0.len()
    }

    pub fn __getitem__(&self, idx: usize) -> PyResult<Segment> {
        self.0
            .iter()
            .nth(idx)
            .map(|(r, sort)| Segment::new(r.start, r.end, sort.clone()))
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyIndexError, _>(format!(
                    "Index {} out of range",
                    idx
                ))
            })
    }

    pub fn __iter__(self_: Py<Self>) -> SegmentListIter {
        SegmentListIter::new(self_)
    }

    #[getter]
    pub fn occupied_size(&self) -> u64 {
        self.0.iter().map(|(r, _)| r.end - r.start).sum()
    }

    #[getter]
    pub fn has_blocks(&self) -> bool {
        !self.0.is_empty()
    }

    /// Checks which segment that the address `addr` should belong to,
    /// and returns the offset of that segment.
    /// Note that the address may not actually belong to the block.
    pub fn search(&self, addr: u64) -> Option<usize> {
        self.0
            .iter()
            .enumerate()
            .find(|(_, (range, _))| range.end >= addr)
            .map(|(index, _)| index)
    }

    pub fn next_free_pos(&self, address: u64) -> Option<u64> {
        self.0
            .gaps(&(address..u64::MAX))
            .map(|gap| gap.start)
            .next()
    }

    /// Returns the next occupied position that is not in the given set of sorts.
    #[pyo3(signature = (address, sorts, max_distance = None))]
    pub fn next_pos_with_sort_not_in(
        &self,
        address: u64,
        sorts: HashSet<Option<String>>,
        max_distance: Option<u64>,
    ) -> Option<u64> {
        // Determine the end of the search range
        let end = address.saturating_add(max_distance.unwrap_or(u64::MAX));
        let search_range = address..end;
        // Find the lowest position among the occupied ranges
        self.0
            .overlapping(search_range.clone())
            .filter(|(_, sort)| !sorts.contains(sort))
            .map(|(range, _)| std::cmp::max(range.start, address))
            .next()
    }

    pub fn is_occupied(&self, address: u64) -> bool {
        self.0.contains_key(&address)
    }

    pub fn occupied_by_sort(&self, address: u64) -> Option<String> {
        self.0.get(&address)?.clone()
    }

    pub fn occupied_by(&self, address: u64) -> Option<(u64, u64, Option<String>)> {
        self.0
            .get_key_value(&address)
            .map(|(range, sort)| (range.start, range.end - range.start, sort.clone()))
    }

    pub fn occupy(&mut self, address: u64, size: u64, sort: Option<String>) {
        if size == 0 {
            return;
        }
        self.0.insert(address..(address + size), sort);
    }

    pub fn update(&mut self, other: &SegmentList) {
        for (r, sort) in other.0.iter() {
            self.occupy(r.start, r.end - r.start, sort.clone());
        }
    }

    pub fn release(&mut self, address: u64, size: u64) {
        self.0.remove(address..(address + size));
    }

    pub fn copy(&self) -> SegmentList {
        self.clone()
    }
}

#[pyclass]
pub struct SegmentListIter {
    segmentlist: Py<SegmentList>,
    idx: u64,
}

#[pymethods]
impl SegmentListIter {
    #[new]
    fn new(segmentlist: Py<SegmentList>) -> Self {
        Self {
            segmentlist,
            idx: 0,
        }
    }

    fn __iter__(self_: Bound<'_, Self>) -> Bound<'_, Self> {
        self_
    }

    fn __next__(&mut self, py: Python<'_>) -> PyResult<Segment> {
        let segmentlist = self.segmentlist.bind(py).borrow();
        match segmentlist.get_segment(self.idx) {
            Some((start, size, sort)) => {
                self.idx += 1;
                Ok(Segment::new(start, size, sort))
            }
            None => Err(PyErr::new::<PyStopIteration, _>("")),
        }
    }
}

#[pymodule]
pub fn segmentlist(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Segment>()?;
    m.add_class::<SegmentList>()?;
    m.add_class::<SegmentListIter>()?;
    Ok(())
}
