use std::{collections::HashSet, ops::Range};

use pyo3::{prelude::*, types::PyTuple};
use rangemap::{RangeMap, RangeSet};

#[pyclass(module = "angr.angrlib.segmentlist")]
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
#[pyclass(module = "angr.angrlib.segmentlist")]
pub struct SegmentList(RangeMap<u64, Option<String>>);

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

    #[getter]
    pub fn occupied_size(&self) -> u64 {
        self.0.len() as u64
    }

    #[getter]
    pub fn has_blocks(&self) -> bool {
        !self.0.is_empty()
    }

    pub fn keys(&self) -> SegmentSet {
        self.0
            .iter()
            .map(|(r, _)| r.clone())
            .collect::<RangeSet<u64>>()
            .into()
    }

    pub fn next_free_pos(&self, address: u64) -> Option<u64> {
        self.0
            .gaps(&(address..u64::MAX))
            .map(|gap| gap.start)
            .next()
    }

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
        let min_occupied = self
            .0
            .overlapping(search_range.clone())
            .filter(|(_, sort)| !sorts.contains(sort))
            .map(|(range, _)| std::cmp::max(range.start, address))
            .next();
        // Find the lowest position in the gap ranges
        let min_gaps = self
            .0
            .gaps(&search_range)
            .map(|range| std::cmp::max(range.start, address))
            .next();
        // Pick the lowest between them
        std::cmp::min(min_occupied, min_gaps)
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

#[derive(Clone, Debug)]
#[pyclass(module = "angr.angrlib.segmentlist")]
pub struct SegmentSetIter {
    // Current range being iterated
    current_range: Option<Range<u64>>,
    // Current position within the range
    current_pos: u64,
    // Iterator over all ranges in the RangeSet
    ranges: Vec<Range<u64>>,
    // Current index in the ranges vector
    range_idx: usize,
}

#[pymethods]
impl SegmentSetIter {
    fn __iter__(self_: PyRef<'_, Self>) -> PyRef<'_, Self> {
        self_
    }

    fn __next__(mut self_: PyRefMut<'_, Self>) -> Option<u64> {
        // Loop until we find a valid value or run out of ranges
        loop {
            // If we have a current range and we're still within it
            if let Some(range) = &self_.current_range {
                if self_.current_pos < range.end {
                    let result = self_.current_pos;
                    self_.current_pos += 1;
                    return Some(result);
                }
                // We've reached the end of the current range, move to the next one
                self_.current_range = None;
            }

            // Try to get the next range
            if self_.range_idx < self_.ranges.len() {
                let next_range = self_.ranges[self_.range_idx].clone();
                self_.range_idx += 1;

                // If the range is empty, skip it and continue the loop
                if next_range.start >= next_range.end {
                    continue;
                }

                self_.current_range = Some(next_range.clone());
                self_.current_pos = next_range.start;

                // Return the first position in the new range
                return Some(self_.current_pos);
            }

            // No more ranges
            return None;
        }
    }
}

#[derive(Clone, Debug, Default)]
#[pyclass(module = "angr.angrlib.segmentlist")]
pub struct SegmentSet(RangeSet<u64>);

#[pymethods]
impl SegmentSet {
    #[new]
    pub fn new() -> Self {
        SegmentSet(RangeSet::new())
    }

    pub fn __getnewargs__(&self, py: Python<'_>) -> Py<PyTuple> {
        PyTuple::empty(py).unbind()
    }

    pub fn __getstate__(&self) -> Vec<(u64, u64)> {
        self.0.iter().map(|r| (r.start, r.end)).collect()
    }

    pub fn __setstate__(&mut self, state: Vec<(u64, u64)>) {
        self.0.clear();
        for (start, end) in state {
            self.0.insert(start..end);
        }
    }

    pub fn __contains__(&self, address: u64) -> bool {
        self.0.contains(&address)
    }

    pub fn __iter__(self_: PyRef<'_, Self>) -> SegmentSetIter {
        let ranges = self_.0.iter().cloned().collect();
        SegmentSetIter {
            current_range: None,
            current_pos: 0,
            ranges,
            range_idx: 0,
        }
    }

    pub fn __or__(&self, other: &SegmentSet) -> SegmentSet {
        let mut new_set = self.clone();
        new_set.union(other);
        new_set
    }

    pub fn __ior__<'py>(
        self_: Bound<'py, SegmentSet>,
        other: Bound<'py, SegmentSet>,
    ) -> PyResult<()> {
        self_.try_borrow_mut()?.union(&*other.try_borrow()?);
        Ok(())
    }

    pub fn __len__(&self) -> usize {
        self.0.iter().map(|r| r.end - r.start).sum::<u64>() as usize
    }

    pub fn add(&mut self, address: u64, size: u64) {
        self.0.insert(address..(address + size));
    }

    pub fn remove(&mut self, address: u64, size: u64) {
        self.0.remove(address..(address + size));
    }

    pub fn union(&mut self, other: &SegmentSet) {
        self.0.union(&other.0);
    }

    pub fn copy(&self) -> SegmentSet {
        self.clone()
    }
}

impl From<RangeSet<u64>> for SegmentSet {
    fn from(range_set: RangeSet<u64>) -> Self {
        SegmentSet(range_set)
    }
}

#[pymodule]
pub fn segmentlist(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Segment>()?;
    m.add_class::<SegmentList>()?;
    m.add_class::<SegmentSet>()?;
    Ok(())
}
