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
        // Calculate the sum of sizes of all blocks
        self.0.iter().map(|(r, _)| r.end - r.start).sum()
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

    pub fn search(&self, addr: u64) -> usize {
        // Checks which segment that the address `addr` should belong to,
        // and returns the offset of that segment.
        // Note that the address may not actually belong to the block.

        // Find the first segment whose start is greater than addr
        let mut idx = 0;
        for (r, _) in self.0.iter() {
            if r.start > addr {
                break;
            }
            idx += 1;
        }

        // Check if addr is within the previous segment
        if idx > 0 {
            let prev_idx = idx - 1;
            if let Some((r, _)) = self.0.iter().nth(prev_idx) {
                if r.end > addr {
                    // Address is within the previous segment
                    return prev_idx;
                }
            }
        }

        // If we get here, addr should belong at the current index
        idx
    }

    pub fn next_free_pos(&self, address: u64) -> PyResult<u64> {
        let idx = self.search(address);

        // Check if the address is within a segment
        if let Some((r, _)) = self.0.iter().nth(idx) {
            if r.start <= address && address < r.end {
                // Address is occupied, find the end of consecutive segments
                let mut i = idx;
                let mut current_end = r.end;

                while i + 1 < self.0.len() {
                    if let Some((next_r, _)) = self.0.iter().nth(i + 1) {
                        if current_end == next_r.start {
                            // Segments are consecutive
                            current_end = next_r.end;
                            i += 1;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                return Ok(current_end);
            }
        }

        // Address is not occupied, return the address itself
        Ok(address)
    }

    #[pyo3(signature = (address, sorts, max_distance = None))]
    pub fn next_pos_with_sort_not_in(
        &self,
        address: u64,
        sorts: HashSet<Option<String>>,
        max_distance: Option<u64>,
    ) -> Option<u64> {
        let list_length = self.0.len();

        let idx = self.search(address);
        if idx < list_length {
            // Get the segment at idx
            if let Some((r, sort)) = self.0.iter().nth(idx) {
                // Check max_distance for the first segment
                if let Some(md) = max_distance {
                    if address + md < r.start {
                        return None;
                    }
                }

                // Check if address is within the current segment
                if r.start <= address && address < r.end {
                    // Address is inside the current segment
                    if !sorts.contains(sort) {
                        return Some(address);
                    }
                    // Move to the next segment
                    let mut next_idx = idx + 1;

                    // Iterate through subsequent segments
                    while next_idx < list_length {
                        if let Some((next_r, next_sort)) = self.0.iter().nth(next_idx) {
                            // Check max_distance
                            if let Some(md) = max_distance {
                                if address + md < next_r.start {
                                    return None;
                                }
                            }

                            if !sorts.contains(next_sort) {
                                return Some(next_r.start);
                            }

                            next_idx += 1;
                        } else {
                            break;
                        }
                    }
                } else {
                    // Address is not inside the current segment
                    // Start checking from the current segment
                    let mut current_idx = idx;

                    while current_idx < list_length {
                        if let Some((current_r, current_sort)) = self.0.iter().nth(current_idx) {
                            // Check max_distance
                            if let Some(md) = max_distance {
                                if address + md < current_r.start {
                                    return None;
                                }
                            }

                            if !sorts.contains(current_sort) {
                                return Some(current_r.start);
                            }

                            current_idx += 1;
                        } else {
                            break;
                        }
                    }
                }
            }
        }

        None
    }

    pub fn is_occupied(&self, address: u64) -> bool {
        let idx = self.search(address);
        if let Some((r, _)) = self.0.iter().nth(idx) {
            if r.start <= address && address < r.end {
                return true;
            }
        }
        false
    }

    pub fn occupied_by_sort(&self, address: u64) -> Option<String> {
        let idx = self.search(address);
        if let Some((r, sort)) = self.0.iter().nth(idx) {
            if r.start <= address && address < r.end {
                return sort.clone();
            }
        }
        None
    }

    pub fn occupied_by(&self, address: u64) -> Option<(u64, u64, Option<String>)> {
        let idx = self.search(address);
        if let Some((r, sort)) = self.0.iter().nth(idx) {
            if r.start <= address && address < r.end {
                return Some((r.start, r.end - r.start, sort.clone()));
            }
        }
        None
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
