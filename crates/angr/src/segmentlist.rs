use std::cmp::{max, min};
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
pub struct SegmentList {
    map: RangeMap<u64, Option<String>>,
    bytes_occupied: u64,
}

impl SegmentList {
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get_segment(&self, address: u64) -> Option<(u64, u64, Option<String>)> {
        self.map
            .get_key_value(&address)
            .map(|(range, sort)| (range.start, range.end - range.start, sort.clone()))
    }
}

#[pymethods]
impl SegmentList {
    #[new]
    pub fn new() -> Self {
        SegmentList {
            map: RangeMap::new(),
            bytes_occupied: 0,
        }
    }

    pub fn __getnewargs__(&self, py: Python<'_>) -> Py<PyTuple> {
        PyTuple::empty(py).unbind()
    }

    pub fn __getstate__(&self) -> Vec<(u64, u64, Option<String>)> {
        self.map
            .iter()
            .map(|(r, sort)| (r.start, r.end - r.start, sort.clone()))
            .collect()
    }

    pub fn __setstate__(&mut self, state: Vec<(u64, u64, Option<String>)>) {
        self.map.clear();
        for (start, size, sort) in state {
            self.occupy(start, size, sort);
        }
    }

    pub fn __len__(&self) -> usize {
        self.map.len()
    }

    pub fn __getitem__(&self, idx: usize) -> PyResult<Segment> {
        self.map
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
        self.bytes_occupied
    }

    #[getter]
    pub fn has_blocks(&self) -> bool {
        !self.map.is_empty()
    }

    /// Checks which segment that the address `addr` should belong to,
    /// and returns the offset of that segment.
    /// Note that the address may not actually belong to the block.
    pub fn search(&self, addr: u64) -> Option<usize> {
        self.map
            .iter()
            .enumerate()
            .find(|(_, (range, _))| range.end >= addr)
            .map(|(index, _)| index)
    }

    pub fn next_free_pos(&self, address: u64) -> Option<u64> {
        self.map
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
        self.map
            .overlapping(search_range.clone())
            .filter(|(_, sort)| !sorts.contains(sort))
            .map(|(range, _)| std::cmp::max(range.start, address))
            .next()
    }

    pub fn is_occupied(&self, address: u64) -> bool {
        self.map.contains_key(&address)
    }

    pub fn occupied_by_sort(&self, address: u64) -> Option<String> {
        self.map.get(&address)?.clone()
    }

    pub fn occupied_by(&self, address: u64) -> Option<(u64, u64, Option<String>)> {
        self.map
            .get_key_value(&address)
            .map(|(range, sort)| (range.start, range.end - range.start, sort.clone()))
    }

    pub fn occupy(&mut self, address: u64, size: u64, sort: Option<String>) {
        if size == 0 {
            return;
        }
        // ensure address + size does not overflow
        if address.checked_add(size).is_none() {
            return;
        }
        let new_range = address..address + size;
        let overlapped: u64 = self
            .map
            .overlapping(new_range.clone())
            .map(|(r, _)| {
                let s = max(r.start, new_range.start);
                let e = min(r.end, new_range.end);
                e.saturating_sub(s)
            })
            .sum();
        let added = size.saturating_sub(overlapped);
        self.map.insert(new_range, sort);
        self.bytes_occupied = self.bytes_occupied.saturating_add(added);
    }

    pub fn update(&mut self, other: &SegmentList) {
        for (r, sort) in other.map.iter() {
            let size = r.end - r.start;
            self.occupy(r.start, size, sort.clone());
        }
    }

    pub fn release(&mut self, address: u64, size: u64) {
        if size == 0 {
            return;
        }
        let rem = address..address + size;
        let removed: u64 = self
            .map
            .overlapping(rem.clone())
            .map(|(r, _)| {
                let s = max(r.start, rem.start);
                let e = min(r.end, rem.end);
                e.saturating_sub(s)
            })
            .sum();
        self.map.remove(rem);
        self.bytes_occupied = self.bytes_occupied.saturating_sub(removed);
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
        let segmentlist_ref = self.segmentlist.bind(py).borrow();
        // Iterate by index: get the (range, sort) pair at position idx
        // FIXME: This is linear time, should be no more than O(log n)
        if let Some((range, sort)) = segmentlist_ref.map.iter().nth(self.idx as usize) {
            self.idx += 1;
            Ok(Segment::new(range.start, range.end, sort.clone()))
        } else {
            Err(PyErr::new::<PyStopIteration, _>(""))
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

#[cfg(test)]
mod tests {
    use super::SegmentList;

    #[test]
    fn empty_list() {
        let mut sl = SegmentList::new();
        assert_eq!(sl.occupied_size(), 0);
        sl.release(0, 10);
        assert_eq!(sl.occupied_size(), 0);
    }

    #[test]
    fn single_range() {
        let mut sl = SegmentList::new();
        sl.occupy(10, 5, None);
        assert_eq!(sl.occupied_size(), 5);
        assert!(sl.is_occupied(10));
        assert!(!sl.is_occupied(9));
    }

    #[test]
    fn multi_non_overlapping() {
        let mut sl = SegmentList::new();
        sl.occupy(0, 10, None);
        sl.occupy(20, 5, Some("X".to_string()));
        assert_eq!(sl.occupied_size(), 15);
        sl.release(100, 5);
        assert_eq!(sl.occupied_size(), 15);
    }

    #[test]
    fn overlapping_inserts() {
        let mut sl = SegmentList::new();
        sl.occupy(0, 10, None);
        sl.occupy(5, 10, None);
        assert_eq!(sl.occupied_size(), 15);
    }

    #[test]
    fn full_and_partial_release() {
        let mut sl = SegmentList::new();
        sl.occupy(0, 10, None);
        // partial release [3..8)
        sl.release(3, 5);
        assert_eq!(sl.occupied_size(), 5);
        assert!(sl.is_occupied(2));
        assert!(!sl.is_occupied(4));
        assert!(sl.is_occupied(8));
        // full release
        sl.release(0, 10);
        assert_eq!(sl.occupied_size(), 0);
        assert!(sl.is_empty());
    }
}
