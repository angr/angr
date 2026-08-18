use std::cmp::{max, min};
use std::collections::HashSet;
use std::ops::Range;

use pyo3::{
    exceptions::{PyStopIteration, PyValueError},
    prelude::*,
    types::PyTuple,
};
use rangemap::RangeMap;

#[pyclass(module = "angr.rustylib.segmentlist", from_py_object, get_all)]
#[derive(Clone, Debug)]
pub struct Segment {
    start: u64,
    end: u64,
    sort: Option<String>,
}

#[pymethods]
impl Segment {
    #[new]
    #[pyo3(signature = (start, end, sort=None))]
    pub fn new(start: u64, end: u64, sort: Option<String>) -> PyResult<Self> {
        if end < start {
            return Err(PyValueError::new_err(format!(
                "Segment end {end:#x} precedes start {start:#x}"
            )));
        }
        Ok(Segment { start, end, sort })
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
#[pyclass(module = "angr.rustylib.segmentlist", from_py_object)]
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

    /// The last segment that starts before `before`.
    ///
    /// `rangemap` offers no predecessor query, and its `Overlapping` iterator is unbounded above,
    /// which makes iterating it backwards linear in the number of segments above `before`. Instead,
    /// grow a search window exponentially until it reaches a segment, then bisect it down to the
    /// smallest window that still does: that window can only contain the segment we are after.
    /// Every step is a point query, so this is O(log n * log gap).
    fn prev_segment(&self, before: u64) -> Option<(&Range<u64>, &Option<String>)> {
        if before == 0 {
            return None;
        }
        let mut hi = 1u64;
        while !self.map.overlaps(&(before.saturating_sub(hi)..before)) {
            if before.saturating_sub(hi) == 0 {
                return None;
            }
            hi = hi.saturating_mul(2);
        }
        let mut lo = hi / 2; // does not reach a segment (0 when hi == 1)
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if self.map.overlaps(&(before.saturating_sub(mid)..before)) {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        self.map
            .overlapping(before.saturating_sub(hi)..before)
            .next()
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
            .map(|(r, sort)| Segment {
                start: r.start,
                end: r.end,
                sort: sort.clone(),
            })
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyIndexError, _>(format!("Index {idx} out of range"))
            })
    }

    pub fn __iter__(&self) -> SegmentListIter {
        SegmentListIter::new(self)
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
    ///
    /// This is O(n): an index into the map cannot be computed any faster. Prefer the point-query
    /// methods (`occupied_by`, `occupied_by_sort`, ...) wherever an index is not strictly needed.
    pub fn search(&self, addr: u64) -> Option<usize> {
        self.map
            .iter()
            .enumerate()
            .find(|(_, (range, _))| range.end >= addr)
            .map(|(index, _)| index)
    }

    /// The fraction of bytes belonging to segments of sort `sort`, among the last `window_size`
    /// occupied bytes at or before `addr`.
    ///
    /// The walk starts at the segment `search()` would return for `addr` and moves backwards,
    /// skipping over gaps, until `window_size` bytes have been covered. Returns 0.0 when the
    /// starting segment has a different sort, or when fewer than `window_size` occupied bytes
    /// are available.
    #[pyo3(signature = (addr, window_size, sort))]
    pub fn sort_ratio_backwards(&self, addr: u64, window_size: u64, sort: Option<String>) -> f64 {
        // the first segment whose end is >= addr, i.e. what search(addr) points at
        let Some((mut range, mut seg_sort)) = self
            .map
            .overlapping(addr.saturating_sub(1)..u64::MAX)
            .next()
        else {
            return 0.0;
        };
        if *seg_sort != sort {
            return 0.0;
        }

        let mut total: u64 = 0;
        let mut matching: u64 = 0;
        loop {
            let size = range.end - range.start;
            if *seg_sort == sort {
                matching = matching.saturating_add(size);
            }
            total = total.saturating_add(size);
            if total >= window_size {
                return matching as f64 / total as f64;
            }
            match self.prev_segment(range.start) {
                Some((r, s)) => (range, seg_sort) = (r, s),
                None => return 0.0,
            }
        }
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
    // snapshot taken up front: walking the map by index would be quadratic over a full iteration
    segments: std::vec::IntoIter<Segment>,
}

#[pymethods]
impl SegmentListIter {
    #[new]
    fn new(segmentlist: &SegmentList) -> Self {
        Self {
            segments: segmentlist
                .map
                .iter()
                .map(|(range, sort)| Segment {
                    start: range.start,
                    end: range.end,
                    sort: sort.clone(),
                })
                .collect::<Vec<_>>()
                .into_iter(),
        }
    }

    fn __iter__(self_: Bound<'_, Self>) -> Bound<'_, Self> {
        self_
    }

    fn __next__(&mut self) -> PyResult<Segment> {
        self.segments
            .next()
            .ok_or_else(|| PyErr::new::<PyStopIteration, _>(""))
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

    /// The pre-existing O(n) algorithm: search() for the starting index, then walk backwards
    /// through the map by index. Used to pin sort_ratio_backwards() to the old behavior.
    fn ratio_reference(sl: &SegmentList, addr: u64, window_size: u64, sort: Option<&str>) -> f64 {
        let sort = sort.map(str::to_string);
        let segments: Vec<_> = sl
            .map
            .iter()
            .map(|(r, s)| (r.end - r.start, s.clone()))
            .collect();
        let Some(mut idx) = sl.search(addr) else {
            return 0.0;
        };
        if segments[idx].1 != sort {
            return 0.0;
        }
        let (mut total, mut matching) = (0u64, 0u64);
        loop {
            let (size, seg_sort) = &segments[idx];
            if *seg_sort == sort {
                matching += size;
            }
            total += size;
            if total >= window_size {
                break;
            }
            if idx == 0 {
                return 0.0;
            }
            idx -= 1;
        }
        matching as f64 / total as f64
    }

    /// A deterministic xorshift, so the randomized cases stay reproducible.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self, bound: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % bound
        }
    }

    #[test]
    fn prev_segment_walks_backwards() {
        let mut sl = SegmentList::new();
        sl.occupy(10, 5, Some("a".to_string()));
        sl.occupy(1000, 5, Some("b".to_string()));
        sl.occupy(1005, 5, Some("c".to_string()));

        assert_eq!(sl.prev_segment(0), None);
        assert_eq!(sl.prev_segment(10), None);
        assert_eq!(sl.prev_segment(1005).unwrap().0, &(1000..1005));
        assert_eq!(sl.prev_segment(1000).unwrap().0, &(10..15));
        // an address in the middle of a gap
        assert_eq!(sl.prev_segment(500).unwrap().0, &(10..15));
        // past the end of every segment
        assert_eq!(sl.prev_segment(u64::MAX).unwrap().0, &(1005..1010));
    }

    #[test]
    fn prev_segment_matches_brute_force() {
        let mut rng = Rng(0x2545F4914F6CDD1D);
        for _ in 0..50 {
            let mut sl = SegmentList::new();
            let mut addr = 0;
            for i in 0..40 {
                addr += rng.next(64);
                let size = 1 + rng.next(16);
                sl.occupy(addr, size, Some(format!("s{}", i % 3)));
                addr += size;
            }
            let starts: Vec<u64> = sl.map.iter().map(|(r, _)| r.start).collect();
            for probe in 0..addr + 8 {
                let expected = starts.iter().rev().find(|&&s| s < probe);
                assert_eq!(
                    sl.prev_segment(probe).map(|(r, _)| r.start).as_ref(),
                    expected,
                    "probe {probe:#x}"
                );
            }
        }
    }

    #[test]
    fn sort_ratio_backwards_basics() {
        let mut sl = SegmentList::new();
        sl.occupy(0, 100, Some("code".to_string()));
        sl.occupy(100, 100, Some("nodecode".to_string()));
        sl.occupy(200, 100, Some("code".to_string()));
        sl.occupy(300, 100, Some("nodecode".to_string()));

        // the walk starts inside the last segment and covers the whole map
        assert_eq!(
            sl.sort_ratio_backwards(399, 400, Some("nodecode".into())),
            0.5
        );
        // ... and only the last two segments with a smaller window
        assert_eq!(
            sl.sort_ratio_backwards(399, 200, Some("nodecode".into())),
            0.5
        );
        assert_eq!(
            sl.sort_ratio_backwards(399, 100, Some("nodecode".into())),
            1.0
        );
        // the starting segment has the wrong sort
        assert_eq!(
            sl.sort_ratio_backwards(250, 100, Some("nodecode".into())),
            0.0
        );
        // not enough occupied bytes
        assert_eq!(
            sl.sort_ratio_backwards(399, 500, Some("nodecode".into())),
            0.0
        );
        // beyond every segment
        assert_eq!(
            sl.sort_ratio_backwards(500, 100, Some("nodecode".into())),
            0.0
        );
        // empty list
        assert_eq!(
            SegmentList::new().sort_ratio_backwards(0, 100, Some("nodecode".into())),
            0.0
        );
    }

    #[test]
    fn sort_ratio_backwards_skips_gaps() {
        let mut sl = SegmentList::new();
        sl.occupy(0, 40, Some("nodecode".to_string()));
        sl.occupy(60, 40, Some("code".to_string()));
        // a 900-byte gap, which the walk steps over without counting it
        sl.occupy(1000, 40, Some("nodecode".to_string()));

        assert_eq!(
            sl.sort_ratio_backwards(1039, 40, Some("nodecode".into())),
            1.0
        );
        assert_eq!(
            sl.sort_ratio_backwards(1039, 80, Some("nodecode".into())),
            0.5
        );
        // the gap contributes nothing, so all three segments fit in a 120-byte window
        assert_eq!(
            sl.sort_ratio_backwards(1039, 120, Some("nodecode".into())),
            2.0 / 3.0
        );
        // ... and there is nothing left to cover a larger one
        assert_eq!(
            sl.sort_ratio_backwards(1039, 121, Some("nodecode".into())),
            0.0
        );
    }

    #[test]
    fn sort_ratio_backwards_matches_reference() {
        let mut rng = Rng(0x9E3779B97F4A7C15);
        for _ in 0..50 {
            let mut sl = SegmentList::new();
            let mut addr = 0;
            for _ in 0..60 {
                // gaps and single-byte segments are both common in CFGFast's segment list
                addr += rng.next(4);
                let size = 1 + rng.next(8);
                let sort = if rng.next(2) == 0 { "nodecode" } else { "code" };
                sl.occupy(addr, size, Some(sort.to_string()));
                addr += size;
            }
            for probe in 0..addr + 4 {
                for window in [1u64, 7, 32, 4096] {
                    assert_eq!(
                        sl.sort_ratio_backwards(probe, window, Some("nodecode".into())),
                        ratio_reference(&sl, probe, window, Some("nodecode")),
                        "probe {probe:#x} window {window}"
                    );
                }
            }
        }
    }

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
