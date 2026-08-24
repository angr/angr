#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest

from angr.analyses.forward_analysis import ForwardAnalysis


class _Job:
    """A minimal job: identity is its key, so JobInfo equality is exercised for real."""

    def __init__(self, key, tag=""):
        self.key = key
        self.tag = tag

    def __eq__(self, other):
        return type(other) is _Job and self.key == other.key and self.tag == other.tag

    def __hash__(self):
        return hash((self.key, self.tag))


class _Queue(ForwardAnalysis):
    """ForwardAnalysis reduced to its job queue, which is all _remove_job touches."""

    def __init__(self):
        super().__init__(order_jobs=False, allow_merging=False, allow_widening=False)

    def _job_key(self, job):
        return job.key


class TestForwardAnalysisJobQueue(unittest.TestCase):
    def _queue(self, jobs):
        q = _Queue()
        for job in jobs:
            q._insert_job(job)
        return q

    def test_remove_job_removes_exactly_the_matching_jobs(self):
        jobs = [_Job(i) for i in range(10)]
        q = self._queue(jobs)

        q._remove_job(lambda j: j.key % 3 == 0)

        assert [j.key for j in q.jobs] == [1, 2, 4, 5, 7, 8]
        assert sorted(q._job_map) == [1, 2, 4, 5, 7, 8]

    def test_remove_job_preserves_queue_order(self):
        q = self._queue([_Job(k) for k in (7, 3, 9, 1, 5)])

        q._remove_job(lambda j: j.key == 9)

        assert [j.key for j in q.jobs] == [7, 3, 1, 5]

    def test_remove_job_matching_nothing_leaves_the_queue_alone(self):
        q = self._queue([_Job(i) for i in range(5)])

        q._remove_job(lambda j: j.key > 100)

        assert [j.key for j in q.jobs] == [0, 1, 2, 3, 4]
        assert sorted(q._job_map) == [0, 1, 2, 3, 4]

    def test_remove_job_removes_every_equal_job(self):
        # Jobs that compare equal but are distinct objects must all go: deleting them one at a time by value used
        # to rely on list.remove() finding "a" match rather than the one selected.
        q = _Queue()
        for job in (_Job(1, "a"), _Job(2, "b"), _Job(3, "a"), _Job(4, "b")):
            q._insert_job(job)

        q._remove_job(lambda j: j.tag == "a")

        assert [j.key for j in q.jobs] == [2, 4]
        assert sorted(q._job_map) == [2, 4]

    def test_remove_job_can_empty_the_queue(self):
        q = self._queue([_Job(i) for i in range(4)])

        q._remove_job(lambda j: True)

        assert not list(q.jobs)
        assert not q._job_map


if __name__ == "__main__":
    unittest.main()
