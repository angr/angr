#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import cle

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def load_coredump():
    """The core records mappings for binaries that are not at those paths here, so point it at ours."""
    directory = os.path.join(test_location, "x86_64")
    core = os.path.join(directory, "coredump", "true-libc.so.6-ld-linux-x86-64.so.2.core")
    return angr.Project(
        core,
        main_opts={
            "backend": "elfcore",
            "remote_file_mapper": lambda path: path.replace("/tmp/foobar/does-not-exist", directory),
        },
        auto_load_libs=True,
    )


class TestCfgCoredump(unittest.TestCase):
    def test_core_mappings_are_not_all_code(self):
        # A core dump records what every mapping was allowed to do. The mappings CLE cannot match to a child
        # object become blobs, and before those carried their permissions the whole dump - heap, stack and
        # guard pages included - reached CFGFast as executable memory.
        project = load_coredump()
        core = project.loader.elfcore_object
        assert core is not None

        executable = [
            (segment.vaddr, segment.vaddr + segment.memsize) for segment in core.segments if segment.is_executable
        ]
        assert executable

        blobs = [obj for obj in project.loader.all_objects if isinstance(obj, cle.Blob)]
        assert blobs, "the core's leftover mappings should have become blobs"

        # the last blob that covers a mapping the process could not execute
        target = None
        for blob in blobs:
            mapping = core.segments.find_region_containing(blob.min_addr)
            if mapping is not None and not mapping.is_executable:
                target = blob
        assert target is not None

        # Scanning it from end to end recovers nothing, because the process could not have executed it.
        cfg = project.analyses.CFGFast(
            regions=[(target.min_addr, target.max_addr + 1)],
            force_complete_scan=True,
            normalize=True,
        )
        recovered = [node for node in cfg.model.nodes() if node.size]
        assert not recovered, f"{len(recovered)} blocks decoded out of a mapping the core recorded as data"

        # The map CFGFast derives for itself covers the executable mappings and nothing else.
        for start, end in cfg._exec_mem_regions:
            assert any(low <= start and end <= high for low, high in executable), (
                f"{start:#x}-{end:#x} is not inside any executable mapping of the core"
            )


if __name__ == "__main__":
    unittest.main()
