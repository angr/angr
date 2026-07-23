#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import importlib.util
import json
import os.path
import shutil
import tempfile
import unittest

import angr
from angr.errors import AngrValueError
from tests.common import bin_location

# glibc strings verified to be recovered as String memory data by CFGFast on
# elf_with_static_libc_ubuntu_2004_stripped
LIBC_STRINGS = [
    "malloc(): invalid size (unsorted)",
    "free(): invalid pointer",
    "double free or corruption (out)",
    "corrupted double-linked list",
    "invalid fastbin entry (free)",
]

DECOY_STRINGS = [
    "deadbeef cafe 0x1337 zz sentinel qq",
    "0xfeedface nonsense marker string xx",
    "qzjxvkwp absent gibberish 0xabad1dea",
]


@unittest.skipUnless(importlib.util.find_spec("sigserv") is not None, "sigserv is not installed")
class TestSuggestSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.TemporaryDirectory()  # pylint:disable=consider-using-with
        cls.sigs_dir = os.path.join(cls.tmpdir.name, "sigs")
        os.makedirs(cls.sigs_dir)

        # the real library
        shutil.copy(
            os.path.join(bin_location, "tests", "x86_64", "libc_ubuntu_2004.sig"),
            os.path.join(cls.sigs_dir, "libc_ubuntu_2004.sig"),
        )
        meta = {
            "unique_strings": LIBC_STRINGS,
            "arch": "amd64",
            "platform": "linux",
            "os": "ubuntu",
            "os_version": "20.04",
            "compiler": "gcc",
            "compiler_version": "",
        }
        with open(os.path.join(cls.sigs_dir, "libc_ubuntu_2004.meta"), "w", encoding="utf-8") as f:
            json.dump(meta, f)

        # a decoy library whose unique strings do not occur in the binary
        shutil.copy(
            os.path.join(bin_location, "tests", "armhf", "debian_10.3_libc.sig"),
            os.path.join(cls.sigs_dir, "decoy_lib.sig"),
        )
        decoy_meta = dict(meta)
        decoy_meta["unique_strings"] = DECOY_STRINGS
        with open(os.path.join(cls.sigs_dir, "decoy_lib.meta"), "w", encoding="utf-8") as f:
            json.dump(decoy_meta, f)

        binary_path = os.path.join(bin_location, "tests", "x86_64", "elf_with_static_libc_ubuntu_2004_stripped")
        cls.proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)
        cls.proj.analyses.CFGFast(show_progressbar=False)

    @classmethod
    def tearDownClass(cls):
        cls.tmpdir.cleanup()

    def test_dir_mode_suggest_and_apply(self):
        proj = self.proj
        analysis = proj.analyses.SuggestSignature(signatures_dir=self.sigs_dir, apply=False)

        assert analysis.suggestions
        assert analysis.accepted
        top = analysis.accepted[0]
        assert top["library_name"] == "libc_ubuntu_2004"
        assert len(top["matched_strings"]) >= 2
        assert all(s["library_name"] != "decoy_lib" for s in analysis.accepted)
        assert not analysis.applied
        assert proj.kb.functions[0x415CC0].is_default_name is True

        analysis = proj.analyses.SuggestSignature(signatures_dir=self.sigs_dir, apply=True)
        assert analysis.applied
        assert all(v > 0 for v in analysis.applied.values())
        assert proj.kb.functions[0x415CC0].name == "_IO_file_open"
        assert proj.kb.functions[0x415CC0].is_default_name is False
        assert proj.kb.functions[0x415CC0].from_signature == "flirt"

    def test_db_mode(self):
        import sigserv  # pylint:disable=import-outside-toplevel

        db_path = os.path.join(self.tmpdir.name, "sigs.db")
        server = sigserv.SigServer(db_url=f"sqlite://{db_path}")
        counts = server.import_dir(self.sigs_dir)
        assert counts["libraries"] == 2

        analysis = self.proj.analyses.SuggestSignature(db_url=f"sqlite://{db_path}", apply=False)
        assert analysis.suggestions
        assert analysis.accepted
        top = analysis.accepted[0]
        assert top["library_name"] == "libc_ubuntu_2004"
        assert len(top["matched_strings"]) >= 2
        assert all(s["library_name"] != "decoy_lib" for s in analysis.accepted)

    def test_input_collection(self):
        analysis = self.proj.analyses.SuggestSignature(signatures_dir=self.sigs_dir, apply=False)

        assert analysis.query_strings
        assert len(analysis.query_strings) == len(set(analysis.query_strings))
        assert all(6 <= len(s) <= 70 for s in analysis.query_strings)
        for s in LIBC_STRINGS:
            assert s in analysis.query_strings
        assert all(v >= 0x10000 for v in analysis.query_integers)

    def test_bad_arguments(self):
        with self.assertRaises(AngrValueError):
            self.proj.analyses.SuggestSignature()
        with self.assertRaises(AngrValueError):
            self.proj.analyses.SuggestSignature(
                signatures_dir=self.sigs_dir, db_url=f"sqlite://{os.path.join(self.tmpdir.name, 'x.db')}"
            )


if __name__ == "__main__":
    unittest.main()
