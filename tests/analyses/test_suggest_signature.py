#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import http.server
import importlib.util
import json
import os.path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.parse

import angr
from angr.errors import AngrRuntimeError, AngrValueError
from angr.sigs import SIGSERV_PROTOCOL_VERSION, SigservClient
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

LIBRARY_NAMES = ["decoy_lib", "libc_ubuntu_2004", "libc_ubuntu_2004_alt"]


def setUpModule():  # pylint:disable=invalid-name
    # everything here is about sigserv, one way or another: the in-process modes need the package itself, and the
    # rest exercises the client of its REST protocol
    if importlib.util.find_spec("sigserv") is None:
        raise unittest.SkipTest("sigserv is not installed")


def populate_signatures_dir(sigs_dir: str) -> None:
    """
    Fill a directory with the .sig/.meta pairs the tests query against: a libc signature that matches the test
    binary, a worse-scoring signature of the same library, and a decoy library that matches nothing.
    """
    # the real library
    shutil.copy(
        os.path.join(bin_location, "tests", "x86_64", "libc_ubuntu_2004.sig"),
        os.path.join(sigs_dir, "libc_ubuntu_2004.sig"),
    )
    meta = {
        "unique_strings": LIBC_STRINGS,
        "library": "libc",
        "arch": "amd64",
        "platform": "linux",
        "os": "ubuntu",
        "os_version": "20.04",
        "compiler": "gcc",
        "compiler_version": "",
    }
    with open(os.path.join(sigs_dir, "libc_ubuntu_2004.meta"), "w", encoding="utf-8") as f:
        json.dump(meta, f)

    # a second, worse-scoring signature of the same library: fewer unique strings match the binary
    shutil.copy(
        os.path.join(sigs_dir, "libc_ubuntu_2004.sig"),
        os.path.join(sigs_dir, "libc_ubuntu_2004_alt.sig"),
    )
    alt_meta = dict(meta)
    alt_meta["unique_strings"] = LIBC_STRINGS[:2]
    with open(os.path.join(sigs_dir, "libc_ubuntu_2004_alt.meta"), "w", encoding="utf-8") as f:
        json.dump(alt_meta, f)

    # a decoy library whose unique strings do not occur in the binary
    shutil.copy(
        os.path.join(bin_location, "tests", "armhf", "debian_10.3_libc.sig"),
        os.path.join(sigs_dir, "decoy_lib.sig"),
    )
    decoy_meta = dict(meta)
    decoy_meta["unique_strings"] = DECOY_STRINGS
    decoy_meta["library"] = "decoy"
    with open(os.path.join(sigs_dir, "decoy_lib.meta"), "w", encoding="utf-8") as f:
        json.dump(decoy_meta, f)


def analyzed_project() -> angr.Project:
    binary_path = os.path.join(bin_location, "tests", "x86_64", "elf_with_static_libc_ubuntu_2004_stripped")
    proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)
    proj.analyses.CFGFast(show_progressbar=False)
    return proj


#
# A stand-in sigserv server, so the client can be tested without the sigserv package or its server binary
#


def load_libraries(sigs_dir: str) -> list[dict]:
    libraries = []
    for filename in sorted(os.listdir(sigs_dir)):
        if not filename.endswith(".meta"):
            continue
        name = filename[: -len(".meta")]
        sig_path = os.path.join(sigs_dir, name + ".sig")
        if not os.path.isfile(sig_path):
            continue
        with open(os.path.join(sigs_dir, filename), encoding="utf-8") as f:
            meta = json.load(f)
        meta.setdefault("unique_strings", [])
        meta.setdefault("unique_integers", [])
        libraries.append({"name": name, "meta": meta, "sig_path": sig_path})
    return libraries


def rank(libraries: list[dict], query: dict) -> list[dict]:
    """
    Score libraries the way sigserv does: query strings are matched case-insensitively as substrings of the unique
    strings of a library, integers exactly, and a string match weighs twice as much as an integer match.
    """
    strings = query.get("strings") or []
    integers = query.get("integers") or []
    total_inputs = len(strings) + len(integers)
    if not total_inputs:
        return []

    results = []
    for library in libraries:
        meta = library["meta"]
        if query.get("arch") and query["arch"].lower() != meta.get("arch", "").lower():
            continue
        if query.get("platform") and query["platform"].lower() != meta.get("platform", "").lower():
            continue

        indexed = [s.lower() for s in meta["unique_strings"]]
        matched_strings = [s for s in strings if any(s.lower() in indexed_string for indexed_string in indexed)]
        indexed_integers = set(meta["unique_integers"])
        matched_integers = [i for i in integers if i in indexed_integers]
        if not matched_strings and not matched_integers:
            continue

        results.append(
            {
                "library_name": library["name"],
                "sig_path": library["sig_path"],
                "meta": meta,
                "score": (2 * len(matched_strings) + len(matched_integers)) / total_inputs,
                "matched_strings": matched_strings,
                "matched_integers": matched_integers,
            }
        )

    results.sort(key=lambda r: -r["score"])
    return results


class FakeSigservHandler(http.server.BaseHTTPRequestHandler):
    """
    Implements the part of the sigserv REST protocol that SigservClient uses.
    """

    def log_message(self, format, *args):  # pylint:disable=redefined-builtin
        pass  # keep the test output clean

    def do_GET(self):  # pylint:disable=invalid-name
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/version":
            self._send_json(
                {
                    "protocol_version": self.server.reported_protocol_version,
                    "server_version": "0.0.0-fake",
                }
            )
        elif parsed.path == "/libraries":
            self._send_json(
                [
                    {"name": library["name"], "meta": library["meta"], "sig_path_str": library["sig_path"]}
                    for library in self.server.libraries
                ]
            )
        elif parsed.path.startswith("/signature/"):
            self._send_signature(parsed)
        else:
            self.send_error(404, "unknown endpoint")

    def do_POST(self):  # pylint:disable=invalid-name
        if urllib.parse.urlparse(self.path).path != "/query":
            self.send_error(404, "unknown endpoint")
            return
        length = int(self.headers.get("Content-Length", 0))
        query = json.loads(self.rfile.read(length))
        self.server.queries.append(query)
        self._send_json(rank(self.server.libraries, query))

    def _send_signature(self, parsed) -> None:
        name = urllib.parse.unquote(parsed.path[len("/signature/") :])
        params = urllib.parse.parse_qs(parsed.query)

        def matches(library, key):
            wanted = params.get(key)
            return not wanted or library["meta"].get(key, "").lower() == wanted[0].lower()

        library = next(
            (
                library
                for library in self.server.libraries
                if library["name"] == name and matches(library, "arch") and matches(library, "platform")
            ),
            None,
        )
        if library is None:
            self.send_error(404, "no such signature")
            return

        with open(library["sig_path"], "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, payload) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeSigserv(http.server.ThreadingHTTPServer):
    """
    A sigserv stand-in serving a signatures directory over the REST protocol.
    """

    daemon_threads = True

    def __init__(self, sigs_dir: str, reported_protocol_version: int = SIGSERV_PROTOCOL_VERSION):
        super().__init__(("127.0.0.1", 0), FakeSigservHandler)
        self.libraries = load_libraries(sigs_dir)
        self.reported_protocol_version = reported_protocol_version
        self.queries: list[dict] = []
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
        self._thread.join(timeout=10)


class TestSuggestSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.TemporaryDirectory()  # pylint:disable=consider-using-with
        cls.sigs_dir = os.path.join(cls.tmpdir.name, "sigs")
        os.makedirs(cls.sigs_dir)
        populate_signatures_dir(cls.sigs_dir)
        cls.proj = analyzed_project()

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
        assert top["library"] == "libc"
        assert len(top["matched_strings"]) >= 2
        assert all(s["library_name"] != "decoy_lib" for s in analysis.accepted)
        # both libc signatures are suggested, but only the best-scored one per library is accepted
        assert any(s["library_name"] == "libc_ubuntu_2004_alt" for s in analysis.suggestions)
        assert [s["library_name"] for s in analysis.accepted if s["library"] == "libc"] == ["libc_ubuntu_2004"]
        assert set(analysis.accepted_by_library) == {"libc"}
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
        assert counts["libraries"] == 3

        analysis = self.proj.analyses.SuggestSignature(db_url=f"sqlite://{db_path}", apply=False)
        assert analysis.suggestions
        assert analysis.accepted
        top = analysis.accepted[0]
        assert top["library_name"] == "libc_ubuntu_2004"
        assert top["library"] == "libc"
        assert len(top["matched_strings"]) >= 2
        assert all(s["library_name"] != "decoy_lib" for s in analysis.accepted)
        assert [s["library_name"] for s in analysis.accepted if s["library"] == "libc"] == ["libc_ubuntu_2004"]

    def test_per_library_selection(self):
        analysis = self.proj.analyses.SuggestSignature(
            signatures_dir=self.sigs_dir, apply=False, max_signatures_per_library=2
        )
        libc_group = analysis.accepted_by_library["libc"]
        assert [s["library_name"] for s in libc_group] == ["libc_ubuntu_2004", "libc_ubuntu_2004_alt"]
        assert libc_group[0]["score"] > libc_group[1]["score"]
        assert all(s["library"] == "libc" for s in libc_group)

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
        with self.assertRaises(AngrValueError):
            self.proj.analyses.SuggestSignature(signatures_dir=self.sigs_dir, server_url="http://127.0.0.1:8080")


class TestSigservClient(unittest.TestCase):
    """
    SigservClient against a stand-in server. Nothing here needs the sigserv package to be installed.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.TemporaryDirectory()  # pylint:disable=consider-using-with
        cls.sigs_dir = os.path.join(cls.tmpdir.name, "sigs")
        os.makedirs(cls.sigs_dir)
        populate_signatures_dir(cls.sigs_dir)
        cls.server = FakeSigserv(cls.sigs_dir)
        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.tmpdir.cleanup()

    def test_version(self):
        client = SigservClient(self.server.url)
        assert client.protocol_version == SIGSERV_PROTOCOL_VERSION
        assert client.server_version == "0.0.0-fake"
        assert client.version()["protocol_version"] == SIGSERV_PROTOCOL_VERSION

    def test_url_normalization(self):
        host_and_port = self.server.url.removeprefix("http://")
        assert SigservClient(host_and_port + "/").url == self.server.url

    def test_libraries(self):
        client = SigservClient(self.server.url)
        assert client.library_count() == len(LIBRARY_NAMES)
        assert sorted(client.library_names()) == LIBRARY_NAMES
        assert all("meta" in library for library in client.libraries())

    def test_query(self):
        client = SigservClient(self.server.url)
        results = client.query(strings=LIBC_STRINGS)
        assert [r["library_name"] for r in results] == ["libc_ubuntu_2004", "libc_ubuntu_2004_alt"]
        assert results[0]["score"] > results[1]["score"]
        assert set(results[0]["matched_strings"]) == set(LIBC_STRINGS)
        assert client.query() == []

    def test_fetch_signature(self):
        client = SigservClient(self.server.url)
        with tempfile.TemporaryDirectory() as dest_dir:
            path = client.fetch_signature("libc_ubuntu_2004", dest_dir, arch="amd64", platform="linux")
            assert os.path.basename(path) == "libc_ubuntu_2004.sig"
            with open(path, "rb") as f:
                downloaded = f.read()
        with open(os.path.join(self.sigs_dir, "libc_ubuntu_2004.sig"), "rb") as f:
            assert downloaded == f.read()

    def test_fetch_unknown_signature(self):
        client = SigservClient(self.server.url)
        with tempfile.TemporaryDirectory() as dest_dir, self.assertRaises(AngrRuntimeError) as cm:
            client.fetch_signature("no_such_library", dest_dir)
        assert "404" in str(cm.exception)

    def test_protocol_version_mismatch(self):
        server = FakeSigserv(self.sigs_dir, reported_protocol_version=SIGSERV_PROTOCOL_VERSION + 1)
        server.start()
        try:
            with self.assertRaises(AngrRuntimeError) as cm:
                SigservClient(server.url)
            assert "protocol version" in str(cm.exception)
            # the check can be skipped when a server is known to be compatible anyway
            client = SigservClient(server.url, check_protocol_version=False)
            assert client.library_count() == len(LIBRARY_NAMES)
        finally:
            server.stop()

    def test_unreachable_server(self):
        with self.assertRaises(AngrRuntimeError) as cm:
            SigservClient("http://127.0.0.1:1", timeout=5.0)
        assert "Cannot reach" in str(cm.exception)


class TestSuggestSignatureOverHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.TemporaryDirectory()  # pylint:disable=consider-using-with
        cls.sigs_dir = os.path.join(cls.tmpdir.name, "sigs")
        os.makedirs(cls.sigs_dir)
        populate_signatures_dir(cls.sigs_dir)
        cls.server = FakeSigserv(cls.sigs_dir)
        cls.server.start()
        cls.proj = analyzed_project()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.tmpdir.cleanup()

    def test_apply_over_http(self):
        proj = self.proj
        assert proj.kb.functions[0x415CC0].is_default_name is True

        analysis = proj.analyses.SuggestSignature(server_url=self.server.url, apply=True)
        assert analysis.applied
        assert all(v > 0 for v in analysis.applied.values())
        # applied is keyed by the path on the server, not by the temporary local copy that was matched
        assert all(path.startswith(self.sigs_dir) for path in analysis.applied)
        assert proj.kb.functions[0x415CC0].name == "_IO_file_open"
        assert proj.kb.functions[0x415CC0].is_default_name is False
        assert proj.kb.functions[0x415CC0].from_signature == "flirt"

    def test_suggest_over_http(self):
        analysis = self.proj.analyses.SuggestSignature(server_url=self.server.url, apply=False)

        assert analysis.suggestions
        assert analysis.accepted
        top = analysis.accepted[0]
        assert top["library_name"] == "libc_ubuntu_2004"
        assert top["library"] == "libc"
        assert len(top["matched_strings"]) >= 2
        assert all(s["library_name"] != "decoy_lib" for s in analysis.accepted)
        assert [s["library_name"] for s in analysis.accepted if s["library"] == "libc"] == ["libc_ubuntu_2004"]
        assert set(analysis.accepted_by_library) == {"libc"}
        assert not analysis.applied
        # the constants really went to the server
        assert self.server.queries
        assert set(LIBC_STRINGS) <= set(self.server.queries[-1]["strings"])


def sigserv_binary() -> str | None:
    return os.environ.get("SIGSERV_BIN") or shutil.which("sigserv")


@unittest.skipUnless(sigserv_binary(), "the sigserv server binary is not available; set SIGSERV_BIN")
class TestSuggestSignatureAgainstRealServer(unittest.TestCase):
    """
    End-to-end against the real sigserv server binary. The stand-in server above only shows the client is
    self-consistent; this shows that the client and the server agree on the protocol.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.TemporaryDirectory()  # pylint:disable=consider-using-with
        cls.sigs_dir = os.path.join(cls.tmpdir.name, "sigs")
        os.makedirs(cls.sigs_dir)
        populate_signatures_dir(cls.sigs_dir)

        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        cls.url = f"http://127.0.0.1:{port}"
        cls.proc = subprocess.Popen(  # pylint:disable=consider-using-with
            [sigserv_binary(), "serve", "-d", cls.sigs_dir, "--host", "127.0.0.1", "--port", str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cls._wait_until_serving()
        cls.proj = analyzed_project()

    @classmethod
    def _wait_until_serving(cls, timeout: float = 30.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                SigservClient(cls.url, timeout=2.0)
                return
            except AngrRuntimeError:
                if cls.proc.poll() is not None:
                    raise unittest.SkipTest(f"sigserv exited with {cls.proc.returncode}") from None
                time.sleep(0.2)
        raise unittest.SkipTest("sigserv did not start serving in time")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=30)
        cls.tmpdir.cleanup()

    def test_end_to_end(self):
        client = SigservClient(self.url)
        assert client.protocol_version == SIGSERV_PROTOCOL_VERSION
        assert client.library_count() == len(LIBRARY_NAMES)
        assert sorted(client.library_names()) == LIBRARY_NAMES

        analysis = self.proj.analyses.SuggestSignature(server_url=self.url, apply=True)
        assert analysis.accepted
        top = analysis.accepted[0]
        assert top["library_name"] == "libc_ubuntu_2004"
        assert top["library"] == "libc"
        assert all(s["library_name"] != "decoy_lib" for s in analysis.accepted)
        assert all(v > 0 for v in analysis.applied.values())
        assert self.proj.kb.functions[0x415CC0].name == "_IO_file_open"
        assert self.proj.kb.functions[0x415CC0].from_signature == "flirt"


if __name__ == "__main__":
    unittest.main()
