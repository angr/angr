# pylint:disable=redefined-outer-name,no-self-use,missing-class-docstring
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

import angr
from angr.mcp.errors import InvalidArgumentError
from angr.mcp.server import close_project, get_basic_blocks, get_cfg, list_functions, load_binary
from angr.mcp.session import get_session_manager, reject_dos_executable

from .conftest import BIN_LOCATION

FAUXWARE = os.path.join(BIN_LOCATION, "tests", "x86_64", "fauxware")
UNIVERSAL = os.path.join(BIN_LOCATION, "tests", "multi_arch", "fauxware_macho_multiarch")
DOS_EXE = os.path.join(BIN_LOCATION, "tests", "i386", "dos", "hello.exe")
WINDOWS_PE = os.path.join(BIN_LOCATION, "tests", "i386", "simple_windows.exe")


def _require(path: str) -> str:
    if not os.path.exists(path):
        pytest.skip(f"Test binary not found: {path}")
    return path


@pytest.fixture(autouse=True)
def _close_sessions():
    yield
    manager = get_session_manager()
    for project_id in list(manager._sessions):  # pylint:disable=protected-access
        manager.close_session(project_id)


@pytest.fixture
def raw_text(tmp_path: Path) -> dict[str, str]:
    """fauxware's .text carved into a headerless image, with its load address and main's entry."""
    proj = angr.Project(_require(FAUXWARE), auto_load_libs=False)
    text = proj.loader.main_object.sections_map[".text"]
    image = tmp_path / "fauxware_text.bin"
    image.write_bytes(proj.loader.memory.load(text.vaddr, text.memsize))
    main = proj.loader.find_symbol("main")
    assert main is not None
    return {"path": str(image), "base": hex(text.vaddr), "entry": hex(main.rebased_addr)}


class TestUniversalMachO:
    def test_default_load_reports_every_slice(self):
        result = load_binary(_require(UNIVERSAL))
        assert result["backend"] == "universal2"
        assert result["available_arches"] == ["AMD64", "AARCH64"]
        assert result["loaded_slices"] == ["AMD64", "AARCH64"]
        assert result["arch"] == "AMD64"
        assert result["load_options"] == {}

    @pytest.mark.parametrize("arch", ["aarch64", "amd64"])
    def test_arch_selects_one_slice(self, arch):
        result = load_binary(_require(UNIVERSAL), arch=arch)
        assert result["arch"] == arch.upper()
        assert result["loaded_slices"] == [arch.upper()]
        assert result["load_options"] == {"arch": arch.upper()}
        get_cfg(result["project_id"])
        names = [f["name"] for f in list_functions(result["project_id"], name_pattern="auth")["functions"]]
        assert names == ["_authenticate"]

    def test_arch_absent_from_container_is_reported(self):
        with pytest.raises(InvalidArgumentError, match="not found in universal binary"):
            load_binary(_require(UNIVERSAL), arch="mips32")


class TestRawImage:
    def test_blob_loads_at_the_given_base_and_entry(self, raw_text):
        result = load_binary(
            raw_text["path"],
            backend="blob",
            arch="x86_64",
            base_address=raw_text["base"],
            entry_point=raw_text["entry"],
        )
        assert result["backend"] == "blob"
        assert result["arch"] == "AMD64"
        assert result["entry_point"] == raw_text["entry"]
        assert result["load_options"] == {
            "arch": "AMD64",
            "backend": "blob",
            "base_addr": raw_text["base"],
            "entry_point": raw_text["entry"],
        }
        get_cfg(result["project_id"])
        blocks = get_basic_blocks(result["project_id"], raw_text["entry"])
        assert blocks["blocks"][0]["instructions"][0]["mnemonic"] == "push"
        close_project(result["project_id"])

    def test_blob_requires_an_architecture(self, raw_text):
        with pytest.raises(InvalidArgumentError, match="requires arch"):
            load_binary(raw_text["path"], backend="blob")


class TestIdentity:
    def test_result_reports_the_file_digest(self):
        path = _require(FAUXWARE)
        result = load_binary(path)
        expected = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        assert result["sha256"] == expected
        assert [s["sha256"] for s in get_session_manager().list_sessions()] == [expected]


class TestRejections:
    def test_unknown_architecture_names_known_ones(self):
        with pytest.raises(InvalidArgumentError, match=r"Unknown architecture 'z80'.*aarch64"):
            load_binary(_require(FAUXWARE), arch="z80")

    def test_unsupported_backend(self):
        with pytest.raises(InvalidArgumentError, match="Unsupported backend 'pe'"):
            load_binary(_require(FAUXWARE), backend="pe")

    def test_malformed_address(self):
        with pytest.raises(InvalidArgumentError, match="base_address must be"):
            load_binary(_require(FAUXWARE), backend="blob", arch="x86_64", base_address="zzz")

    def test_dos_mz_is_rejected_with_the_reason(self):
        with pytest.raises(InvalidArgumentError, match="16-bit DOS"):
            load_binary(_require(DOS_EXE))

    def test_pe_is_not_mistaken_for_dos(self):
        reject_dos_executable(Path(_require(WINDOWS_PE)))

    def test_nothing_is_loaded_after_a_rejection(self):
        with pytest.raises(InvalidArgumentError):
            load_binary(_require(FAUXWARE), arch="z80")
        assert get_session_manager().list_sessions() == []
