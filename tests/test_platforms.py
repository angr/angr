from __future__ import annotations

import importlib
import os
import subprocess
import sys

import pytest

import angr.utils.lmdb as lmdb_utils
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# CFG recovery on a binary this size passes the node cache limit, so whether the model
# ever reaches LMDB is decided by the spilling flag rather than by the binary.
CFG_BINARY = os.path.join(test_location, "x86_64", "bbbq")

CHILD_TIMEOUT = 600

# The spilling flags are bound at import, so the check needs a fresh interpreter. Making
# `import lmdb` fail leaves angr.utils.lmdb in the state its sys.platform == "emscripten"
# branch produces: lmdb_available False, with the stub whose open() raises in place.
NO_LMDB_CFG_CHILD = """
import sys

sys.modules["lmdb"] = None

import angr
from angr.knowledge_plugins.cfg.spilling_cfg import USE_SPILLING_CFGNODE_DICT
from angr.utils.lmdb import lmdb_available

assert not lmdb_available, "the child did not reproduce a platform without LMDB"

project = angr.Project(sys.argv[1], auto_load_libs=False)
assert project.get_cfg_node_cache_limit() is not None, "this binary no longer spills; use a larger one"

cfg = project.analyses.CFGFast(normalize=True)
print("spilling", USE_SPILLING_CFGNODE_DICT, "nodes", cfg.graph.number_of_nodes())
"""


def test_lmdb_emscripten_fallback(monkeypatch):
    try:
        with monkeypatch.context() as patch:
            patch.setattr(sys, "platform", "emscripten")
            importlib.reload(lmdb_utils)

            assert not lmdb_utils.lmdb_available
            assert lmdb_utils.lmdb.Error is lmdb_utils.lmdb.MapFullError
            with pytest.raises(lmdb_utils.lmdb.Error, match="LMDB is not available"):
                lmdb_utils.lmdb.open("unused")
    finally:
        importlib.reload(lmdb_utils)


def test_cfg_recovery_does_not_need_lmdb():
    """CFG node and edge spilling has to switch itself off when LMDB is unavailable.

    Emscripten has no LMDB, so `angr.utils.lmdb` hands out a stub whose `open` raises.
    The other three spilling caches already read `lmdb_available` and stay off. If this
    one does not, CFGFast drops nodes out of memory and only then calls `_save_to_lmdb`,
    which raises `AngrRuntimeDbError` with the nodes already gone.
    """
    # -P keeps the working directory off the child's sys.path, so it imports the built
    # angr rather than whatever tree the suite happens to be running from.
    child = subprocess.run(
        [sys.executable, "-P", "-c", NO_LMDB_CFG_CHILD, CFG_BINARY],
        capture_output=True,
        text=True,
        timeout=CHILD_TIMEOUT,
        check=False,
    )

    assert child.returncode == 0, f"stdout:\n{child.stdout}\nstderr:\n{child.stderr}"
    assert "spilling False" in child.stdout, child.stdout
