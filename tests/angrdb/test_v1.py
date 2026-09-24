#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
"""
A version-1 angrdb (functions in the per-block / per-edge layout, no graph_blob) loads through AngrDbV1 and yields
the same functions as the live knowledge base.
"""

from __future__ import annotations

import os
import tempfile
import unittest

import angr
from angr.angrdb import AngrDB
from angr.angrdb.models import DbFunction, DbInformation
from angr.angrdb.v1 import AngrDbV1
from angr.protos import function_pb2
from tests.common import bin_location

FAUXWARE = os.path.join(bin_location, "tests", "x86_64", "fauxware")


def _node(n):
    return (type(n).__name__, n.addr, n.size, bool(n.thumb))


def _digest(f):
    tg = f.transition_graph
    return (
        f.name,
        f.returning,
        None if f.startpoint is None else _node(f.startpoint),
        sorted(f.block_addrs_set),
        sorted(_node(n) for n in tg.nodes()),
        sorted((_node(u), _node(v), tuple(sorted(d.items()))) for u, v, d in tg.edges(data=True)),
        {k: sorted(_node(n) for n in v) for k, v in f.endpoints_with_type.items()},
        sorted(_node(n) for n in f.ret_sites),
        sorted(_node(n) for n in f.jumpout_sites),
        sorted(_node(n) for n in f.callout_sites),
        sorted(_node(n) for n in f.retout_sites),
        sorted((a, f.get_call_target(a), f.get_call_return(a)) for a in f.get_call_sites()),
    )


class TestAngrDbV1(unittest.TestCase):
    def test_version_1_database_loads(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        proj.analyses.CFGFast()
        live = {addr: _digest(f) for addr, f in proj.kb.functions.items()}

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "fauxware-v1.adb")
            db = AngrDB(proj)
            db.dump(path)
            # rewrite every function row in the version-1 layout and mark the database as version 1
            with db.open_db(f"sqlite:///{path}") as Session, db.session_scope(Session) as session:
                for row in session.query(DbFunction):
                    cmsg = function_pb2.Function()
                    cmsg.ParseFromString(row.blob)
                    assert cmsg.graph_blob
                    v1 = AngrDbV1.serialize_function(proj.kb.functions[cmsg.ea])
                    assert not v1.graph_blob and v1.blocks
                    row.blob = v1.SerializeToString()
                session.query(DbInformation).filter_by(key="version").update({"value": "1"})
            db.invalidate()

            proj2 = AngrDB().load(path)

        assert set(proj2.kb.functions) == set(live)
        for addr, digest in live.items():
            assert _digest(proj2.kb.functions[addr]) == digest, hex(addr)
        # re-serializing a loaded function writes the current (blob) layout
        assert proj2.kb.functions["main"].serialize_to_cmessage().graph_blob


if __name__ == "__main__":
    unittest.main()
