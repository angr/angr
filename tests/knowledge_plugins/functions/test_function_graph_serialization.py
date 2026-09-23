#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

import os
import pickle
import tempfile
import unittest

import angr
from angr.angrdb import AngrDB
from angr.angrdb.v1 import AngrDbV1
from angr.codenode import BlockNode
from angr.knowledge_plugins.functions.function import Function
from angr.knowledge_plugins.functions.function_parser import FunctionParser
from angr.protos import function_pb2
from angr.rustylib.function_graph import FunctionGraph
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# fauxware "authenticate" and "main" serialized by angr 24737f3a2 (graph_format 0: per-block/per-edge messages)
LEGACY_AUTHENTICATE = bytes.fromhex(
    "08e48c8002123308e48c8002202a2a2a554889e54883ec2048897de8488975e0c645f800488b15c9092000488b45e04889d64889c7e8c2fe"
    "ffff120d088e8d800220042a0485c07507121008928d800220072a07b801000000eb52121f08998d800220162a16488b45e8be0000000048"
    "89c7b800000000e8b1feffff120b08eb8d800220022a02c9c3122208af8d800220192a198945fc488d4df08b45fcba080000004889ce89c7"
    "e868feffff121c08c88d800220132a13488d55f0488b45e04889d64889c7e875feffff120d08db8d800220042a0485c07507121008df8d80"
    "0220072a07b801000000eb05120e08e68d800220052a05b800000000220c61757468656e74696361746550015a0866617578776172656283"
    "030a1e08e48c800210d08a8002180228898d800230feffffffffffffffff0138020a0e08e48c8002108e8d8002180438010a15088e8d8002"
    "10928d8002180128908d8002301138020a1e088e8d800210998d8002180128908d800230feffffffffffffffff0138020a1e08928d800210"
    "eb8d8002180128978d800230feffffffffffffffff0138020a1e08998d800210e08a8002180228aa8d800230feffffffffffffffff013802"
    "0a0e08998d800210af8d8002180438010a1e08af8d800210b08a8002180228c38d800230feffffffffffffffff0138020a0e08af8d800210"
    "c88d8002180438010a1e08c88d800210d08a8002180228d68d800230feffffffffffffffff0138020a0e08c88d800210db8d800218043801"
    "0a1508db8d800210df8d8002180128dd8d8002301138020a1e08db8d800210e68d8002180128dd8d800230feffffffffffffffff0138020a"
    "1e08df8d800210eb8d8002180128e48d800230feffffffffffffffff0138020a1308e68d800210eb8d8002180128e68d800238026a0cd08a"
    "8002b08a8002e08a80027801aa01147b2262705f61735f677072223a2066616c73657db20109080110eb8d80021802ea010f08e48c800210"
    "d08a8002188e8d8002ea010f08998d800210e08a800218af8d8002ea010f08af8d800210b08a800218c88d8002ea010f08c88d800210d08a"
    "800218db8d8002"
)
LEGACY_MAIN = bytes.fromhex(
    "089d8e8002122a089d8e800220212a21554889e54883ec40897dcc488975c0c645f800c645e800bf15094000e8d2fdffff121f08be8e8002"
    "20162a16488d45f0ba080000004889c6bf00000000e8dcfdffff121f08d48e800220162a16488d45dcba010000004889c6bf00000000e8c6"
    "fdffff121308ea8e8002200a2a0abf20094000e89cfdffff121f08f48e800220162a16488d45e0ba080000004889c6bf00000000e8a6fdff"
    "ff121f088a8f800220162a16488d45dcba010000004889c6bf00000000e890fdffff121c08a08f800220132a13488d55e0488d45f04889d6"
    "4889c7e8b1feffff121308b38f8002200a2a0a8945dc8b45dc85c0740c121308c98f8002200a2a0ab800000000e82affffff121308bd8f80"
    "02200a2a0ab800000000e826ffffff120b08c78f800220022a02eb0a120b08d38f800220022a02c9c322046d61696e50015a086661757877"
    "61726562f7030a1e089d8e800210908a8002180228b98e800230feffffffffffffffff0138020a0e089d8e800210be8e8002180438010a1e"
    "08be8e800210b08a8002180228cf8e800230feffffffffffffffff0138020a0e08be8e800210d48e8002180438010a1e08d48e800210b08a"
    "8002180228e58e800230feffffffffffffffff0138020a0e08d48e800210ea8e8002180438010a1e08ea8e800210908a8002180228ef8e80"
    "0230feffffffffffffffff0138020a0e08ea8e800210f48e8002180438010a1e08f48e800210b08a8002180228858f800230feffffffffff"
    "ffffff0138020a0e08f48e8002108a8f8002180438010a1e088a8f800210b08a80021802289b8f800230feffffffffffffffff0138020a0e"
    "088a8f800210a08f8002180438010a1e08a08f800210e48c8002180228ae8f800230feffffffffffffffff0138020a0e08a08f800210b38f"
    "8002180438010a1508b38f800210c98f8002180128bb8f8002302138020a1e08b38f800210bd8f8002180128bb8f800230feffffffffffff"
    "ffff0138020a1e08c98f800210fd8d8002180228ce8f800230feffffffffffffffff0138020a1e08bd8f800210ed8d8002180228c28f8002"
    "30feffffffffffffffff0138020a0e08bd8f800210c78f8002180438010a1e08c78f800210d38f8002180128c78f800230feffffffffffff"
    "ffff0138026a14e48c8002ed8d8002908a8002b08a8002fd8d80027801aa01147b2262705f61735f677072223a2066616c73657db2010908"
    "0110d38f80021802b2010710c98f8002180aea010f089d8e800210908a800218be8e8002ea010f08be8e800210b08a800218d48e8002ea01"
    "0f08d48e800210b08a800218ea8e8002ea010f08ea8e800210908a800218f48e8002ea010f08f48e800210b08a8002188a8f8002ea010f08"
    "8a8f800210b08a800218a08f8002ea010f08a08f800210e48c800218b38f8002ea010a08c98f800210fd8d8002ea010f08bd8f800210ed8d"
    "800218c78f8002"
)


def digest_without_stmt_idx(digest: tuple) -> tuple:
    """
    A function digest with edge statement indices blanked. Statement indices depend on the lifter (VEX) version, so a
    graph serialized by one angr build cannot be compared field-for-field against a CFG recovered by another.
    """
    nodes, edges, *rest = digest
    return (nodes, sorted((*e[:9], None, *e[10:]) for e in edges), *rest)


def function_digest(func: Function) -> tuple:
    """
    Everything the CFG and the decompiler read off a function's graph, in a comparable form. Unknown ins_addr and
    stmt_idx (unset, None, or 0; a transition never originates at address 0 or at statement 0) are canonicalized to None.
    """
    graph = func.transition_graph
    nodes = sorted((type(n).__name__, n.addr, n.size, n.thumb) for n in graph.nodes())
    edges = []
    for src, dst, data in graph.edges(data=True):
        ins_addr = data.get("ins_addr") or None
        stmt_idx = data.get("stmt_idx") or None
        edges.append(
            (
                type(src).__name__,
                src.addr,
                src.size,
                type(dst).__name__,
                dst.addr,
                dst.size,
                data["type"],
                data.get("outside", False),
                ins_addr,
                stmt_idx,
                data.get("confirmed"),
            )
        )
    endpoints = sorted((sort, sorted((n.addr, n.size) for n in ns)) for sort, ns in func.endpoints_with_type.items())
    return (
        nodes,
        sorted(edges),
        sorted(func.block_addrs_set),
        endpoints,
        func.returning,
        sorted((a, func.get_call_target(a), func.get_call_return(a)) for a in func.get_call_sites()),
        (func.startpoint.addr, func.startpoint.size) if func.startpoint is not None else None,
        sorted((n.addr, n.size) for n in func.ret_sites),
        sorted((n.addr, n.size) for n in func.jumpout_sites),
        sorted((n.addr, n.size) for n in func.callout_sites),
        sorted((n.addr, n.size) for n in func.retout_sites),
        func.normalized,
        func.name,
    )


class TestFunctionGraphSerialization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cls.cfg = cls.proj.analyses.CFGFast(normalize=True)
        cls.digests = {addr: function_digest(f) for addr, f in cls.proj.kb.functions.items()}

    def test_protobuf_round_trip(self):
        proj = self.proj
        for func in proj.kb.functions.values():
            cmsg = func.serialize_to_cmessage()
            assert cmsg.graph_blob
            assert not cmsg.blocks and not cmsg.graph.edges and not cmsg.endpoints and not cmsg.call_sites
            assert FunctionParser.local_block_addrs_from_cmsg(cmsg) == func.block_addrs_set
            loaded = Function.parse(cmsg.SerializeToString(), function_manager=proj.kb.functions, project=proj)
            assert function_digest(loaded) == self.digests[func.addr]
            assert loaded.dirty is False
            for addr, node in func.code_nodes.items():
                if isinstance(node, BlockNode):
                    # block bytes are not stored; they are read back from the loader on demand
                    assert loaded.code_nodes[addr].bytestr(proj) == node.bytestr(proj)

    def test_block_bytes_are_derived_from_the_loader(self):
        proj = self.proj
        # a node with user-supplied bytes keeps them across a reload; a node at an unmapped address has none, and a
        # node in mapped memory reads the loader's bytes
        synthetic = Function(
            proj.kb.functions,
            0x500000,
            name="synthetic",
            syscall=False,
            is_simprocedure=False,
            is_plt=False,
            returning=True,
        )
        synthetic._register_node(True, BlockNode(0x500000, 4, bytestr=b"\x90\x90\x90\xc3"))
        synthetic._register_node(True, BlockNode(0x500004, 4))
        loaded = Function.parse(synthetic.serialize(), function_manager=proj.kb.functions, project=proj)
        n0, n4 = loaded.code_nodes[0x500000], loaded.code_nodes[0x500004]
        assert n0.manual_bytes and n0.bytestr(proj) == b"\x90\x90\x90\xc3"
        assert not n4.manual_bytes and n4.bytestr(proj) is None
        main = proj.kb.functions["main"]
        loaded = Function.parse(main.serialize(), function_manager=proj.kb.functions, project=proj)
        node = loaded.code_nodes[main.addr]
        assert not node.manual_bytes and node.bytestr(proj) == proj.loader.memory.load(main.addr, node.size)

    def test_meta_only_load(self):
        proj = self.proj
        func = proj.kb.functions["main"]
        meta = Function.parse_from_cmessage(
            func.serialize_to_cmessage(), function_manager=proj.kb.functions, project=proj, meta_only=True
        )
        assert meta.meta_only is True
        assert meta.dirty is False
        assert meta.block_addrs_set == func.block_addrs_set
        assert {n.addr for n in meta.endpoints} == {n.addr for n in func.endpoints}
        assert meta.startpoint is not None and meta.startpoint.addr == func.addr
        # the blob is decoded whole, so a meta-only function carries the same graph as a full load
        assert set(meta.block_addrs) == func.block_addrs_set
        assert meta._graph.number_of_edges() == func._graph.number_of_edges()

    def test_legacy_format_load(self):
        proj = self.proj
        for blob, name in ((LEGACY_AUTHENTICATE, "authenticate"), (LEGACY_MAIN, "main")):
            cmsg = function_pb2.Function()
            cmsg.ParseFromString(blob)
            assert not cmsg.graph_blob and cmsg.blocks
            loaded = Function.parse_from_cmessage(cmsg, function_manager=proj.kb.functions, project=proj)
            assert loaded.name == name
            # the fixtures were serialized by a specific lifter build; only stmt_idx may differ from today's CFG
            assert digest_without_stmt_idx(function_digest(loaded)) == digest_without_stmt_idx(
                self.digests[proj.kb.functions[name].addr]
            )
            # re-serializing produces the blob layout, and the blob round-trips to the same graph
            reserialized = loaded.serialize_to_cmessage()
            assert reserialized.graph_blob and not reserialized.blocks
            reloaded = Function.parse_from_cmessage(reserialized, function_manager=proj.kb.functions, project=proj)
            assert function_digest(reloaded) == function_digest(loaded)

    def test_pickle_round_trip(self):
        proj2 = pickle.loads(pickle.dumps(self.proj, -1))
        assert {addr: function_digest(f) for addr, f in proj2.kb.functions.items()} == self.digests

    def test_angrdb_round_trip(self):
        dtemp = tempfile.mkdtemp()
        db_file = os.path.join(dtemp, "fauxware.adb")
        AngrDB(self.proj, nullpool=True).dump(db_file)
        proj2 = AngrDB(nullpool=True).load(db_file)
        assert {addr: function_digest(f) for addr, f in proj2.kb.functions.items()} == self.digests

    def test_blob_layout(self):
        func = self.proj.kb.functions["main"]
        cmsg = func.serialize_to_cmessage()
        blob = cmsg.graph_blob
        assert blob[0] == 2  # format version
        graph = FunctionGraph.from_bytes(blob)
        assert graph.func_addr == func.addr
        assert graph.local_count() == len(func.block_addrs_set)
        assert graph.number_of_edges() == func.transition_graph.number_of_edges()
        assert graph.startpoint is not None
        assert graph.to_bytes() == blob
        # the per-edge layout is still written on request and loads to the same graph
        legacy = AngrDbV1.serialize_function(func)
        assert not legacy.graph_blob and legacy.blocks and legacy.graph.edges
        loaded = Function.parse_from_cmessage(legacy, function_manager=self.proj.kb.functions, project=self.proj)
        assert function_digest(loaded) == self.digests[func.addr]


if __name__ == "__main__":
    unittest.main()
