"""
Typed protobuf pack/parse helpers for AIL-typed containers.

AIL leaves (Block / Statement / Expression) serialize through their native ``to_bytes()`` methods (postcard,
implemented in Rust); the helpers here only encode the Python container structure around them using the typed
messages in :mod:`angr.protos.ail_types_pb2`. There is no generic fallback: any value shape not covered by the
schema raises ``TypeError``.
"""
# pylint:disable=no-member

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Any

import networkx

from angr import sim_variable
from angr.analyses.decompiler.optimization_passes.static_vvar_rewriter import FixedBuffer, FixedBufferPtr
from angr.protos import ail_types_pb2
from angr.rustylib.ailment import Block, Expression

if TYPE_CHECKING:
    from angr.sim_variable import SimVariable


# ---------------------------------------------------------------------------------------------------------------------
# SimVariable polymorphic encoding
# ---------------------------------------------------------------------------------------------------------------------


def simvar_to_bytes_polymorphic(v: SimVariable) -> bytes:
    """Polymorphic SimVariable encoding: ``b"<ClassName>\\0<proto bytes>"``."""
    return type(v).__name__.encode("ascii") + b"\0" + v.serialize()


def simvar_from_bytes_polymorphic(b: bytes) -> SimVariable:
    sep = b.index(b"\0")
    cls_name = b[:sep].decode("ascii")
    return getattr(sim_variable, cls_name).parse(b[sep + 1 :])


# ---------------------------------------------------------------------------------------------------------------------
# networkx.DiGraph[ailment.Block]
# ---------------------------------------------------------------------------------------------------------------------

_EDGE_TYPE_TO_ENUM = {
    "transition": ail_types_pb2.AIL_EDGE_TRANSITION,
    "exception": ail_types_pb2.AIL_EDGE_EXCEPTION,
    "fake_return": ail_types_pb2.AIL_EDGE_FAKE_RETURN,
    "call": ail_types_pb2.AIL_EDGE_CALL,
    "syscall": ail_types_pb2.AIL_EDGE_SYSCALL,
    "return": ail_types_pb2.AIL_EDGE_RETURN,
}
_ENUM_TO_EDGE_TYPE = {v: k for k, v in _EDGE_TYPE_TO_ENUM.items()}


def _pack_edge_data(data: dict[str, Any], out: ail_types_pb2.AilEdgeData) -> bool:
    """Fill an AilEdgeData message from a networkx edge-attribute dict. Returns True if any field was set.

    Attributes with value None are packed as unset (and come back as absent keys); unknown keys or value types raise
    ``TypeError`` -- extend the AilEdgeData schema when a new edge attribute is introduced.
    """
    any_set = False
    for key, value in data.items():
        if value is None:
            continue
        if key == "type":
            if value not in _EDGE_TYPE_TO_ENUM:
                raise TypeError(f"Unsupported AIL graph edge type {value!r}; extend AilEdgeType in ail_types.proto")
            out.type = _EDGE_TYPE_TO_ENUM[value]
        elif key == "outside":
            out.outside = bool(value)
        elif key == "confirmed":
            out.confirmed = bool(value)
        elif key == "ins_addr":
            out.ins_addr = value
        elif key == "stmt_idx":
            out.stmt_idx = value
        else:
            raise TypeError(f"Unsupported AIL graph edge attribute {key!r}; extend AilEdgeData in ail_types.proto")
        any_set = True
    return any_set


def _parse_edge_data(msg: ail_types_pb2.AilEdgeData) -> dict[str, Any]:
    data: dict[str, Any] = {}
    if msg.HasField("type"):
        data["type"] = _ENUM_TO_EDGE_TYPE[msg.type]
    if msg.HasField("outside"):
        data["outside"] = msg.outside
    if msg.HasField("ins_addr"):
        data["ins_addr"] = msg.ins_addr
    if msg.HasField("stmt_idx"):
        data["stmt_idx"] = msg.stmt_idx
    if msg.HasField("confirmed"):
        data["confirmed"] = msg.confirmed
    return data


class BlockPool:
    """A shared pool of ``Block.to_bytes()`` payloads for deduplicating byte-identical blocks across graphs."""

    __slots__ = ("_index_by_payload", "payloads")

    def __init__(self) -> None:
        self.payloads: list[bytes] = []
        self._index_by_payload: dict[bytes, int] = {}

    def add(self, block) -> int:
        payload = block.to_bytes()
        idx = self._index_by_payload.get(payload)
        if idx is None:
            idx = len(self.payloads)
            self._index_by_payload[payload] = idx
            self.payloads.append(payload)
        return idx


def _edge_data_key(data: dict[str, Any]) -> tuple:
    """Hashable canonical form of an edge-data dict excluding ins_addr (which varies per edge). Skips None values to
    match ``_pack_edge_data`` (which drops them), so it reflects exactly what round-trips."""
    return tuple(sorted((k, v) for k, v in data.items() if k != "ins_addr" and v is not None))


def pack_graph(graph: networkx.DiGraph, pool: BlockPool | None = None) -> ail_types_pb2.AilGraph:
    """Encode a DiGraph of ailment Blocks. Node identity is preserved through per-graph block indices. When ``pool``
    is given, block payloads are deduplicated into it and the message stores pool refs instead of inline payloads."""
    msg = ail_types_pb2.AilGraph()
    node_to_idx: dict[Any, int] = {}
    for i, node in enumerate(graph.nodes):
        if not isinstance(node, Block):
            raise TypeError(f"Unsupported AIL graph node type {type(node).__name__}; only ailment.Block is allowed")
        node_to_idx[node] = i
        if pool is None:
            msg.blocks.append(node.to_bytes())
        else:
            msg.block_refs.append(pool.add(node))

    # Pick the modal non-ins_addr edge-data value as the default so common edge attributes are stored once.
    edge_list = list(graph.edges(data=True))
    key_counts = Counter(_edge_data_key(data) for _, _, data in edge_list)
    default_key, default_count = key_counts.most_common(1)[0] if key_counts else ((), 0)
    default_dict = dict(default_key)
    use_default = default_count >= 2 and bool(default_dict)
    if use_default:
        _pack_edge_data(default_dict, msg.default_edge_data)

    for src, dst, data in edge_list:
        edge = msg.edges.add()
        edge.src = node_to_idx[src]
        edge.dst = node_to_idx[dst]
        if use_default and _edge_data_key(data) == default_key:
            # matches the graph default: keep only the per-edge ins_addr (if any) and let parse restore the rest
            edge.has_default_data = True
            ins_addr = data.get("ins_addr")
            if ins_addr is not None:
                edge.data.ins_addr = ins_addr
        elif data:
            edge_data = ail_types_pb2.AilEdgeData()
            if _pack_edge_data(data, edge_data):
                edge.data.CopyFrom(edge_data)
    return msg


def parse_graph(msg: ail_types_pb2.AilGraph, pool_payloads=None) -> networkx.DiGraph:
    graph = networkx.DiGraph()
    if msg.block_refs:
        # pool-backed encoding: a fresh Block per graph occurrence so graphs never share node objects
        blocks = [Block.from_bytes(pool_payloads[i]) for i in msg.block_refs]
    else:
        blocks = [Block.from_bytes(b) for b in msg.blocks]
    graph.add_nodes_from(blocks)
    default_data = _parse_edge_data(msg.default_edge_data) if msg.HasField("default_edge_data") else {}
    for edge in msg.edges:
        if edge.has_default_data:
            data = dict(default_data)
            if edge.HasField("data") and edge.data.HasField("ins_addr"):
                data["ins_addr"] = edge.data.ins_addr
        else:
            data = _parse_edge_data(edge.data) if edge.HasField("data") else {}
        graph.add_edge(blocks[edge.src], blocks[edge.dst], **data)
    return graph


# ---------------------------------------------------------------------------------------------------------------------
# dict[int, tuple[VirtualVariable, SimVariable]]
# ---------------------------------------------------------------------------------------------------------------------


def pack_arg_vvars(arg_vvars: dict[int, tuple[Any, Any]]) -> ail_types_pb2.ArgVVars:
    msg = ail_types_pb2.ArgVVars()
    for idx, (vvar, simvar) in arg_vvars.items():
        entry = msg.entries[idx]
        entry.vvar = vvar.to_bytes()
        entry.simvar = simvar_to_bytes_polymorphic(simvar)
    return msg


def parse_arg_vvars(msg: ail_types_pb2.ArgVVars) -> dict[int, tuple[Any, Any]]:
    return {
        idx: (Expression.from_bytes(entry.vvar), simvar_from_bytes_polymorphic(entry.simvar))
        for idx, entry in msg.entries.items()
    }


# ---------------------------------------------------------------------------------------------------------------------
# set[tuple[int, Expression]]
# ---------------------------------------------------------------------------------------------------------------------


def pack_ite_exprs(ite_exprs: set[tuple[int, Any]]) -> ail_types_pb2.IteExprs:
    msg = ail_types_pb2.IteExprs()
    for addr, expr in sorted(ite_exprs, key=lambda t: t[0]):
        entry = msg.entries.add()
        entry.addr = addr
        entry.expr = expr.to_bytes()
    return msg


def parse_ite_exprs(msg: ail_types_pb2.IteExprs) -> set[tuple[int, Any]]:
    return {(entry.addr, Expression.from_bytes(entry.expr)) for entry in msg.entries}


# ---------------------------------------------------------------------------------------------------------------------
# Static buffer parameters (optimization_passes.static_vvar_rewriter)
# ---------------------------------------------------------------------------------------------------------------------


def pack_static_vvars(static_vvars: dict[int, Any]) -> ail_types_pb2.StaticVVars:
    msg = ail_types_pb2.StaticVVars()
    for varid, value in static_vvars.items():
        entry = msg.entries[varid]
        if isinstance(value, FixedBufferPtr):
            entry.ptr.buffer_ident = value.buffer_ident
            entry.ptr.offset = value.offset
        elif isinstance(value, Expression):
            entry.const_expr = value.to_bytes()
        else:
            raise TypeError(f"Unsupported static_vvars value type {type(value).__name__}")
    return msg


def parse_static_vvars(msg: ail_types_pb2.StaticVVars) -> dict[int, Any]:
    result: dict[int, Any] = {}
    for varid, entry in msg.entries.items():
        if entry.WhichOneof("v") == "ptr":
            result[varid] = FixedBufferPtr(entry.ptr.buffer_ident, offset=entry.ptr.offset)
        else:
            result[varid] = Expression.from_bytes(entry.const_expr)
    return result


def pack_static_buffers(static_buffers: dict[str, Any]) -> ail_types_pb2.StaticBuffers:
    msg = ail_types_pb2.StaticBuffers()
    for key, buf in static_buffers.items():
        entry = msg.entries[key]
        entry.ident = buf.ident
        entry.size = buf.size
        entry.content = buf.content
    return msg


def parse_static_buffers(msg: ail_types_pb2.StaticBuffers) -> dict[str, Any]:
    return {key: FixedBuffer(entry.ident, entry.size, entry.content) for key, entry in msg.entries.items()}
