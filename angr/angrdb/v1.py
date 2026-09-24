"""
angrDb Version 1 compatibility logic.

angrDb v1 stores function graphs as per-block and per-edge protobuf messages. We will deprecate the v1 compatibility
logic in about a year's time.
"""

# pylint:disable=no-member,raise-missing-from,protected-access
from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING

from angr.codenode import BlockNode, CodeNode, FuncNode, HookNode, SyscallNode
from angr.protos import function_pb2, primitives_pb2
from angr.rustylib.function_graph import EndpointKind, SiteKind  # pylint:disable=import-error,no-name-in-module
from angr.utils.enums_conv import (
    _EDGETYPE_MISSING,
    _PB_TO_FUNCTION_EDGETYPES,
    func_edge_type_from_pb,
    func_edge_type_to_pb,
)

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function

l = logging.getLogger(name=__name__)


class AngrDbV1:
    """
    Reader and writer of the angrDb v1-specific data types. Static methods only.
    """

    @staticmethod
    def serialize_function(function) -> function_pb2.Function:
        """
        Serialize a Function with its metadata as FunctionParser.serialize() writes it and its graph in the angrDb v1
        per-block / per-edge layout.
        """
        obj = function.serialize_to_cmessage()
        obj.ClearField("graph_blob")
        AngrDbV1.write_graph(function, obj)
        return obj

    @staticmethod
    def local_block_addrs(cmsg) -> set[int]:
        """
        The addresses of the local blocks of an angrDb v1 function record, without building the Function.
        """
        return {b.ea for b in cmsg.blocks}

    @staticmethod
    def write_graph(function: Function, obj) -> None:
        ret_sites = set(function.ret_sites)
        retout_sites = set(function.retout_sites)
        for endpoint_type, endpoint_nodes in function.endpoints_with_type.items():
            for node in endpoint_nodes:
                match endpoint_type:
                    case "call":
                        ep_types = [primitives_pb2.EndpointType.CALL]
                    case "return":
                        # a "return" endpoint is a return site, a retout site, or (rarely) both
                        ep_types = []
                        if node in retout_sites:
                            ep_types.append(primitives_pb2.EndpointType.RETOUT)
                        if node in ret_sites or not ep_types:
                            ep_types.append(primitives_pb2.EndpointType.RETURN)
                    case "transition":
                        ep_types = [primitives_pb2.EndpointType.TRANSITION]
                    case _:
                        continue
                for ep_type in ep_types:
                    ep = primitives_pb2.Endpoint()
                    ep.ea = node.addr
                    ep.size = node.size
                    ep.type = ep_type
                    obj.endpoints.append(ep)

        # local nodes
        code_nodes = function.code_nodes
        blocks_list = []
        for b in code_nodes.values():
            blocks_list.append(AngrDbV1.node_to_block_cmsg(b))
        obj.blocks.extend(blocks_list)  # pylint:disable=no-member

        # nodes outside of this function; FuncNode, HookNode, and SyscallNode addresses are also recorded in
        # external_functions for readers that predate Block.kind
        external_func_addrs = []
        external_blocks = []
        for node in function.transition_graph:
            if code_nodes.get(node.addr) == node:
                continue
            external_blocks.append(AngrDbV1.node_to_block_cmsg(node))
            if isinstance(node, (FuncNode, HookNode)):
                external_func_addrs.append(node.addr)

        TRANSITION_JK = func_edge_type_to_pb("transition")  # default edge type
        edges = []
        for src, dst, data in function.transition_graph.edges(data=True):
            edge = primitives_pb2.Edge()
            edge.src_ea = src.addr
            edge.dst_ea = dst.addr
            edge.jumpkind = TRANSITION_JK
            edge.confirmed = 2  # default value
            for key, value in data.items():
                if key == "type":
                    edge.jumpkind = func_edge_type_to_pb(value)
                elif key == "ins_addr":
                    if value is not None:
                        edge.ins_addr = value
                elif key == "stmt_idx":
                    if value is not None:
                        edge.stmt_idx = value
                elif key == "outside":
                    edge.is_outside = value
                elif key == "confirmed":
                    edge.confirmed = 0 if value is False else 1
                else:
                    l.warning('Unexpected edge data type "%s" encountered during serialization.', key)
            edges.append(edge)
        obj.graph.edges.extend(edges)  # pylint:disable=no-member
        obj.external_functions.extend(external_func_addrs)  # pylint:disable=no-member
        obj.external_blocks.extend(external_blocks)  # pylint:disable=no-member

        for call_site_addr, (call_target_addr, retn_addr) in function.call_sites.items():
            call_site = function_pb2.CallSite()
            call_site.ea = call_site_addr
            if call_target_addr is not None:
                call_site.target_ea = call_target_addr
            if retn_addr is not None:
                call_site.return_ea = retn_addr
            obj.call_sites.append(call_site)  # pylint:disable=no-member

    @staticmethod
    def node_to_block_cmsg(node) -> primitives_pb2.Block:
        block = primitives_pb2.Block()
        block.ea = node.addr
        block.size = node.size
        block.thumb = node.thumb
        if isinstance(node, SyscallNode):
            block.kind = primitives_pb2.CodeNodeKind.SYSCALL_NODE
        elif isinstance(node, HookNode):
            block.kind = primitives_pb2.CodeNodeKind.HOOK_NODE
        elif isinstance(node, FuncNode):
            block.kind = primitives_pb2.CodeNodeKind.FUNC_NODE
        elif isinstance(node, BlockNode):
            block.kind = primitives_pb2.CodeNodeKind.BLOCK_NODE
            if node.manual_bytes:
                block.bytes = node._bytestr
        else:
            raise TypeError(f"Unsupported node type {type(node)}")
        return block

    @staticmethod
    def node_from_block_cmsg(block, project):
        match block.kind:
            case primitives_pb2.CodeNodeKind.BLOCK_NODE:
                # Messages of the per-block layout carry bytes for every block (angr <= #7235 wrote them for all
                # lifted blocks), so user-supplied bytes cannot be told apart: the stored bytes are dropped and the
                # node reads its bytes from the loader.
                return BlockNode(block.ea, block.size, thumb=block.thumb)
            case primitives_pb2.CodeNodeKind.HOOK_NODE:
                hooker = project.hooked_by(block.ea) if project is not None and project.is_hooked(block.ea) else None
                return HookNode(block.ea, block.size, hooker, thumb=block.thumb)
            case primitives_pb2.CodeNodeKind.SYSCALL_NODE:
                syscall = project.simos.syscall_from_addr(block.ea) if project is not None else None
                return SyscallNode(block.ea, block.size, syscall, thumb=block.thumb)
            case primitives_pb2.CodeNodeKind.FUNC_NODE:
                return FuncNode(block.ea, thumb=block.thumb)
            case _:
                raise ValueError(f"Unsupported CodeNodeKind {block.kind}")

    @staticmethod
    def parse_function(cmsg, obj, project, meta_only: bool):
        """
        Rebuild the graph of `obj` (a Function whose metadata is already set) from the per-block / per-edge layout
        of `cmsg`.
        """
        if meta_only:
            for b in cmsg.blocks:
                obj._register(True, AngrDbV1.node_from_block_cmsg(b, project), update_func_block_count=False)
            if obj.startpoint is None:
                obj.startpoint = (
                    HookNode(cmsg.ea, 0, project.hooked_by(cmsg.ea))
                    if project and project.is_hooked(cmsg.ea)
                    else BlockNode(cmsg.ea, 1)
                )  # the size is incorrect, but it should probably be fine?

            for endpoint in cmsg.endpoints:
                block = BlockNode(endpoint.ea, endpoint.size)
                AngrDbV1.add_endpoint(obj, block, endpoint.type)

            obj.meta_only = True  # can't be serialized again when evicted from the cache
            obj._dirty = False
            return obj

        # nodes
        blocks: dict[int, CodeNode] = {}
        for b in cmsg.blocks:
            block = AngrDbV1.node_from_block_cmsg(b, project)
            blocks[block.addr] = block

        external_nodes: dict[int, list[CodeNode]] = defaultdict(list)
        for b in cmsg.external_blocks:
            external_nodes[b.ea].append(AngrDbV1.node_from_block_cmsg(b, project))

        # addresses of referenced functions that are not inside the current function (readers of old messages only)
        external_func_addrs = set(cmsg.external_functions)

        def resolve(addr: int) -> CodeNode:
            node = blocks.get(addr)
            if node is not None:
                return node
            return AngrDbV1.get_external_node(addr, external_nodes, external_func_addrs, project)

        # edges
        edges = []
        fake_return_edges = []
        # inline the protobuf-jumpkind -> edge-type lookup on this hot per-edge path; fall back to
        # func_edge_type_from_pb only to log the error for an unrecognized value
        edge_type_of = _PB_TO_FUNCTION_EDGETYPES.get
        for edge_cmsg in cmsg.graph.edges:
            edge_type = edge_type_of(edge_cmsg.jumpkind, _EDGETYPE_MISSING)
            if edge_type is _EDGETYPE_MISSING:
                edge_type = func_edge_type_from_pb(edge_cmsg.jumpkind)
            assert edge_type is not None

            # Function._call_to() and Function._return_from_call() always take the callee as a FuncNode
            src = FuncNode(edge_cmsg.src_ea) if edge_type == "return" else resolve(edge_cmsg.src_ea)
            dst = FuncNode(edge_cmsg.dst_ea) if edge_type in ("call", "syscall") else resolve(edge_cmsg.dst_ea)

            data = {
                "outside": edge_cmsg.is_outside,
                "ins_addr": edge_cmsg.ins_addr if edge_cmsg.HasField("ins_addr") else None,
                "stmt_idx": edge_cmsg.stmt_idx if edge_cmsg.HasField("stmt_idx") else None,
            }
            if edge_cmsg.confirmed == 0:
                data["confirmed"] = False
            elif edge_cmsg.confirmed == 1:
                data["confirmed"] = True
            if edge_type == "fake_return":
                fake_return_edges.append((src, dst, data))
            else:
                edges.append((src, dst, edge_type, data))

        for src, dst, edge_type, data in edges:
            if edge_type in ("transition", "exception"):
                obj._transit_to(
                    src,
                    dst,
                    outside=data["outside"],
                    ins_addr=data["ins_addr"],
                    stmt_idx=data["stmt_idx"],
                    is_exception=edge_type == "exception",
                    update_func_block_count=False,  # we will update the block count at the end of this function
                )
            elif edge_type in ("call", "syscall"):
                obj._call_to(
                    src,
                    dst,
                    None,  # fake-return edges are restored on their own below
                    stmt_idx=data["stmt_idx"],
                    ins_addr=data["ins_addr"],
                    syscall=edge_type == "syscall",
                    update_func_block_count=False,  # we will update the block count at the end of this function
                )
            elif edge_type == "return":
                obj._return_from_call(
                    src,
                    dst,
                    to_outside=data["outside"],
                    confirm_fakeret=False,
                )

        for src, dst, data in fake_return_edges:
            confirmed = data.get("confirmed")
            # _fakeret_to() registers a confirmed destination as a local block unless to_outside is set; the block
            # list decides locality, the stored flag is restored on the edge afterwards
            obj._fakeret_to(
                src,
                dst,
                confirmed=confirmed,
                to_outside=data["outside"] or dst.addr not in blocks,
                update_func_block_count=False,  # we will update the block count at the end of this function
            )
            obj._set_edge_outside(src, dst, data["outside"])

        for endpoint in cmsg.endpoints:
            if endpoint.ea not in blocks:
                continue
            AngrDbV1.add_endpoint(obj, blocks[endpoint.ea], endpoint.type)

        # add leftover nodes: local blocks without edges or only reachable via unconfirmed fake-return edges, and
        # external nodes without edges
        for block in blocks.values():
            if not obj._graph.is_local(block.addr):
                obj._register(True, block, update_func_block_count=False)
        for nodes in external_nodes.values():
            for node in nodes:
                if not obj._has_node(node):
                    obj._register(False, node, update_func_block_count=False)

        obj.update_func_block_count()

        for call_site_cmsg in cmsg.call_sites:
            obj._graph.add_call_site(
                call_site_cmsg.ea,
                call_site_cmsg.target_ea if call_site_cmsg.HasField("target_ea") else None,
                call_site_cmsg.return_ea if call_site_cmsg.HasField("return_ea") else None,
            )

        obj._dirty = False

        return obj

    @staticmethod
    def add_endpoint(func, block: CodeNode, endpoint_type) -> None:
        match endpoint_type:
            case primitives_pb2.EndpointType.CALL:
                idx = func._register(True, block)
                func._graph.add_site(idx, SiteKind.CALLOUT)
                func._graph.add_endpoint(idx, EndpointKind.CALL)
            case primitives_pb2.EndpointType.RETURN:
                func._add_return_site(block)
            case primitives_pb2.EndpointType.RETOUT:
                func.add_retout_site(block)
            case primitives_pb2.EndpointType.TRANSITION:
                func.add_jumpout_site(block)
            case _:
                l.warning("Unsupported EndpointType %s encountered during deserialization.", endpoint_type)

    @staticmethod
    def get_external_node(
        addr, external_nodes: dict[int, list[CodeNode]], external_func_addrs: set[int], project
    ) -> CodeNode:
        candidates = external_nodes.get(addr)
        if candidates:
            # a FuncNode only ever coexists at the same address with a Block/Hook/SyscallNode that is the real target
            for node in candidates:
                if not isinstance(node, FuncNode):
                    return node
            return candidates[0]

        # messages written before Block.kind existed only record the addresses of external functions
        if addr in external_func_addrs:
            if project is not None and project.is_hooked(addr):
                return HookNode(addr, 0, project.hooked_by(addr))
            return FuncNode(addr)

        raise ValueError(
            f"Unsupported case: The block addr {addr:#x} is not an external function or block. "
            f"This probably indicates a bug in angrdb generation."
        )
