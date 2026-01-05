# pylint:disable=no-member,raise-missing-from
from __future__ import annotations
import logging
import json

from collections import defaultdict

from angr.calling_conventions import SimCC, SimCCUsercall, CC_NAMES
from angr.codenode import BlockNode, HookNode, FuncNode
from angr.utils.enums_conv import func_edge_type_to_pb, func_edge_type_from_pb
from angr.sim_type import SimType, SimTypeFunction
from angr.protos import primitives_pb2, function_pb2
from angr.utils.types import make_type_reference

l = logging.getLogger(name=__name__)


class CallingConventionSerializer:
    """
    Serialize/deserialize SimCC classes.
    """

    @staticmethod
    def to_json(cc: SimCC) -> dict:
        if isinstance(cc, SimCCUsercall):
            return {
                "t": "SimCCUsercall",
                # TODO: Deserialize the rest of the fields
            }
        return {"t": cc.__class__.__name__}

    @staticmethod
    def from_json(data: dict, arch) -> SimCC | None:
        cc_type = data.get("t")
        if cc_type == "SimCCUsercall":
            return SimCCUsercall(arch, [], None)  # TODO: Deserialize the rest of the fields
        if cc_type not in CC_NAMES:
            l.warning("Unknown calling convention type %s", cc_type)
            return None
        return CC_NAMES[cc_type](arch)


class FunctionParser:
    """
    The implementation of the serialization methods for the <Function> class.
    """

    @staticmethod
    def serialize(function):
        """
        :return :
        """
        # delayed import
        from .function import Function  # pylint:disable=import-outside-toplevel

        obj = Function._get_cmsg()
        obj.ea = function.addr
        obj.is_entrypoint = False  # TODO: Set this up accordingly
        obj.name = function.name
        obj.is_plt = function.is_plt
        obj.is_syscall = function.is_syscall
        obj.is_simprocedure = function.is_simprocedure
        if function.returning is not None:
            obj.returning = function.returning
        obj.alignment = function.is_alignment
        obj.binary_name = function.binary_name or ""
        obj.normalized = function.normalized
        obj.calling_convention = (
            json.dumps(CallingConventionSerializer.to_json(function.calling_convention)).encode("utf-8")
            if function.calling_convention is not None
            else b""
        )
        if function.prototype is None:
            obj.prototype = b""
        else:
            # convert all named structs in the prototype to typerefs; they will be dereferenced when used
            prototype_ref = make_type_reference(function.prototype)
            obj.prototype = json.dumps(prototype_ref.to_json()).encode("utf-8")
        obj.prototype_libname = (function.prototype_libname or "").encode()
        obj.is_prototype_guessed = function.is_prototype_guessed
        obj.info = json.dumps(function.info).encode("utf-8") if function.info else b""

        # signature matched?
        if not function.from_signature:
            obj.matched_from = function_pb2.Function.UNMATCHED
        else:
            if function.from_signature == "flirt":
                obj.matched_from = function_pb2.Function.FLIRT
            else:
                raise ValueError(
                    f"Cannot convert from_signature {function.from_signature} into a SignatureSource " f"enum."
                )

        # blocks
        blocks_list = [b.serialize_to_cmessage() for b in function.blocks]
        obj.blocks.extend(blocks_list)  # pylint:disable=no-member

        block_addrs_set = function.block_addrs_set
        # graph
        edges = []
        external_addrs = set()
        TRANSITION_JK = func_edge_type_to_pb("transition")  # default edge type
        for src, dst, data in function.transition_graph.edges(data=True):
            edge = primitives_pb2.Edge()
            edge.src_ea = src.addr
            edge.dst_ea = dst.addr
            if src.addr not in block_addrs_set:
                # this is a Block in another function, or just another Function instance.
                external_addrs.add(src.addr)
            if dst.addr not in block_addrs_set:
                external_addrs.add(dst.addr)
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
        # referenced functions
        obj.external_functions.extend(external_addrs)  # pylint:disable=no-member

        return obj

    @staticmethod
    def parse_from_cmsg(cmsg, function_manager=None, project=None, all_func_addrs=None, meta_only: bool = False):
        """
        :param cmsg: The data to instantiate the <Function> from.

        :return Function:
        """
        # delayed import
        from .function import Function  # pylint:disable=import-outside-toplevel

        proto = SimType.from_json(json.loads(cmsg.prototype.decode("utf-8"))) if cmsg.prototype else None
        if proto is not None:
            if not isinstance(proto, SimTypeFunction):
                l.warning("Unexpected type of function prototype deserialized: %s", type(proto))
                proto = None
            elif project is None:
                proto = None  # we cannot assign an arch-less prototype to a function
            else:
                proto = proto.with_arch(project.arch)

        cc = (
            CallingConventionSerializer.from_json(json.loads(cmsg.calling_convention.decode("utf-8")), project.arch)
            if cmsg.calling_convention and project is not None
            else None
        )

        obj = Function(
            function_manager,
            cmsg.ea,
            name=cmsg.name,
            is_plt=cmsg.is_plt,
            syscall=cmsg.is_syscall,
            is_simprocedure=cmsg.is_simprocedure,
            returning=cmsg.returning,
            alignment=cmsg.alignment,
            binary_name=None if not cmsg.binary_name else cmsg.binary_name,
            calling_convention=cc,
            prototype=proto,
            prototype_libname=cmsg.prototype_libname if cmsg.prototype_libname else None,
            is_prototype_guessed=cmsg.is_prototype_guessed,
        )
        obj._project = project
        obj.normalized = cmsg.normalized
        obj.info = json.loads(cmsg.info.decode("utf-8")) if cmsg.info else {}

        # signature matched?
        if cmsg.matched_from == function_pb2.Function.UNMATCHED:
            obj.from_signature = None
        elif cmsg.matched_from == function_pb2.Function.FLIRT:
            obj.from_signature = "flirt"
        else:
            raise ValueError(f"Cannot convert SignatureSource enum {cmsg.matched_from} to Function.from_signature.")

        if meta_only:
            startpoint_addr = cmsg.ea
            obj.startpoint = (
                HookNode(startpoint_addr, 0, project.hooked_by(startpoint_addr))
                if project and project.is_hooked(startpoint_addr)
                else BlockNode(startpoint_addr, 1)
            )  # the size is incorrect, but it should probably be fine?
            obj._dirty = False
            return obj

        # blocks
        blocks = {}
        for b in cmsg.blocks:
            if project is not None and project.is_hooked(b.ea):
                # create a HookNode
                block = HookNode(b.ea, 0, project.hooked_by(b.ea))
            else:
                block = BlockNode(b.ea, b.size, bytestr=b.bytes)
            blocks[block.addr] = block
        external_addrs = set(cmsg.external_functions)  # addresses of referenced blocks or nodes that are not inside
        # the current function

        # edges
        edges = {}
        fake_return_edges = defaultdict(list)
        for edge_cmsg in cmsg.graph.edges:
            try:
                src = FunctionParser._get_block_or_func(
                    edge_cmsg.src_ea,
                    blocks,
                    external_addrs,
                    project,
                    all_func_addrs=all_func_addrs,
                )
            except KeyError as err:
                raise KeyError(f"Address of the edge source {edge_cmsg.src_ea:#x} is not found.") from err

            edge_type = func_edge_type_from_pb(edge_cmsg.jumpkind)
            assert edge_type is not None

            dst = None
            dst_addr = edge_cmsg.dst_ea
            if (
                dst_addr not in blocks and edge_type == "call"
            ) or (  # call has to go to either a HookNode or a function
                all_func_addrs is not None and dst_addr in all_func_addrs
            ):  # jumps to another function
                dst = FunctionParser._get_func(dst_addr)

            if dst is None:
                # create a block instead
                try:
                    dst = FunctionParser._get_block_or_func(
                        dst_addr,
                        blocks,
                        external_addrs,
                        project,
                        all_func_addrs=all_func_addrs,
                    )
                except KeyError as err:
                    raise KeyError(f"Address of the edge destination {edge_cmsg.dst_ea:#x} is not found.") from err

            data = {
                "outside": edge_cmsg.is_outside,
                "ins_addr": edge_cmsg.ins_addr,
                "stmt_idx": edge_cmsg.stmt_idx,
            }
            if edge_cmsg.confirmed == 0:
                data["confirmed"] = False
            elif edge_cmsg.confirmed == 1:
                data["confirmed"] = True
            if edge_type == "fake_return":
                fake_return_edges[edge_cmsg.src_ea].append((src, dst, data))
            else:
                edges[(edge_cmsg.src_ea, dst_addr, edge_type)] = (src, dst, data)

        added_nodes = set()
        for k, v in edges.items():
            src_addr, dst_addr, edge_type = k
            src, dst, data = v

            outside = data.get("outside", False)
            ins_addr = data.get("ins_addr", None)
            stmt_idx = data.get("stmt_idx", None)
            added_nodes.add(src)
            added_nodes.add(dst)
            if edge_type in ("transition", "exception"):
                obj._transit_to(
                    src,
                    dst,
                    outside=outside,
                    ins_addr=ins_addr,
                    stmt_idx=stmt_idx,
                    is_exception=edge_type == "exception",
                )
            elif edge_type in ("call", "syscall"):
                # find the corresponding fake_ret edge
                fake_ret_edge = next(
                    iter(edge_ for edge_ in fake_return_edges[src_addr] if edge_[1].addr == src.addr + src.size), None
                )
                if dst is None:
                    l.warning(
                        "The destination function %#x does not exist, and it cannot be created since function "
                        "manager is not provided. Please consider passing in a function manager to rebuild this "
                        "graph.",
                        dst_addr,
                    )
                else:
                    if isinstance(dst, FuncNode):
                        obj._call_to(
                            src,
                            dst,
                            None if fake_ret_edge is None else fake_ret_edge[1],
                            stmt_idx=stmt_idx,
                            ins_addr=ins_addr,
                            return_to_outside=fake_ret_edge is None,
                        )
                    if fake_ret_edge is not None:
                        fakeret_src, fakeret_dst, fakeret_data = fake_ret_edge
                        added_nodes.add(fakeret_dst)
                        obj._fakeret_to(
                            fakeret_src,
                            fakeret_dst,
                            confirmed=fakeret_data.get("confirmed"),
                            to_outside=fakeret_data.get("outside", None),
                        )
            elif edge_type == "fake_return":
                pass

        # add leftover blocks
        for block in blocks.values():
            if block not in added_nodes:
                obj._register_node(True, block)

        obj._dirty = False

        return obj

    @staticmethod
    def _get_block_or_func(addr, blocks, external_addrs, project, all_func_addrs=None):
        # should we get a block or a function?
        try:
            return blocks[addr]
            # it's a block. just return it
        except KeyError:
            pass

        if addr in external_addrs:
            if project is not None and project.is_hooked(addr):
                # get a hook node instead
                return HookNode(addr, 0, project.hooked_by(addr))
            if all_func_addrs is not None and addr in all_func_addrs:
                # get a function node
                return FuncNode(addr)
            # create a block
            # TODO: We are deciding the size by re-lifting the block from project. This is usually fine except for
            # TODO: the cases where the block does not exist in project (e.g., when the block was dynamically
            # TODO: created). The correct solution is to store the size and bytes of the block, too.
            if project is not None:
                block = project.factory.block(addr)
                block_size = block.size
                bytestr = block.bytes
            else:
                l.warning(
                    "The Project instance is not specified. Use a dummy block size of 1 byte for block %#x.", addr
                )
                block_size = 1
                bytestr = b"\x00"
            return BlockNode(addr, block_size, bytestr=bytestr)
        raise ValueError(
            "Unsupported case: The block %#x is not in external_addrs and is not in local blocks. "
            "This probably indicates a bug in angrdb generation."
        )

    @staticmethod
    def _get_func(addr):
        return FuncNode(addr)
