# pylint:disable=no-member,raise-missing-from
import logging
import pickle

from collections import defaultdict

from ...codenode import BlockNode, HookNode
from ...utils.enums_conv import func_edge_type_to_pb, func_edge_type_from_pb
from ...protos import primitives_pb2, function_pb2

l = logging.getLogger(name=__name__)


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
        obj.returning = function.returning
        obj.alignment = function.alignment
        obj.binary_name = function.binary_name
        obj.normalized = function.normalized

        # signature matched?
        if not function.from_signature:
            obj.matched_from = function_pb2.Function.UNMATCHED
        else:
            if function.from_signature == "flirt":
                obj.matched_from = function_pb2.Function.FLIRT
            else:
                raise ValueError(f"Cannot convert from_signature {function.from_signature} into a SignatureSource "
                                 f"enum.")

        # blocks
        blocks_list = [ b.serialize_to_cmessage() for b in function.blocks ]
        obj.blocks.extend(blocks_list)  # pylint:disable=no-member

        block_addrs_set = function.block_addrs_set
        # graph
        edges = []
        external_addrs = set()
        TRANSITION_JK = func_edge_type_to_pb('transition')  # default edge type
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
                else:
                    edge.data[key] = pickle.dumps(value)  # pylint:disable=no-member
            edges.append(edge)
        obj.graph.edges.extend(edges)  # pylint:disable=no-member
        # referenced functions
        obj.external_functions.extend(external_addrs)  # pylint:disable=no-member

        return obj

    @staticmethod
    def parse_from_cmsg(cmsg, function_manager=None, project=None, all_func_addrs=None):
        """
        :param cmsg: The data to instanciate the <Function> from.

        :return Function:
        """
        # delayed import
        from .function import Function  # pylint:disable=import-outside-toplevel

        obj = Function(
            function_manager,
            cmsg.ea,
            name=cmsg.name,
            is_plt=cmsg.is_plt,
            syscall=cmsg.is_syscall,
            is_simprocedure=cmsg.is_simprocedure,
            returning=cmsg.returning,
            alignment=cmsg.alignment,
            binary_name=cmsg.binary_name,
        )
        obj._project = project
        obj.normalized = cmsg.normalized

        # signature matched?
        if cmsg.matched_from == function_pb2.Function.UNMATCHED:
            obj.from_signature = None
        elif cmsg.matched_from == function_pb2.Function.FLIRT:
            obj.from_signature = "flirt"
        else:
            raise ValueError(f"Cannot convert SignatureSource enum {cmsg.matched_from} to Function.from_signature.")

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
                    function_manager,
                    project,
                    all_func_addrs=all_func_addrs,
                )
            except KeyError:
                raise KeyError("Address of the edge source %#x is not found." % edge_cmsg.src_ea)

            edge_type = func_edge_type_from_pb(edge_cmsg.jumpkind)
            assert edge_type is not None

            dst = None
            dst_addr = edge_cmsg.dst_ea
            if dst_addr not in blocks:
                if (edge_type == 'call' # call has to go to either a HookNode or a function
                    or (all_func_addrs is not None and dst_addr in all_func_addrs)  # jumps to another function
                ):
                    if function_manager is not None:
                        # get a function
                        dst = FunctionParser._get_func(dst_addr, function_manager)
                    else:
                        l.warning("About to get or create a function at %#x, but function_manager is not provided. "
                                  "Will create a block instead.", dst_addr)

            if dst is None:
                # create a block instead
                try:
                    dst = FunctionParser._get_block_or_func(
                        dst_addr,
                        blocks,
                        external_addrs,
                        function_manager,
                        project,
                        all_func_addrs=all_func_addrs,
                    )
                except KeyError:
                    raise KeyError("Address of the edge destination %#x is not found." % edge_cmsg.dst_ea)

            data = dict((k, pickle.loads(v)) for k, v in edge_cmsg.data.items())
            data['outside'] = edge_cmsg.is_outside
            data['ins_addr'] = edge_cmsg.ins_addr
            data['stmt_idx'] = edge_cmsg.stmt_idx
            if edge_type == 'fake_return':
                fake_return_edges[edge_cmsg.src_ea].append((src, dst, data))
            else:
                edges[(edge_cmsg.src_ea, dst_addr, edge_type)] = (src, dst, data)

        added_nodes = set()
        for k, v in edges.items():
            src_addr, dst_addr, edge_type = k
            src, dst, data = v

            outside = data.get('outside', False)
            ins_addr = data.get('ins_addr', None)
            stmt_idx = data.get('stmt_idx', None)
            added_nodes.add(src)
            added_nodes.add(dst)
            if edge_type in ('transition', 'exception'):
                obj._transit_to(src, dst, outside=outside, ins_addr=ins_addr, stmt_idx=stmt_idx,
                                is_exception=edge_type == 'exception')
            elif edge_type == 'call':
                # find the corresponding fake_ret edge
                fake_ret_edge = next(iter(edge_ for edge_ in fake_return_edges[src_addr]
                                          if edge_[1].addr == src.addr + src.size), None)
                if dst is None:
                    l.warning("The destination function %#x does not exist, and it cannot be created since function "
                              "manager is not provided. Please consider passing in a function manager to rebuild this "
                              "graph.", dst_addr)
                else:
                    if isinstance(dst, Function):
                        obj._call_to(src, dst, None if fake_ret_edge is None else fake_ret_edge[1],
                                     stmt_idx=stmt_idx,
                                     ins_addr=ins_addr,
                                     return_to_outside=fake_ret_edge is None,
                                     )
                    if fake_ret_edge is not None:
                        fakeret_src, fakeret_dst, fakeret_data = fake_ret_edge
                        added_nodes.add(fakeret_dst)
                        obj._fakeret_to(fakeret_src, fakeret_dst,
                                        confirmed=fakeret_data.get('confirmed'),
                                        to_outside=fakeret_data.get('outside', None))
            elif edge_type == 'fake_return':
                pass

        # add leftover blocks
        for block in blocks.values():
            if block not in added_nodes:
                obj._register_nodes(True, block)

        return obj

    @staticmethod
    def _get_block_or_func(addr, blocks, external_addrs, function_manager, project, all_func_addrs=None):

        # should we get a block or a function?
        try:
            r = blocks[addr]
            # it's a block. just return it
            return r
        except KeyError:
            pass

        if addr in external_addrs:
            if project is not None and project.is_hooked(addr):
                # get a hook node instead
                r = HookNode(addr, 0, project.hooked_by(addr))
                return r
            if all_func_addrs is not None and addr in all_func_addrs:
                # get a function (which is yet to be created in the function manager)
                r = function_manager.function(addr=addr, create=True)
                return r
            else:
                # create a block
                # TODO: We are deciding the size by re-lifting the block from project. This is usually fine except for
                # TODO: the cases where the block does not exist in project (e.g., when the block was dynamically
                # TODO: created). The correct solution is to store the size and bytes of the block, too.
                if project is not None:
                    block = project.factory.block(addr)
                    block_size = block.size
                    bytestr = block.bytes
                else:
                    l.warning("The Project instance is not specified. Use a dummy block size of 1 byte for block %#x.",
                              addr)
                    block_size = 1
                    bytestr = b"\x00"
                r = BlockNode(addr, block_size, bytestr=bytestr)
                return r
        raise ValueError("Unsupported case: The block %#x is not in external_addrs and is not in local blocks. "
                         "This probably indicates a bug in angrdb generation.")

    @staticmethod
    def _get_func(addr, function_manager):
        func = function_manager.function(addr=addr, create=True)
        return func
