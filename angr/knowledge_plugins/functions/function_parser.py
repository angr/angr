import logging
import pickle

from collections import defaultdict

import angr.knowledge_plugins.functions.function

from ...codenode import BlockNode
from ...utils.enums_conv import func_edge_type_to_pb, func_edge_type_from_pb
from ...protos import primitives_pb2

l = logging.getLogger(name=__name__)


class FunctionParser():
    """
    The implementation of the serialization methods for the <Function> class.
    """
    @staticmethod
    def serialize(function):
        """
        :return :
        """
        obj = angr.knowledge_plugins.functions.function.Function._get_cmsg()
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

        # blocks
        blocks_list = [ b.serialize_to_cmessage() for b in function.blocks ]
        obj.blocks.extend(blocks_list)  # pylint:disable=no-member

        block_addrs_set = function.block_addrs_set
        # graph
        edges = []
        external_functions = set()
        TRANSITION_JK = func_edge_type_to_pb('transition')  # default edge type
        for src, dst, data in function.transition_graph.edges(data=True):
            edge = primitives_pb2.Edge()
            edge.src_ea = src.addr
            edge.dst_ea = dst.addr
            if src.addr not in block_addrs_set:
                # this is a Block in another function, or just another Function instance.
                external_functions.add(src.addr)
            if dst.addr not in block_addrs_set:
                external_functions.add(dst.addr)
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
        obj.external_functions.extend(external_functions)  # pylint:disable=no-member

        return obj

    @staticmethod
    def parse_from_cmsg(cmsg, function_manager=None, project=None):
        """
        :param cmsg: The data to instanciate the <Function> from.

        :return Function:
        """

        obj = angr.knowledge_plugins.functions.function.Function(
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

        # blocks
        blocks = dict(map(
            lambda block: (block.addr, block),
            map(
                lambda b: BlockNode(b.ea, b.size, bytestr=b.bytes),
                cmsg.blocks
            )
        ))
        external_functions = set(cmsg.external_functions)

        # edges
        edges = {}
        fake_return_edges = defaultdict(list)
        for edge_cmsg in cmsg.graph.edges:
            try:
                src = FunctionParser._get_block_or_func(
                    edge_cmsg.src_ea,
                    blocks,
                    external_functions,
                    function_manager
                )
            except KeyError:
                raise KeyError("Address of the edge source %#x is not found." % edge_cmsg.src_ea)
            try:
                dst = FunctionParser._get_block_or_func(
                    edge_cmsg.dst_ea,
                    blocks,
                    external_functions,
                    function_manager
                )
            except KeyError:
                raise KeyError("Address of the edge destination %#x is not found." % edge_cmsg.dst_ea)
            edge_type = func_edge_type_from_pb(edge_cmsg.jumpkind)
            assert edge_type is not None
            data = dict((k, pickle.loads(v)) for k, v in edge_cmsg.data.items())
            data['outside'] = edge_cmsg.is_outside
            data['ins_addr'] = edge_cmsg.ins_addr
            data['stmt_idx'] = edge_cmsg.stmt_idx
            if edge_type == 'fake_return':
                fake_return_edges[edge_cmsg.src_ea].append((src, dst, data))
            else:
                edges[(edge_cmsg.src_ea, edge_cmsg.dst_ea, edge_type)] = (src, dst, data)

        added_nodes = set()
        for k, v in edges.items():
            src_addr, dst_addr, edge_type = k
            src, dst, data = v

            outside = data.get('outside', False)
            ins_addr = data.get('ins_addr', None)
            stmt_idx = data.get('stmt_idx', None)
            added_nodes.add(src)
            added_nodes.add(dst)
            if edge_type == 'transition':
                obj._transit_to(src, dst, outside=outside, ins_addr=ins_addr, stmt_idx=stmt_idx)
            elif edge_type == 'call':
                # find the corresponding fake_ret edge
                fake_ret_edge = next(iter(edge_ for edge_ in fake_return_edges[src_addr]
                                          if edge_[1].addr == src.addr + src.size), None)
                if dst is None:
                    l.warning("The destination function %#x does not exist, and it cannot be created since function "
                              "manager is not provided. Please consider passing in a function manager to rebuild this "
                              "graph.", dst_addr)
                else:
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
    def _get_block_or_func(addr, blocks, external_functions, function_manager):
        try:
            block_or_func = blocks[addr]
        except KeyError:
            if addr in external_functions:
                if function_manager is not None:
                    block_or_func = function_manager.function(addr=addr, create=True)
                else:
                    # TODO:
                    block_or_func = None
            else:
                raise
        return block_or_func
