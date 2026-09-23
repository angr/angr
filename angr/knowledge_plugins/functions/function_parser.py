# pylint:disable=no-member,raise-missing-from,protected-access
from __future__ import annotations

import json
import logging

import angr
from angr.calling_conventions import CC_NAMES, SimCC, SimCCUsercall
from angr.protos import function_pb2
from angr.rustylib.function_graph import FunctionGraph
from angr.sim_type import SimType, SimTypeFunction
from angr.utils.types import make_type_reference, type_collections_for_lib

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
        obj = angr.knowledge_plugins.Function._get_cmsg()
        obj.ea = function.addr
        obj.is_entrypoint = False  # TODO: Set this up accordingly
        obj.name = function.name
        obj.is_default_name = function.is_default_name
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
            # convert library-defined structs in the prototype to typerefs; Function.prototype dereferences them lazily
            prototype_ref = make_type_reference(
                function.prototype, type_collections=type_collections_for_lib(function.prototype_libname)
            )
            obj.prototype = json.dumps(prototype_ref.to_json()).encode("utf-8")
        obj.prototype_libname = (function.prototype_libname or "").encode()
        obj.prototype_source = function.prototype_source.value
        obj.info = function.info.to_json().encode("utf-8") if function.info else b""
        obj.ran_cca = function.ran_cca
        obj.previous_names.extend(function.previous_names)

        # signature matched?
        if not function.from_signature:
            obj.matched_from = function_pb2.Function.UNMATCHED
        else:
            if function.from_signature == "flirt":
                obj.matched_from = function_pb2.Function.FLIRT
            else:
                raise ValueError(
                    f"Cannot convert from_signature {function.from_signature} into a SignatureSource enum."
                )

        # blocks, graph, endpoints, external references and call sites
        obj.graph_blob = function._graph.to_bytes()

        return obj

    @staticmethod
    def local_block_addrs_from_cmsg(cmsg) -> set[int]:
        """
        The addresses of the local blocks of a serialized function, without building the Function.
        """
        if cmsg.graph_blob:
            return set(FunctionGraph.local_block_addrs_from_bytes(cmsg.graph_blob))
        from angr.angrdb.v1 import AngrDbV1  # pylint:disable=import-outside-toplevel

        return AngrDbV1.local_block_addrs(cmsg)

    @staticmethod
    def parse_from_cmsg(cmsg, function_manager=None, project=None, meta_only: bool = False):
        """
        :param cmsg: The data to instantiate the <Function> from.

        :return Function:
        """
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

        returning = None
        if cmsg.HasField("returning"):
            returning = cmsg.returning

        obj = angr.knowledge_plugins.functions.Function(
            function_manager,
            cmsg.ea,
            name=cmsg.name,
            is_plt=cmsg.is_plt,
            syscall=cmsg.is_syscall,
            is_simprocedure=cmsg.is_simprocedure,
            returning=returning,
            alignment=cmsg.alignment,
            binary_name=None if not cmsg.binary_name else cmsg.binary_name,
            calling_convention=cc,
            prototype=proto,
            prototype_libname=cmsg.prototype_libname or None,
            prototype_source=angr.knowledge_plugins.functions.PrototypeSource(cmsg.prototype_source),
        )
        obj._project = project
        obj.normalized = cmsg.normalized
        obj.info = json.loads(cmsg.info.decode("utf-8")) if cmsg.info else {}
        obj.is_default_name = cmsg.is_default_name
        obj.ran_cca = cmsg.ran_cca
        obj.previous_names = list(cmsg.previous_names)

        # signature matched?
        # set the backing slot directly so that loading a function from LMDB does not mark it dirty or
        # trigger the FunctionManager cache hook
        if cmsg.matched_from == function_pb2.Function.UNMATCHED:
            obj._from_signature = None
        elif cmsg.matched_from == function_pb2.Function.FLIRT:
            obj._from_signature = "flirt"
        else:
            raise ValueError(f"Cannot convert SignatureSource enum {cmsg.matched_from} to Function.from_signature.")

        if cmsg.graph_blob:
            graph = FunctionGraph.from_bytes(cmsg.graph_blob)
            if graph.func_addr != cmsg.ea:
                raise ValueError(f"Function graph of {graph.func_addr:#x} stored under {cmsg.ea:#x}")
            obj._graph = graph
            obj._block_addrs_cache = None
            if meta_only:
                obj.meta_only = True  # can't be serialized again when evicted from the cache
            else:
                obj.update_func_block_count()
            obj._dirty = False
            return obj

        # no blob: a version-1 angrdb record (per-block / per-edge layout)
        from angr.angrdb.v1 import AngrDbV1  # pylint:disable=import-outside-toplevel

        return AngrDbV1.parse_function(cmsg, obj, project, meta_only)
