# pylint:disable=no-member,raise-missing-from,protected-access
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

import angr
from angr.calling_conventions import CC_NAMES, SimCC, SimCCUsercall
from angr.protos import function_pb2
from angr.rustylib.function_graph import FunctionGraph  # pylint:disable=import-error,no-name-in-module
from angr.sim_type import SimType, SimTypeFunction
from angr.utils.types import make_type_reference, type_collections_for_lib

if TYPE_CHECKING:
    from .function import PrototypeSource

l = logging.getLogger(name=__name__)

# Function.info is tiny and highly repetitive (e.g. {"bp_as_gpr": true}); memoize its decoding across loads.
# Only flat dicts of immutable values are cached, so a shallow copy fully isolates each Function's info.
_INFO_SCALARS = (str, int, float, bool, type(None))
_INFO_CACHE_MAX = 256
_info_cache: dict[bytes, dict] = {}


def _decode_info(raw: bytes) -> dict:
    cached = _info_cache.get(raw)
    if cached is not None:
        return cached.copy()
    data = json.loads(raw.decode("utf-8"))
    if (
        isinstance(data, dict)
        and len(_info_cache) < _INFO_CACHE_MAX
        and all(isinstance(v, _INFO_SCALARS) for v in data.values())
    ):
        _info_cache[raw] = data.copy()
    return data


_prototype_sources: dict[int, PrototypeSource] = {}


def _prototype_source(value: int) -> PrototypeSource:
    source = _prototype_sources.get(value)
    if source is None:
        source = angr.knowledge_plugins.functions.PrototypeSource(value)
        _prototype_sources[value] = source
    return source


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
        if cc.x87_args:
            return {"t": cc.__class__.__name__, "x87_args": cc.x87_args}
        return {"t": cc.__class__.__name__}

    @staticmethod
    def from_json(data: dict, arch) -> SimCC | None:
        cc_type = data.get("t")
        if cc_type == "SimCCUsercall":
            return SimCCUsercall(arch, [], None)  # TODO: Deserialize the rest of the fields
        if cc_type not in CC_NAMES:
            l.warning("Unknown calling convention type %s", cc_type)
            return None
        cc = CC_NAMES[cc_type](arch)
        cc.x87_args = data.get("x87_args", 0)
        return cc


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
        obj.prototype = FunctionParser._serialize_prototype(function.prototype, function.prototype_libname)
        obj.prototype_libname = (function.prototype_libname or "").encode()
        obj.prototype_source = function.prototype_source.value
        # the default-flavor prototype lives in the fields above; every other flavor is stored separately
        for flavor, proto in function.prototypes.items():
            if flavor == angr.knowledge_plugins.functions.DEFAULT_FLAVOR:
                continue
            flavored = obj.flavored_prototypes.add()
            flavored.flavor = flavor
            flavored.prototype = FunctionParser._serialize_prototype(proto, function.prototype_libname)
            flavored.prototype_source = function.prototype_sources[flavor].value
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

        obj.graph_blob = function._graph.to_bytes()

        return obj

    @staticmethod
    def local_block_addrs_from_cmsg(cmsg) -> set[int]:
        """
        Get the addresses of the local blocks of a serialized function without building the Function object.
        """
        if cmsg.graph_blob:
            return set(FunctionGraph.local_block_addrs_from_bytes(cmsg.graph_blob))
        from angr.angrdb.v1 import AngrDbV1  # pylint:disable=import-outside-toplevel

        return AngrDbV1.local_block_addrs(cmsg)

    @staticmethod
    def _serialize_prototype(proto: SimTypeFunction | None, libname: str | None) -> bytes:
        if proto is None:
            return b""
        # convert library-defined structs in the prototype to typerefs; Function dereferences them lazily
        prototype_ref = make_type_reference(proto, type_collections=type_collections_for_lib(libname))
        return json.dumps(prototype_ref.to_json()).encode("utf-8")

    @staticmethod
    def _parse_prototype(raw: bytes, project) -> SimTypeFunction | None:
        if not raw:
            return None
        proto = SimType.from_json(json.loads(raw.decode("utf-8")))
        if not isinstance(proto, SimTypeFunction):
            l.warning("Unexpected type of function prototype deserialized: %s", type(proto))
            return None
        if project is None:
            return None  # we cannot assign an arch-less prototype to a function
        return proto.with_arch(project.arch)

    @staticmethod
    def parse_from_cmsg(cmsg, function_manager=None, project=None, meta_only: bool = False):
        """
        :param cmsg: The data to instantiate the <Function> from.

        :return Function:
        """
        proto = FunctionParser._parse_prototype(cmsg.prototype, project)

        cc = (
            CallingConventionSerializer.from_json(json.loads(cmsg.calling_convention.decode("utf-8")), project.arch)
            if cmsg.calling_convention and project is not None
            else None
        )

        returning = None
        if cmsg.HasField("returning"):
            returning = cmsg.returning

        if cmsg.graph_blob:
            graph = FunctionGraph.from_bytes(cmsg.graph_blob)
            if graph.func_addr != cmsg.ea:
                raise ValueError(f"Function graph of {graph.func_addr:#x} stored under {cmsg.ea:#x}")
        else:
            graph = FunctionGraph(cmsg.ea)

        # every stored field is known, so skip Function.__init__ (which would derive them from the project again)
        function_cls = angr.knowledge_plugins.functions.Function
        obj = function_cls.__new__(function_cls)
        obj._init_slots(
            function_manager,
            cmsg.ea,
            graph,
            cc,
            proto,
            cmsg.prototype_libname or None,
            _prototype_source(cmsg.prototype_source),
            cmsg.alignment,
        )
        obj._is_syscall = cmsg.is_syscall
        obj._is_simprocedure = cmsg.is_simprocedure
        obj._is_plt = cmsg.is_plt
        obj._name = cmsg.name
        obj.binary_name = cmsg.binary_name or obj._get_initial_binary_name()
        if returning is not None:
            obj.returning = returning
        for flavored in cmsg.flavored_prototypes:
            obj.set_prototype(
                flavored.flavor,
                FunctionParser._parse_prototype(flavored.prototype, project),
                source=_prototype_source(flavored.prototype_source),
            )
        if cmsg.is_syscall or cmsg.is_simprocedure:
            # a SimProcedure (or syscall) overrides the stored prototype and calling convention
            obj._init_prototype_and_calling_convention()
        obj._project = project
        obj.normalized = cmsg.normalized
        if cmsg.info:
            info = _decode_info(cmsg.info)
            obj._info.data = info
            if function_manager is not None:
                for key, value in info.items():
                    if key.startswith("is_") and value is True:
                        function_manager.add_key_func_addr(key[3:], cmsg.ea)
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
            obj._block_addrs_cache = None
            if meta_only:
                obj.meta_only = True  # can't be serialized again when evicted from the cache
            else:
                obj.update_func_block_count()
            obj._dirty = False
            return obj

        # Fall back to angrDb V1 legacy function record.
        from angr.angrdb.v1 import AngrDbV1  # pylint:disable=import-outside-toplevel

        return AngrDbV1.parse_function(cmsg, obj, project, meta_only)
