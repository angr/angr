"""Evidence-only discovery of bounded 16-bit x86 near-call tables.

The analysis recognizes reverse iterators whose bounds are supplied by direct
callers and whose entries are loaded from the module's automatic data segment.
The table is writable, so its initialized contents are candidate roots only:
this analysis deliberately does not resolve an indirect jump or mutate the CFG.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

import networkx

from angr.analyses.analysis import Analysis, register_analysis
from angr.errors import SimError

try:
    import pypcode

    from angr.engines import pcode
    from angr.engines.pcode.userop import (
        X86_PROTECTED_MODE_SEGMENT_USEROP_KEY,
        X86_REAL_MODE_SEGMENT_USEROP_KEY,
        get_named_userop_key,
        get_x86_segment_varnodes,
    )
except ImportError:
    pypcode = None
    pcode = None


_MAX_ENTRIES = 256
_MAX_REVERSE_BLOCKS = 32
_MAX_REVERSE_STEPS = 512
_FIXUP_WIDTHS = {0: 1, 2: 2, 3: 4, 5: 2}
_INTRA_FUNCTION_JUMPKINDS = {"Ijk_Boring", "Ijk_FakeRet"}
_X86_16_SEGMENT_USEROPS = (
    {
        X86_REAL_MODE_SEGMENT_USEROP_KEY,
        X86_PROTECTED_MODE_SEGMENT_USEROP_KEY,
    }
    if pypcode is not None
    else set()
)
_OVERLAPPING_REGISTER_WRITE = object()


@dataclass(frozen=True)
class NearCallTableCandidate:
    """One executable candidate root and the intentionally incomplete proof that produced it."""

    address: int
    proof: dict


@dataclass(frozen=True)
class _LoadOrigin:
    node: object
    operation_index: int


@dataclass(frozen=True)
class _CallTransitionProof:
    calling_convention: str
    preserved_registers: tuple[tuple[str, int, int], ...]


@dataclass(frozen=True)
class _ReverseIterator:
    load_node: object
    load_operation_index: int
    lower_register: tuple[str, int, int]
    pointer_register: tuple[str, int, int]
    target_register: tuple[str, int, int]
    entry_size: int
    call_transition: _CallTransitionProof


@dataclass(frozen=True)
class _DecodedInstruction:
    address: int
    data: bytes
    size: int
    mnemonic: str
    body: str


@dataclass(frozen=True)
class _NearIndirectCall:
    operation_index: int
    instruction: _DecodedInstruction
    target_register: tuple[str, int, int]
    target_register_name: str


def _varnode_key(varnode) -> tuple[str, int, int]:
    return varnode.space.name, int(varnode.offset), int(varnode.size)


def _mask(size: int) -> int:
    return (1 << (int(size) * 8)) - 1


def _definition(operations, varnode, before: int):
    definition = _definition_by_key(operations, _varnode_key(varnode), before)
    return None if definition is _OVERLAPPING_REGISTER_WRITE else definition


def _definition_by_key(operations, key: tuple[str, int, int], before: int):
    for index in range(before - 1, -1, -1):
        output = operations[index].output
        if output is None:
            continue
        output_key = _varnode_key(output)
        if output_key == key:
            return index, operations[index]
        if (
            key[0] == "register"
            and output_key[0] == "register"
            and output_key[1] < key[1] + key[2]
            and key[1] < output_key[1] + output_key[2]
        ):
            # A partial-register write kills the wider value even though the
            # P-code varnode keys are not identical (for example CL vs CX).
            return _OVERLAPPING_REGISTER_WRITE
    return None


def _registers_overlap(varnode, register: tuple[str, int, int]) -> bool:
    if varnode.space.name != register[0]:
        return False
    offset = int(varnode.offset)
    size = int(varnode.size)
    return offset < register[1] + register[2] and register[1] < offset + size


def _writes_register(operation, register: tuple[str, int, int]) -> bool:
    return operation.output is not None and _registers_overlap(operation.output, register)


def _is_segment_userop(project, operation) -> bool:
    if operation.opcode != pypcode.OpCode.CALLOTHER:
        return False
    try:
        return get_named_userop_key(project.arch.name, operation) in _X86_16_SEGMENT_USEROPS
    except ValueError:
        return False


def _affine_register_expression(
    operations,
    varnode,
    before: int,
    seen: frozenset[tuple[int, tuple[str, int, int]]] = frozenset(),
):
    """Return ``(root register, scale, offset)`` for a small exact affine expression."""

    if varnode.space.name == "const":
        return None, 0, int(varnode.offset)

    marker = before, _varnode_key(varnode)
    if marker in seen:
        return None
    definition = _definition(operations, varnode, before)
    if definition is None:
        return (_varnode_key(varnode), 1, 0) if varnode.space.name == "register" else None
    index, operation = definition
    seen = seen | {marker}

    if operation.opcode in {pypcode.OpCode.COPY, pypcode.OpCode.CAST, pypcode.OpCode.INT_ZEXT}:
        if len(operation.inputs) != 1 or operation.inputs[0].size != operation.output.size:
            return None
        return _affine_register_expression(operations, operation.inputs[0], index, seen)

    if operation.opcode not in {pypcode.OpCode.INT_ADD, pypcode.OpCode.INT_SUB} or len(operation.inputs) != 2:
        return None
    left = _affine_register_expression(operations, operation.inputs[0], index, seen)
    right = _affine_register_expression(operations, operation.inputs[1], index, seen)
    if left is None or right is None:
        return None
    left_root, left_scale, left_offset = left
    right_root, right_scale, right_offset = right
    if left_root is not None and right_root is not None and left_root != right_root:
        return None
    sign = -1 if operation.opcode == pypcode.OpCode.INT_SUB else 1
    return (
        left_root if left_root is not None else right_root,
        left_scale + sign * right_scale,
        left_offset + sign * right_offset,
    )


class PcodeX86NearCallTableCandidates(Analysis):
    """Find initialized candidate roots from bounded reverse near-call-table iterators."""

    def __init__(self, cfg, *, max_entries: int = _MAX_ENTRIES):
        self.cfg = cfg
        self.candidates: list[NearCallTableCandidate] = []
        self.proofs: list[dict] = []
        self._block_cache = {}
        if (
            pypcode is None
            or pcode is None
            or self.project.arch.bits != 16
            or self.project.arch.name not in {key[0] for key in _X86_16_SEGMENT_USEROPS}
            or not 0 < max_entries <= _MAX_ENTRIES
        ):
            return
        self._collect(max_entries)

    def _collect(self, max_entries: int) -> None:
        for block_addr, jump in sorted((getattr(self.cfg, "indirect_jumps", {}) or {}).items()):
            if str(getattr(jump, "jumpkind", "")) != "Ijk_Call":
                continue
            proof = self._proof(int(block_addr), int(jump.func_addr), max_entries)
            if proof is None:
                continue
            self.proofs.append(proof)
            self.candidates.extend(NearCallTableCandidate(target, proof) for target in proof["cs_executable_targets"])

    def _proof(self, block_addr: int, function_addr: int, max_entries: int):
        call_node = self._unique_node(block_addr, function_addr)
        entry_node = self._unique_node(function_addr, function_addr)
        if call_node is None or entry_node is None:
            return None
        local_graph = self._bounded_local_graph(call_node, function_addr)
        if local_graph is None or entry_node not in local_graph:
            return None

        call = self._near_indirect_call(call_node)
        if call is None:
            return None
        origin = self._reaching_load(
            call_node,
            call.operation_index,
            call.target_register,
            local_graph,
            frozenset(),
        )
        if origin is None:
            return None
        iterator = self._reverse_iterator(entry_node, call_node, call.target_register, origin, local_graph)
        if iterator is None:
            return None

        lower_register_name = self._register_name(iterator.lower_register)
        pointer_register_name = self._register_name(iterator.pointer_register)
        if lower_register_name is None or pointer_register_name is None:
            return None

        callers = self._direct_caller_bounds(
            entry_node,
            function_addr,
            iterator.lower_register,
            iterator.pointer_register,
        )
        if not callers:
            return None
        pairs = [(caller["lower"], caller["upper"]) for caller in callers]
        offsets = self._bounded_table_offsets(pairs, iterator.entry_size, max_entries)
        if offsets is None:
            return None

        segments = self._table_segments(call.instruction.address)
        if segments is None:
            return None
        cs_segment, ds_segment, automatic_data_segment = segments
        cs_segment_number = getattr(cs_segment, "segment_number", None)
        if not isinstance(cs_segment_number, int) or cs_segment_number < 0:
            return None
        locations = [int(ds_segment.min_addr) + offset for offset in offsets]
        if any(
            not ds_segment.contains_addr(location) or not ds_segment.contains_addr(location + iterator.entry_size - 1)
            for location in locations
        ):
            return None
        if self._overlaps_fixup(locations, iterator.entry_size):
            return None

        main = self.project.loader.main_object
        mapped_base = int(main.mapped_base)
        values = []
        targets = []
        zero_offsets = []
        try:
            for offset, location in zip(offsets, locations, strict=True):
                value = int(
                    self.project.loader.memory.unpack_word(
                        location,
                        size=iterator.entry_size,
                        endness=self.project.arch.memory_endness,
                    )
                )
                values.append(value)
                if value == 0:
                    zero_offsets.append(offset)
                    continue
                target = int(cs_segment.min_addr) + value
                if self.project.loader.main_object.find_segment_containing(target) is not cs_segment:
                    return None
                targets.append(target)
        except (KeyError, TypeError, ValueError):
            return None

        return {
            "site": call.instruction.address,
            "cfg_block_address": int(call_node.addr),
            "call_instruction_address": call.instruction.address,
            "call_instruction_bytes": call.instruction.data.hex(),
            "call_instruction_size": call.instruction.size,
            "call_instruction_mnemonic": call.instruction.mnemonic,
            "target_offset_register_name": call.target_register_name,
            "target_offset_register_range": list(call.target_register[1:]),
            "cs_segment_number": cs_segment_number,
            "pointer_register_name": pointer_register_name,
            "pointer_register_range": list(iterator.pointer_register[1:]),
            "lower_register_name": lower_register_name,
            "lower_register_range": list(iterator.lower_register[1:]),
            "fake_return_calling_convention": iterator.call_transition.calling_convention,
            "fake_return_preserved_registers": [
                {"name": name, "range": [offset, size]}
                for name, offset, size in iterator.call_transition.preserved_registers
            ],
            "function": function_addr,
            "direct_callers": callers,
            "direct_caller_bound_pairs": pairs,
            "automatic_data_segment": automatic_data_segment,
            "automatic_data_segment_rva": int(ds_segment.min_addr) - mapped_base,
            "cs_segment_rva": int(cs_segment.min_addr) - mapped_base,
            "entry_size": iterator.entry_size,
            "ds_table_offsets": offsets,
            "ds_table_locations": locations,
            "ds_table_values": values,
            "zero_entry_offsets_skipped": zero_offsets,
            "cs_executable_targets": sorted(set(targets)),
            "fixup_overlap_rejected": False,
            "dynamic": True,
            "completeness": False,
            "reason": "writable-automatic-ds-reverse-near-call-table",
        }

    def _block(self, node):
        key = int(node.addr), int(node.size)
        if key not in self._block_cache:
            try:
                block = self.project.factory.block(*key)
            except (KeyError, SimError, TypeError, ValueError):
                block = None
            if block is not None and not isinstance(block.vex, pcode.lifter.IRSB):
                block = None
            self._block_cache[key] = block
        return self._block_cache[key]

    def _unique_node(self, address: int, function_addr: int):
        nodes = [
            node
            for node in self.cfg.model.get_all_nodes(address)
            if int(getattr(node, "function_address", -1)) == function_addr and int(getattr(node, "size", 0)) > 0
        ]
        return nodes[0] if len(nodes) == 1 else None

    def _bounded_local_graph(self, call_node, function_addr: int):
        model_graph = self.cfg.model.graph
        worklist = deque([call_node])
        nodes = {call_node}
        edges = []
        while worklist:
            node = worklist.popleft()
            incident_edges = [*model_graph.in_edges(node), *model_graph.out_edges(node)]
            for source, destination in incident_edges:
                neighbor = source if destination is node else destination
                if (
                    int(getattr(neighbor, "function_address", -1)) != function_addr
                    or int(getattr(neighbor, "size", 0)) <= 0
                ):
                    continue
                data = model_graph.get_edge_data(source, destination) or {}
                if data.get("jumpkind") not in _INTRA_FUNCTION_JUMPKINDS:
                    continue
                edges.append((source, destination))
                if neighbor not in nodes:
                    if len(nodes) >= _MAX_REVERSE_BLOCKS:
                        return None
                    nodes.add(neighbor)
                    worklist.append(neighbor)
        graph = networkx.DiGraph()
        graph.add_nodes_from(nodes)
        graph.add_edges_from(edges)
        return graph

    def _near_indirect_call(self, node):
        block = self._block(node)
        if block is None:
            return None
        operations = block.vex._ops
        if not operations or operations[-1].opcode != pypcode.OpCode.CALLIND or len(operations[-1].inputs) != 1:
            return None
        definition = _definition(operations, operations[-1].inputs[0], len(operations) - 1)
        if definition is None or not _is_segment_userop(self.project, definition[1]):
            return None
        try:
            _, segment_node, offset_node = get_x86_segment_varnodes(definition[1])
        except ValueError:
            return None
        cs = ("register", *map(int, self.project.arch.registers["cs"]))
        if _varnode_key(segment_node) != cs or offset_node.space.name != "register":
            return None
        target_register = _varnode_key(offset_node)
        if target_register[2] != self.project.arch.bytes:
            return None
        target_register_name = self._register_name(target_register)
        if target_register_name is None:
            return None
        instruction = self._decoded_final_instruction(node, len(operations) - 1)
        if instruction is None or instruction.body.casefold() != target_register_name.casefold():
            return None
        return _NearIndirectCall(
            len(operations) - 1,
            instruction,
            target_register,
            target_register_name,
        )

    def _decoded_final_instruction(self, node, operation_index: int) -> _DecodedInstruction | None:
        """Decode the final machine instruction identified by the exact preceding IMARK."""

        block = self._block(node)
        if block is None:
            return None
        operations = block.vex._ops
        if operation_index != len(operations) - 1 or operation_index <= 0:
            return None
        imarks = [operation for operation in operations[:operation_index] if operation.opcode == pypcode.OpCode.IMARK]
        if not imarks or len(imarks[-1].inputs) != 1:
            return None
        marker = imarks[-1].inputs[0]
        if marker.space.name != "ram":
            return None
        address = int(marker.offset)
        size = int(marker.size)
        if size <= 0 or address < int(node.addr) or address + size != int(node.addr) + int(node.size):
            return None

        try:
            data = bytes(self.project.loader.memory.load(address, size))
            disassembly = pypcode.Context(self.project.arch.name).disassemble(
                data,
                base_address=address,
                max_instructions=1,
            )
        except (
            KeyError,
            OverflowError,
            TypeError,
            ValueError,
            pypcode.BadDataError,
            pypcode.DecoderError,
            pypcode.LowlevelError,
            pypcode.UnimplError,
        ):
            return None
        if len(data) != size or len(disassembly.instructions) != 1:
            return None
        instruction = disassembly.instructions[0]
        mnemonic = str(instruction.mnem).upper()
        if (
            instruction.addr.space.name != marker.space.name
            or int(instruction.addr.offset) != address
            or int(instruction.length) != size
            or mnemonic != "CALL"
        ):
            return None
        return _DecodedInstruction(address, data, size, mnemonic, str(instruction.body).strip())

    def _register_name(self, register: tuple[str, int, int]) -> str | None:
        if register[0] != "register":
            return None
        register_range = register[1:]
        names = [
            name
            for name, candidate_range in self.project.arch.registers.items()
            if tuple(map(int, candidate_range)) == register_range
        ]
        if len(names) != 1:
            return None
        name = names[0]
        return name if tuple(map(int, self.project.arch.registers[name])) == register_range else None

    def _call_transition_proof(
        self,
        graph,
        call_node,
        call_operation_index: int,
        required_registers: tuple[tuple[str, int, int], ...],
    ) -> _CallTransitionProof | None:
        """Prove the one FakeRet transition cannot hide relevant call clobbers."""

        fake_return_edges = [
            (source, destination)
            for source, destination in graph.edges
            if (self.cfg.model.graph.get_edge_data(source, destination) or {}).get("jumpkind") == "Ijk_FakeRet"
        ]
        if len(fake_return_edges) != 1 or fake_return_edges[0][0] is not call_node:
            return None

        call_opcodes = {pypcode.OpCode.CALL, pypcode.OpCode.CALLIND}
        for node in graph:
            block = self._block(node)
            if block is None:
                return None
            for index, operation in enumerate(block.vex._ops):
                if operation.opcode in call_opcodes and (node is not call_node or index != call_operation_index):
                    return None

        try:
            calling_convention = self.project.factory.cc()
        except (KeyError, TypeError, ValueError):
            return None
        caller_saved_names = getattr(calling_convention, "CALLER_SAVED_REGS", None)
        if not isinstance(caller_saved_names, (list, tuple, set, frozenset)):
            return None
        caller_saved_ranges = []
        for name in caller_saved_names:
            candidate_range = self.project.arch.registers.get(name)
            if candidate_range is None:
                return None
            caller_saved_ranges.append(tuple(map(int, candidate_range)))

        preserved_registers = []
        for register in required_registers:
            name = self._register_name(register)
            if name is None:
                return None
            offset, size = register[1:]
            if any(
                caller_offset < offset + size and offset < caller_offset + caller_size
                for caller_offset, caller_size in caller_saved_ranges
            ):
                return None
            preserved_registers.append((name, offset, size))
        return _CallTransitionProof(type(calling_convention).__name__, tuple(preserved_registers))

    def _reaching_load(self, node, before: int, key, graph, seen) -> _LoadOrigin | None:
        marker = int(node.addr), int(node.size), before, key
        if marker in seen or len(seen) >= _MAX_REVERSE_STEPS:
            return None
        seen = seen | {marker}
        block = self._block(node)
        if block is None:
            return None
        operations = block.vex._ops
        definition = _definition_by_key(operations, key, before)
        if definition is _OVERLAPPING_REGISTER_WRITE:
            return None
        if definition is not None:
            index, operation = definition
            if operation.opcode == pypcode.OpCode.LOAD and operation.output.size == self.project.arch.bytes:
                return _LoadOrigin(node, index)
            if (
                operation.opcode in {pypcode.OpCode.COPY, pypcode.OpCode.CAST, pypcode.OpCode.INT_ZEXT}
                and len(operation.inputs) == 1
                and operation.inputs[0].size == operation.output.size
            ):
                return self._reaching_load(node, index, _varnode_key(operation.inputs[0]), graph, seen)
            return None
        if key[0] != "register":
            return None
        predecessors = sorted(graph.predecessors(node), key=lambda predecessor: (predecessor.addr, predecessor.size))
        if not predecessors:
            return None
        origins = [
            self._reaching_load(
                predecessor,
                len(self._block(predecessor).vex._ops),
                key,
                graph,
                seen,
            )
            if self._block(predecessor) is not None
            else None
            for predecessor in predecessors
        ]
        if any(origin is None for origin in origins):
            return None
        first = origins[0]
        return first if all(origin == first for origin in origins[1:]) else None

    def _reverse_iterator(self, entry_node, call_node, target_register, origin, graph):
        block = self._block(origin.node)
        if block is None:
            return None
        operations = block.vex._ops
        load = operations[origin.operation_index]
        if load.opcode != pypcode.OpCode.LOAD or len(load.inputs) != 2 or load.output.size != self.project.arch.bytes:
            return None
        address_definition = _definition(operations, load.inputs[1], origin.operation_index)
        if address_definition is None or not _is_segment_userop(self.project, address_definition[1]):
            return None
        address_index, address_operation = address_definition
        try:
            _, segment_node, offset_node = get_x86_segment_varnodes(address_operation)
        except ValueError:
            return None
        ds = ("register", *map(int, self.project.arch.registers["ds"]))
        if _varnode_key(segment_node) != ds or offset_node.space.name != "register":
            return None
        pointer_register = _varnode_key(offset_node)
        entry_size = int(load.output.size)
        affine = _affine_register_expression(operations, offset_node, address_index)
        if affine != (pointer_register, 1, -entry_size):
            return None

        guards = []
        for node in graph:
            lower_register = self._range_guard(node, origin.node, pointer_register, graph)
            if lower_register is not None:
                guards.append((node, lower_register))
        if len(guards) != 1:
            return None
        guard_node, lower_register = guards[0]
        try:
            dominators = networkx.immediate_dominators(graph, entry_node)
        except networkx.NetworkXError:
            return None
        cursor = origin.node
        while cursor in dominators and cursor != dominators[cursor] and cursor != guard_node:
            cursor = dominators[cursor]
        if cursor != guard_node or not networkx.has_path(graph, origin.node, guard_node):
            return None

        if guard_node is not entry_node:
            if not networkx.has_path(graph, entry_node, guard_node):
                return None
            preheader_nodes = ({entry_node} | networkx.descendants(graph, entry_node)) & (
                {guard_node} | networkx.ancestors(graph, guard_node)
            )
            preheader_nodes.discard(guard_node)
            for node in preheader_nodes:
                preheader_block = self._block(node)
                if preheader_block is None or any(
                    _writes_register(operation, lower_register) or _writes_register(operation, pointer_register)
                    for operation in preheader_block.vex._ops
                ):
                    return None

        component = next((part for part in networkx.strongly_connected_components(graph) if origin.node in part), set())
        if guard_node not in component or call_node not in component:
            return None
        ds = ("register", *map(int, self.project.arch.registers["ds"]))
        call_transition = self._call_transition_proof(
            graph,
            call_node,
            len(self._block(call_node).vex._ops) - 1,
            (ds, lower_register, pointer_register),
        )
        if call_transition is None:
            return None
        writes_to_pointer = []
        for node in component:
            loop_block = self._block(node)
            if loop_block is None:
                return None
            for index, operation in enumerate(loop_block.vex._ops):
                if _writes_register(operation, lower_register):
                    return None
                if _writes_register(operation, pointer_register):
                    writes_to_pointer.append((node, index))
        if not writes_to_pointer or any(
            node is not origin.node or index >= address_index for node, index in writes_to_pointer
        ):
            return None
        if not self._has_exact_zero_skip(origin, call_node, target_register, graph):
            return None
        return _ReverseIterator(
            origin.node,
            origin.operation_index,
            lower_register,
            pointer_register,
            target_register,
            entry_size,
            call_transition,
        )

    def _range_guard(self, node, load_node, pointer_register, graph):
        branch = self._conditional_branch(node)
        if branch is None:
            return None
        _branch_index, comparison, inverted, taken, fallthrough = branch
        comparison_index, operation = comparison
        if operation.opcode != pypcode.OpCode.INT_LESS or len(operation.inputs) != 2:
            return None
        block = self._block(node)
        left = _affine_register_expression(block.vex._ops, operation.inputs[0], comparison_index)
        right = _affine_register_expression(block.vex._ops, operation.inputs[1], comparison_index)
        if left is None or right != (pointer_register, 1, 0) or left[1:] != (1, 0):
            return None
        lower_register = left[0]
        if lower_register is None or lower_register == pointer_register or lower_register[2] != self.project.arch.bytes:
            return None
        less_successor, exhausted_successor = (fallthrough, taken) if inverted else (taken, fallthrough)
        reduced = graph.copy()
        reduced.remove_node(node)
        if less_successor not in reduced or not networkx.has_path(reduced, less_successor, load_node):
            return None
        if exhausted_successor in reduced and networkx.has_path(reduced, exhausted_successor, load_node):
            return None
        return lower_register

    def _has_exact_zero_skip(self, origin, call_node, target_register, graph) -> bool:
        load_node = origin.node
        for node in graph:
            branch = self._conditional_branch(node)
            if branch is None:
                continue
            _branch_index, comparison, inverted, taken, fallthrough = branch
            comparison_index, operation = comparison
            if operation.opcode != pypcode.OpCode.INT_EQUAL or len(operation.inputs) != 2:
                continue
            left, right = operation.inputs
            if left.space.name == "const":
                left, right = right, left
            if (
                _varnode_key(left) != target_register
                or right.space.name != "const"
                or int(right.offset) != 0
                or int(right.size) != target_register[2]
            ):
                continue
            if self._reaching_load(node, comparison_index, target_register, graph, frozenset()) != origin:
                continue
            if node is load_node:
                load_block = self._block(load_node)
                if load_block is None or comparison_index <= origin.operation_index:
                    continue
                if any(
                    _writes_register(candidate, target_register) and _varnode_key(candidate.output) != target_register
                    for candidate in load_block.vex._ops[origin.operation_index + 1 : comparison_index]
                ):
                    continue
            else:
                # Every load-to-call path must traverse the zero test. Merely
                # finding a zero branch on one path is insufficient because an
                # earlier branch may bypass it and call zero or a stale value.
                without_test = graph.copy()
                without_test.remove_node(node)
                if any(
                    successor == call_node
                    or (
                        successor in without_test
                        and call_node in without_test
                        and networkx.has_path(without_test, successor, call_node)
                    )
                    for successor in graph.successors(load_node)
                ):
                    continue
            zero_successor, nonzero_successor = (fallthrough, taken) if inverted else (taken, fallthrough)
            reduced = graph.copy()
            reduced.remove_node(node)
            if nonzero_successor not in reduced or not networkx.has_path(reduced, nonzero_successor, call_node):
                continue
            if zero_successor in reduced and networkx.has_path(reduced, zero_successor, call_node):
                continue
            corridor = ({nonzero_successor} | networkx.descendants(reduced, nonzero_successor)) & (
                {call_node} | networkx.ancestors(reduced, call_node)
            )
            if any(
                _writes_register(operation, target_register)
                for corridor_node in corridor
                for operation in self._block(corridor_node).vex._ops
                if self._block(corridor_node) is not None
            ):
                continue
            return True
        return False

    def _conditional_branch(self, node):
        block = self._block(node)
        if block is None:
            return None
        operations = block.vex._ops
        if not operations or operations[-1].opcode != pypcode.OpCode.CBRANCH or len(operations[-1].inputs) != 2:
            return None
        definition = _definition(operations, operations[-1].inputs[1], len(operations) - 1)
        if definition is None:
            return None
        inverted = False
        comparison = definition
        if definition[1].opcode == pypcode.OpCode.BOOL_NEGATE:
            if len(definition[1].inputs) != 1:
                return None
            inverted = True
            comparison = _definition(operations, definition[1].inputs[0], definition[0])
            if comparison is None:
                return None
        target = int(operations[-1].inputs[0].offset)
        successors = sorted(self._bounded_successors(node), key=lambda successor: successor.addr)
        taken = [successor for successor in successors if int(successor.addr) == target]
        fallthrough = [successor for successor in successors if int(successor.addr) != target]
        if len(taken) != 1 or len(fallthrough) != 1:
            return None
        return len(operations) - 1, comparison, inverted, taken[0], fallthrough[0]

    def _bounded_successors(self, node):
        graph = self.cfg.model.graph
        return [
            successor
            for successor in graph.successors(node)
            if (graph.get_edge_data(node, successor) or {}).get("jumpkind") in _INTRA_FUNCTION_JUMPKINDS
            and int(getattr(successor, "function_address", -1)) == int(node.function_address)
        ]

    def _direct_caller_bounds(self, entry_node, function_addr, lower_register, upper_register):
        graph = self.cfg.model.graph
        incoming = []
        for caller_node in graph.predecessors(entry_node):
            data = graph.get_edge_data(caller_node, entry_node) or {}
            if data.get("jumpkind") != "Ijk_Call" or int(caller_node.function_address) == function_addr:
                continue
            direct_call = self._direct_call(caller_node, function_addr)
            if direct_call is None:
                return None
            call_index, callsite = direct_call
            lower = self._constant_at(
                caller_node, call_index, lower_register, int(caller_node.function_address), frozenset()
            )
            upper = self._constant_at(
                caller_node, call_index, upper_register, int(caller_node.function_address), frozenset()
            )
            if lower is None or upper is None:
                return None
            incoming.append({"site": callsite, "lower": lower, "upper": upper})
        return sorted(incoming, key=lambda caller: caller["site"])

    def _direct_call(self, node, function_addr: int):
        block = self._block(node)
        if block is None:
            return None
        operations = block.vex._ops
        if not operations or operations[-1].opcode != pypcode.OpCode.CALL or len(operations[-1].inputs) != 1:
            return None
        target = operations[-1].inputs[0]
        if target.space.name != "ram" or int(target.offset) != function_addr:
            return None
        instruction = self._decoded_final_instruction(node, len(operations) - 1)
        if instruction is None:
            return None
        try:
            decoded_target = int(instruction.body, 0)
        except ValueError:
            return None
        if decoded_target != function_addr:
            return None
        return len(operations) - 1, instruction.address

    def _constant_at(self, node, before, key, function_addr, seen):
        marker = int(node.addr), int(node.size), before, key
        if marker in seen or len(seen) >= _MAX_REVERSE_STEPS:
            return None
        seen = seen | {marker}
        if len({item[:2] for item in seen}) > _MAX_REVERSE_BLOCKS:
            return None
        block = self._block(node)
        if block is None:
            return None
        operations = block.vex._ops
        definition = _definition_by_key(operations, key, before)
        if definition is _OVERLAPPING_REGISTER_WRITE:
            return None
        if definition is None:
            if key[0] != "register":
                return None
            predecessors = []
            for predecessor in self.cfg.model.graph.predecessors(node):
                data = self.cfg.model.graph.get_edge_data(predecessor, node) or {}
                if (
                    data.get("jumpkind") == "Ijk_Boring"
                    and int(getattr(predecessor, "function_address", -1)) == function_addr
                ):
                    predecessors.append(predecessor)
            if not predecessors:
                return None
            values = [
                self._constant_at(
                    predecessor,
                    len(self._block(predecessor).vex._ops),
                    key,
                    function_addr,
                    seen,
                )
                if self._block(predecessor) is not None
                else None
                for predecessor in predecessors
            ]
            return (
                values[0] if values and values[0] is not None and all(value == values[0] for value in values) else None
            )
        index, operation = definition
        return self._constant_operation(node, index, operation, function_addr, seen)

    def _constant_varnode(self, node, before, varnode, function_addr, seen):
        if varnode.space.name == "const":
            return int(varnode.offset) & _mask(varnode.size)
        return self._constant_at(node, before, _varnode_key(varnode), function_addr, seen)

    def _constant_operation(self, node, index, operation, function_addr, seen):
        inputs = operation.inputs
        output_mask = _mask(operation.output.size)
        if operation.opcode in {pypcode.OpCode.COPY, pypcode.OpCode.CAST, pypcode.OpCode.INT_ZEXT}:
            if len(inputs) != 1:
                return None
            value = self._constant_varnode(node, index, inputs[0], function_addr, seen)
            return None if value is None else value & output_mask
        if operation.opcode == pypcode.OpCode.INT_SEXT and len(inputs) == 1:
            value = self._constant_varnode(node, index, inputs[0], function_addr, seen)
            if value is None:
                return None
            input_bits = int(inputs[0].size) * 8
            signed = value - (1 << input_bits) if value & (1 << (input_bits - 1)) else value
            return signed & output_mask
        if len(inputs) != 2:
            return None
        left = self._constant_varnode(node, index, inputs[0], function_addr, seen)
        right = self._constant_varnode(node, index, inputs[1], function_addr, seen)
        if left is None or right is None:
            return None
        if operation.opcode == pypcode.OpCode.INT_ADD:
            value = left + right
        elif operation.opcode == pypcode.OpCode.INT_SUB:
            value = left - right
        elif operation.opcode == pypcode.OpCode.INT_MULT:
            value = left * right
        elif operation.opcode == pypcode.OpCode.INT_LEFT:
            value = left << right
        elif operation.opcode == pypcode.OpCode.INT_RIGHT:
            value = left >> right
        elif operation.opcode == pypcode.OpCode.INT_AND:
            value = left & right
        elif operation.opcode == pypcode.OpCode.INT_OR:
            value = left | right
        elif operation.opcode == pypcode.OpCode.INT_XOR:
            value = left ^ right
        else:
            return None
        return value & output_mask

    @staticmethod
    def _bounded_table_offsets(pairs, entry_size: int, max_entries: int):
        offsets = set()
        for lower, upper in pairs:
            if (
                not 0 <= lower <= 0xFFFF
                or not 0 <= upper <= 0xFFFF
                or lower > upper
                or lower % entry_size
                or upper % entry_size
            ):
                return None
            count = (upper - lower) // entry_size
            if count > max_entries:
                return None
            offsets.update(range(lower, upper, entry_size))
            if len(offsets) > max_entries:
                return None
        return sorted(offsets)

    def _table_segments(self, site: int):
        main = self.project.loader.main_object
        automatic_data_segment = getattr(main, "automatic_data_segment", None)
        if not isinstance(automatic_data_segment, int) or automatic_data_segment <= 0:
            return None
        ds_segments = [
            segment
            for segment in getattr(main, "segments", ())
            if int(getattr(segment, "segment_number", -1)) == automatic_data_segment
        ]
        if len(ds_segments) != 1:
            return None
        ds_segment = ds_segments[0]
        cs_segment = main.find_segment_containing(site)
        if (
            cs_segment is None
            or not cs_segment.is_executable
            or not ds_segment.is_readable
            or not ds_segment.is_writable
            or ds_segment.is_executable
        ):
            return None
        return cs_segment, ds_segment, automatic_data_segment

    def _overlaps_fixup(self, locations, entry_size: int) -> bool:
        table_bytes = {byte for location in locations for byte in range(location, location + entry_size)}
        main = self.project.loader.main_object
        mapped_base = int(main.mapped_base)
        for fixup in getattr(main, "fixups", ()):
            width = _FIXUP_WIDTHS.get(int(getattr(fixup, "source_type", -1)))
            if width is None:
                return True
            for rva in getattr(fixup, "source_rvas", ()):
                address = mapped_base + int(rva)
                if any(byte in table_bytes for byte in range(int(address), int(address) + width)):
                    return True
        return False


register_analysis(PcodeX86NearCallTableCandidates, "PcodeX86NearCallTableCandidates")


__all__ = ("NearCallTableCandidate", "PcodeX86NearCallTableCandidates")
