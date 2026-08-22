from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

import networkx

from angr.knowledge_plugins.cfg import IndirectJumpType, JumptableResolutionEvidence

from .resolver import IndirectJumpResolver

try:
    import pypcode

    from angr.engines import pcode
except ImportError:
    pypcode = None
    pcode = None

if TYPE_CHECKING:
    from collections.abc import Sequence


l = logging.getLogger(__name__)

_MAX_FINITE_VALUES = 256
_RESOLVER_NAME = "angr.PcodeX86JumpTableResolver"
_PREDECESSOR_BOUND_PROOF = "pcode-predecessor-unsigned-upper-bound"
_FINITE_DOMAIN_PROOF = "pcode-finite-value-domain"


@dataclass(frozen=True)
class _AffineExpression:
    root: tuple[str, int, int] | None
    scale: int
    offset: int


@dataclass(frozen=True)
class _TableLoad:
    table_offset: int
    entry_size: int
    index_root: tuple[str, int, int] | None


def _varnode_key(varnode) -> tuple[str, int, int]:
    return varnode.space.name, int(varnode.offset), int(varnode.size)


def _is_constant(varnode) -> bool:
    return varnode.space.name == "const"


def _mask(size: int) -> int:
    return (1 << (int(size) * 8)) - 1


def _definition(ops: Sequence, varnode, before: int):
    key = _varnode_key(varnode)
    for index in range(before - 1, -1, -1):
        output = ops[index].output
        if output is not None and _varnode_key(output) == key:
            return index, ops[index]
    return None


def _covering_definition(ops: Sequence, varnode, before: int):
    """Find a same-offset wider register definition for a subregister read."""

    if varnode.space.name != "register":
        return None
    key = _varnode_key(varnode)
    for index in range(before - 1, -1, -1):
        output = ops[index].output
        if output is None:
            continue
        output_key = _varnode_key(output)
        if output_key[0] == key[0] and output_key[1] == key[1] and output_key[2] > key[2]:
            return index, output
    return None


def _constant_value(
    ops: Sequence, varnode, before: int, seen: frozenset[tuple[int, tuple[str, int, int]]] = frozenset()
):
    if _is_constant(varnode):
        return int(varnode.offset) & _mask(varnode.size)

    marker = (before, _varnode_key(varnode))
    if marker in seen:
        return None
    definition = _definition(ops, varnode, before)
    if definition is None:
        return None
    index, operation = definition
    seen = seen | {marker}
    opcode = operation.opcode
    inputs = operation.inputs

    if opcode in {
        pypcode.OpCode.COPY,
        pypcode.OpCode.CAST,
        pypcode.OpCode.INT_ZEXT,
    }:
        return _constant_value(ops, inputs[0], index, seen)
    if opcode == pypcode.OpCode.INT_SEXT:
        value = _constant_value(ops, inputs[0], index, seen)
        if value is None:
            return None
        input_bits = int(inputs[0].size) * 8
        sign_bit = 1 << (input_bits - 1)
        signed_value = value - (1 << input_bits) if value & sign_bit else value
        return signed_value & _mask(operation.output.size)

    if len(inputs) != 2:
        return None
    left = _constant_value(ops, inputs[0], index, seen)
    right = _constant_value(ops, inputs[1], index, seen)
    if left is None or right is None:
        return None
    result_mask = _mask(operation.output.size)
    if opcode == pypcode.OpCode.INT_ADD:
        return (left + right) & result_mask
    if opcode == pypcode.OpCode.INT_SUB:
        return (left - right) & result_mask
    if opcode == pypcode.OpCode.INT_MULT:
        return (left * right) & result_mask
    if opcode == pypcode.OpCode.INT_LEFT:
        return (left << right) & result_mask
    if opcode == pypcode.OpCode.INT_RIGHT:
        return (left >> right) & result_mask
    if opcode == pypcode.OpCode.INT_AND:
        return left & right
    if opcode == pypcode.OpCode.INT_OR:
        return left | right
    return None


def _finite_values(
    ops: Sequence,
    varnode,
    before: int,
    seen: frozenset[tuple[int, tuple[str, int, int]]] = frozenset(),
    initial_values: dict[tuple[str, int, int], frozenset[int]] | None = None,
    load_callback=None,
) -> frozenset[int] | None:
    """Evaluate a p-code value exactly when its complete domain is small.

    An undefined one-byte value has only 256 possible values and is therefore
    still finite. Wider undefined values fail closed. This is useful for table
    indices narrowed by masks and logical shifts without pretending that a
    mutable byte loaded from memory is constant.
    """

    if _is_constant(varnode):
        return frozenset({int(varnode.offset) & _mask(varnode.size)})

    marker = (before, _varnode_key(varnode))
    if marker in seen:
        return None
    definition = _definition(ops, varnode, before)
    if definition is None:
        covering = _covering_definition(ops, varnode, before)
        if covering is not None:
            index, output = covering
            values = _finite_values(ops, output, index + 1, seen | {marker}, initial_values, load_callback)
            if values is None:
                return None
            return frozenset(value & _mask(varnode.size) for value in values)
        if initial_values is not None and _varnode_key(varnode) in initial_values:
            return initial_values[_varnode_key(varnode)]
        domain_size = 1 << (int(varnode.size) * 8)
        if domain_size > _MAX_FINITE_VALUES:
            return None
        return frozenset(range(domain_size))

    index, operation = definition
    if operation.output is None:
        return None
    seen = seen | {marker}
    opcode = operation.opcode
    inputs = operation.inputs
    output_mask = _mask(operation.output.size)

    def recur(node, at=index):
        return _finite_values(ops, node, at, seen, initial_values, load_callback)

    if opcode == pypcode.OpCode.LOAD:
        if load_callback is not None:
            values = load_callback(operation, index, seen)
            if values is not None:
                return values
        domain_size = 1 << (int(operation.output.size) * 8)
        if domain_size > _MAX_FINITE_VALUES:
            return None
        return frozenset(range(domain_size))

    if opcode in {pypcode.OpCode.COPY, pypcode.OpCode.CAST, pypcode.OpCode.INT_ZEXT}:
        values = recur(inputs[0])
        if values is None:
            return None
        return frozenset(value & output_mask for value in values)

    if opcode == pypcode.OpCode.INT_SEXT:
        values = recur(inputs[0])
        if values is None:
            return None
        input_bits = int(inputs[0].size) * 8
        sign_bit = 1 << (input_bits - 1)
        return frozenset(((value - (1 << input_bits)) if value & sign_bit else value) & output_mask for value in values)

    if opcode in {pypcode.OpCode.INT_NEGATE, pypcode.OpCode.INT_2COMP}:
        values = recur(inputs[0])
        if values is None:
            return None
        if opcode == pypcode.OpCode.INT_NEGATE:
            return frozenset((~value) & output_mask for value in values)
        return frozenset((-value) & output_mask for value in values)

    if opcode == pypcode.OpCode.SUBPIECE and len(inputs) == 2:
        values = recur(inputs[0])
        byte_offset = _constant_value(ops, inputs[1], index, seen)
        if values is None or byte_offset is None:
            return None
        return frozenset((value >> (byte_offset * 8)) & output_mask for value in values)

    if len(inputs) != 2:
        return None
    if opcode in {pypcode.OpCode.INT_SUB, pypcode.OpCode.INT_XOR} and _varnode_key(inputs[0]) == _varnode_key(
        inputs[1]
    ):
        return frozenset({0})
    left = recur(inputs[0])
    right = recur(inputs[1])
    if left is None or right is None:
        return None

    input_bits = int(inputs[0].size) * 8
    input_sign_bit = 1 << (input_bits - 1)
    results: set[int] = set()
    for left_value in left:
        for right_value in right:
            if opcode == pypcode.OpCode.INT_ADD:
                result = left_value + right_value
            elif opcode == pypcode.OpCode.INT_SUB:
                result = left_value - right_value
            elif opcode == pypcode.OpCode.INT_MULT:
                result = left_value * right_value
            elif opcode == pypcode.OpCode.INT_LEFT:
                result = left_value << right_value
            elif opcode == pypcode.OpCode.INT_RIGHT:
                result = left_value >> right_value
            elif opcode == pypcode.OpCode.INT_SRIGHT:
                signed_left = left_value - (1 << input_bits) if left_value & input_sign_bit else left_value
                result = signed_left >> right_value
            elif opcode == pypcode.OpCode.INT_AND:
                result = left_value & right_value
            elif opcode == pypcode.OpCode.INT_OR:
                result = left_value | right_value
            elif opcode == pypcode.OpCode.INT_XOR:
                result = left_value ^ right_value
            else:
                return None
            results.add(result & output_mask)
            if len(results) > _MAX_FINITE_VALUES:
                return None
    return frozenset(results)


def _combine_affine(left: _AffineExpression, right: _AffineExpression, *, subtract: bool = False):
    if left.root is not None and right.root is not None and left.root != right.root:
        return None
    right_sign = -1 if subtract else 1
    return _AffineExpression(
        left.root if left.root is not None else right.root,
        left.scale + right_sign * right.scale,
        left.offset + right_sign * right.offset,
    )


def _affine_expression(
    ops: Sequence,
    varnode,
    before: int,
    seen: frozenset[tuple[int, tuple[str, int, int]]] = frozenset(),
):
    if _is_constant(varnode):
        return _AffineExpression(None, 0, int(varnode.offset))

    marker = (before, _varnode_key(varnode))
    if marker in seen:
        return None
    definition = _definition(ops, varnode, before)
    if definition is None:
        return _AffineExpression(_varnode_key(varnode), 1, 0)
    index, operation = definition
    seen = seen | {marker}
    opcode = operation.opcode
    inputs = operation.inputs

    if opcode in {
        pypcode.OpCode.COPY,
        pypcode.OpCode.CAST,
        pypcode.OpCode.INT_ZEXT,
    }:
        return _affine_expression(ops, inputs[0], index, seen)

    if opcode in {pypcode.OpCode.INT_ADD, pypcode.OpCode.INT_SUB}:
        left = _affine_expression(ops, inputs[0], index, seen)
        right = _affine_expression(ops, inputs[1], index, seen)
        if left is None or right is None:
            return None
        return _combine_affine(left, right, subtract=opcode == pypcode.OpCode.INT_SUB)

    if opcode in {pypcode.OpCode.INT_MULT, pypcode.OpCode.INT_LEFT}:
        left = _affine_expression(ops, inputs[0], index, seen)
        right = _constant_value(ops, inputs[1], index, seen)
        if left is None or right is None:
            return None
        factor = right if opcode == pypcode.OpCode.INT_MULT else 1 << right
        return _AffineExpression(left.root, left.scale * factor, left.offset * factor)

    return None


def _match_leq_condition(ops: Sequence, condition, before: int):
    """Match the p-code expansion of an unsigned ``value <= constant`` test."""

    inverted = False
    definition = _definition(ops, condition, before)
    if definition is None:
        return None
    index, operation = definition
    if operation.opcode == pypcode.OpCode.BOOL_NEGATE:
        inverted = True
        definition = _definition(ops, operation.inputs[0], index)
        if definition is None:
            return None
        index, operation = definition
    if operation.opcode != pypcode.OpCode.BOOL_OR:
        return None

    children = []
    for child in operation.inputs:
        child_definition = _definition(ops, child, index)
        if child_definition is None:
            return None
        children.append(child_definition)

    less = next((item for item in children if item[1].opcode == pypcode.OpCode.INT_LESS), None)
    equal = next((item for item in children if item[1].opcode == pypcode.OpCode.INT_EQUAL), None)
    if less is None or equal is None:
        return None

    less_index, less_op = less
    value, bound_node = less_op.inputs
    if not _is_constant(bound_node):
        return None
    bound = int(bound_node.offset)

    equal_index, equal_op = equal
    if len(equal_op.inputs) != 2:
        return None
    zero_index = next((i for i, node in enumerate(equal_op.inputs) if _is_constant(node) and node.offset == 0), None)
    if zero_index is None:
        return None
    subtraction_node = equal_op.inputs[1 - zero_index]
    subtraction = _definition(ops, subtraction_node, equal_index)
    if subtraction is None or subtraction[1].opcode != pypcode.OpCode.INT_SUB:
        return None
    subtraction_op = subtraction[1]
    if (
        _varnode_key(subtraction_op.inputs[0]) != _varnode_key(value)
        or not _is_constant(subtraction_op.inputs[1])
        or int(subtraction_op.inputs[1].offset) != bound
    ):
        return None

    # The compare must not be stale: the bounded register reaches the jump-table
    # block unchanged after the flag-producing operations.
    value_key = _varnode_key(value)
    if any(
        item.output is not None and _varnode_key(item.output) == value_key
        for item in ops[max(less_index, subtraction[0]) + 1 : before]
    ):
        return None
    return value_key, bound, inverted


class PcodeX86JumpTableResolver(IndirectJumpResolver):
    """Resolve bounded 16-bit x86 near jump tables from p-code facts.

    This resolver is deliberately fail-closed. It accepts either a unique
    predecessor proving an unsigned upper bound or a completely enumerable
    finite index domain. The finite proof can use an inductive stack-byte
    invariant and loader-backed bytes from the automatic data segment, but it
    rejects relocated lookup bytes, overlapping stack assignments, sparse
    table offsets, and any domain larger than 256 values. Every final table
    entry must resolve to executable memory; table length is never guessed by
    scanning adjacent words.
    """

    def __init__(self, project):
        super().__init__(project, timeless=False)

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        del cfg, addr, func_addr
        return bool(
            pcode is not None
            and pypcode is not None
            and isinstance(block.vex, pcode.lifter.IRSB)
            and jumpkind == "Ijk_Boring"
            and self.project.arch.bits == 16
            and self.project.arch.name.startswith("x86:")
        )

    def _table_address_expression(self, block):
        ops = block.vex._ops
        if not ops or ops[-1].opcode != pypcode.OpCode.BRANCHIND or len(ops[-1].inputs) != 1:
            return None

        target_definition = _definition(ops, ops[-1].inputs[0], len(ops))
        if target_definition is None or target_definition[1].opcode != pypcode.OpCode.CALLOTHER:
            return None
        target_index, target_op = target_definition
        if len(target_op.inputs) != 3:
            return None

        load_definition = _definition(ops, target_op.inputs[2], target_index)
        if load_definition is None or load_definition[1].opcode != pypcode.OpCode.LOAD:
            return None
        load_index, load_op = load_definition
        if len(load_op.inputs) != 2 or load_op.output is None:
            return None

        address_definition = _definition(ops, load_op.inputs[1], load_index)
        if address_definition is None or address_definition[1].opcode != pypcode.OpCode.CALLOTHER:
            return None
        address_index, address_op = address_definition
        if len(address_op.inputs) != 3:
            return None

        cs_offset, cs_size = self.project.arch.registers["cs"]
        cs_key = ("register", int(cs_offset), int(cs_size))
        if _varnode_key(target_op.inputs[1]) != cs_key or _varnode_key(address_op.inputs[1]) != cs_key:
            return None

        return ops, address_op.inputs[2], address_index, int(load_op.output.size)

    def _table_load(self, block) -> _TableLoad | None:
        expression = self._table_address_expression(block)
        if expression is None:
            return None
        ops, address, address_index, entry_size = expression

        affine = _affine_expression(ops, address, address_index)
        if (
            affine is None
            or affine.root is None
            or affine.scale != entry_size
            or affine.offset < 0
            or affine.offset > 0xFFFF
        ):
            return None
        return _TableLoad(affine.offset, entry_size, affine.root)

    @staticmethod
    def _segmented_offset_expression(ops: Sequence, address, before: int):
        definition = _definition(ops, address, before)
        if definition is None or definition[1].opcode != pypcode.OpCode.CALLOTHER:
            return None
        index, operation = definition
        if len(operation.inputs) != 3:
            return None
        return _varnode_key(operation.inputs[1]), operation.inputs[2], index

    def _incoming_register_values(
        self,
        cfg,
        block_addr: int,
        func_addr: int,
        register_key: tuple[str, int, int],
        active: frozenset[tuple[int, tuple[str, int, int]]] = frozenset(),
    ) -> frozenset[int] | None:
        marker = block_addr, register_key
        if marker in active:
            return None
        nodes = [node for node in cfg.model.get_all_nodes(block_addr) if node.function_address == func_addr]
        if len(nodes) != 1:
            return None
        predecessors = list(cfg.model.graph.predecessors(nodes[0]))
        if not predecessors or any(predecessor.function_address != func_addr for predecessor in predecessors):
            return None

        values: set[int] = set()
        active = active | {marker}
        for predecessor in predecessors:
            pred_block = self.project.factory.block(predecessor.addr, size=predecessor.size)
            ops = pred_block.vex._ops
            definition = next(
                (
                    (index, operation.output)
                    for index in range(len(ops) - 1, -1, -1)
                    if (operation := ops[index]).output is not None and _varnode_key(operation.output) == register_key
                ),
                None,
            )
            if definition is None:
                pred_values = self._incoming_register_values(cfg, predecessor.addr, func_addr, register_key, active)
            else:
                index, output = definition
                pred_values = _finite_values(ops, output, index + 1)
            if pred_values is None:
                return None
            values.update(pred_values)
            if len(values) > _MAX_FINITE_VALUES:
                return None
        return frozenset(values)

    def _initial_register_values(self, cfg, addr: int, func_addr: int, ops: Sequence):
        register_keys = {
            _varnode_key(varnode)
            for operation in ops
            for varnode in operation.inputs
            if varnode.space.name == "register"
        }
        values = {}
        for register_key in register_keys:
            incoming = self._incoming_register_values(cfg, addr, func_addr, register_key)
            if incoming is not None:
                values[register_key] = incoming
        return values

    def _stack_byte_domain(
        self,
        cfg,
        addr: int,
        func_addr: int,
        slot: tuple[tuple[str, int, int], tuple[str, int, int], int],
        load_index: int,
    ) -> frozenset[int] | None:
        function = cfg.functions.get_by_addr(func_addr)
        graph = function.graph
        entry_nodes = [node for node in graph if node.addr == func_addr]
        target_nodes = [node for node in graph if node.addr == addr]
        if len(entry_nodes) != 1 or len(target_nodes) != 1:
            return None
        try:
            dominators = networkx.immediate_dominators(graph, entry_nodes[0])
        except networkx.NetworkXError:
            return None

        def dominates(dominator, node):
            while node != dominator:
                parent = dominators.get(node)
                if parent is None or parent == node:
                    return False
                node = parent
            return True

        has_initializer = False
        assigned_values: set[int] = set()
        for node in graph:
            candidate_block = self.project.factory.block(node.addr, size=node.size)
            candidate_ops = candidate_block.vex._ops
            for index, operation in enumerate(candidate_ops):
                if operation.opcode != pypcode.OpCode.STORE or len(operation.inputs) != 3:
                    continue
                address = self._segmented_offset_expression(candidate_ops, operation.inputs[1], index)
                if address is None:
                    continue
                segment_key, offset_node, offset_before = address
                affine = _affine_expression(candidate_ops, offset_node, offset_before)
                if affine is None or affine.root is None or (segment_key, affine.root) != slot[:2]:
                    continue
                stored_size = int(operation.inputs[2].size)
                stored_offsets = {(affine.offset + byte_index) & 0xFFFF for byte_index in range(stored_size)}
                if slot[2] not in stored_offsets:
                    continue
                if affine.offset != slot[2] or stored_size != 1:
                    return None
                values = _finite_values(candidate_ops, operation.inputs[2], index)
                if values is None or any(value > 0xF for value in values):
                    return None
                assigned_values.update(values)
                if (node != target_nodes[0] and dominates(node, target_nodes[0])) or (
                    node == target_nodes[0] and index < load_index
                ):
                    has_initializer = True
        if not has_initializer or not assigned_values:
            return None
        # The exact iteration count is immaterial. Every assignment preserves
        # this inductive nibble invariant, so expose the full proven domain.
        return frozenset(range(0x10))

    def _finite_load_callback(self, cfg, addr: int, func_addr: int, ops: Sequence, initial_values):
        arch = self.project.arch
        ds_offset, ds_size = arch.registers["ds"]
        ss_offset, ss_size = arch.registers["ss"]
        ds_key = ("register", int(ds_offset), int(ds_size))
        ss_key = ("register", int(ss_offset), int(ss_size))

        main = self.project.loader.main_object
        data_segment_number = getattr(main, "automatic_data_segment", None)
        segments_by_number = getattr(main, "segments_by_number", {})
        data_segment = segments_by_number.get(data_segment_number)
        fixup_source_bytes = set()
        fixup_widths = {0x00: 1, 0x02: 2, 0x03: 4, 0x05: 2}
        for fixup in getattr(main, "fixups", ()):
            width = fixup_widths.get(int(getattr(fixup, "source_type", -1)), 4)
            for source_rva in getattr(fixup, "source_rvas", ()):
                fixup_source_bytes.update(range(int(source_rva), int(source_rva) + width))

        def callback(operation, index, seen):
            if operation.output is None or int(operation.output.size) != 1 or len(operation.inputs) != 2:
                return None
            address = self._segmented_offset_expression(ops, operation.inputs[1], index)
            if address is None:
                return None
            segment_key, offset_node, offset_before = address
            if segment_key == ss_key:
                affine = _affine_expression(ops, offset_node, offset_before)
                if affine is None or affine.root is None:
                    return None
                return self._stack_byte_domain(
                    cfg,
                    addr,
                    func_addr,
                    (segment_key, affine.root, affine.offset),
                    index,
                )
            if segment_key != ds_key or data_segment is None:
                return None

            offsets = _finite_values(ops, offset_node, offset_before, seen, initial_values, callback)
            if offsets is None:
                return None
            values = set()
            for offset in offsets:
                if offset < 0 or offset >= int(data_segment.initialized_size):
                    return None
                physical_address = int(data_segment.vaddr) + offset
                if physical_address in fixup_source_bytes:
                    return None
                try:
                    values.add(self.project.loader.memory.load(physical_address, 1)[0])
                except (KeyError, TypeError, ValueError):
                    return None
            return frozenset(values)

        return callback

    def _finite_table_load(self, cfg, addr: int, func_addr: int, block) -> tuple[_TableLoad, int] | None:
        expression = self._table_address_expression(block)
        if expression is None:
            return None
        ops, address, address_index, entry_size = expression
        initial_values = self._initial_register_values(cfg, addr, func_addr, ops)
        load_callback = self._finite_load_callback(cfg, addr, func_addr, ops, initial_values)
        offsets = _finite_values(
            ops, address, address_index, initial_values=initial_values, load_callback=load_callback
        )
        if offsets is None or not offsets or len(offsets) > cfg._indirect_jump_target_limit:
            return None

        ordered_offsets = sorted(offsets)
        table_offset = ordered_offsets[0]
        expected_offsets = list(range(table_offset, table_offset + len(ordered_offsets) * entry_size, entry_size))
        if ordered_offsets != expected_offsets:
            return None
        return _TableLoad(table_offset, entry_size, None), len(ordered_offsets)

    def _entry_count(self, cfg, addr: int, func_addr: int, index_root: tuple[str, int, int]) -> int | None:
        nodes = [node for node in cfg.model.get_all_nodes(addr) if node.function_address == func_addr]
        if len(nodes) != 1:
            return None
        node = nodes[0]
        predecessors = list(cfg.model.graph.predecessors(node))
        if len(predecessors) != 1:
            return None
        predecessor = predecessors[0]
        pred_block = self.project.factory.block(predecessor.addr, size=predecessor.size)
        ops = pred_block.vex._ops
        branch_index = next(
            (index for index in range(len(ops) - 1, -1, -1) if ops[index].opcode == pypcode.OpCode.CBRANCH),
            None,
        )
        if branch_index is None or len(ops[branch_index].inputs) != 2:
            return None
        branch = ops[branch_index]
        match = _match_leq_condition(ops, branch.inputs[1], branch_index)
        if match is None:
            return None
        compared_root, bound, condition_inverted = match
        if compared_root != index_root:
            return None

        branch_target = int(branch.inputs[0].offset)
        if branch_target == addr:
            path_accepts_leq = not condition_inverted
        elif int(predecessor.addr) + int(predecessor.size) == addr:
            path_accepts_leq = condition_inverted
        else:
            return None
        if not path_accepts_leq:
            return None

        count = bound + 1
        if count <= 0 or count > cfg._indirect_jump_target_limit:
            return None
        return count

    def resolve(self, cfg, addr, func_addr, block, jumpkind, func_graph_complete: bool = True, **kwargs):
        del jumpkind, func_graph_complete, kwargs
        table_load = self._table_load(block)
        if table_load is not None:
            assert table_load.index_root is not None
            count = self._entry_count(cfg, addr, func_addr, table_load.index_root)
            if count is None:
                return False, None
            proof = _PREDECESSOR_BOUND_PROOF
        else:
            finite_table_load = self._finite_table_load(cfg, addr, func_addr, block)
            if finite_table_load is None:
                return False, None
            table_load, count = finite_table_load
            proof = _FINITE_DOMAIN_PROOF

        segment_size = 1 << self.project.arch.bits
        segment_base = int(addr) & ~(segment_size - 1)
        table_size = count * table_load.entry_size
        if table_load.table_offset + table_size > segment_size:
            return False, None
        table_addr = segment_base + table_load.table_offset

        targets = []
        try:
            for index in range(count):
                entry = self.project.loader.memory.unpack_word(
                    table_addr + index * table_load.entry_size,
                    size=table_load.entry_size,
                    endness=self.project.arch.memory_endness,
                )
                target = segment_base + int(entry)
                if not self._is_target_valid(cfg, target):
                    return False, None
                targets.append(target)
        except (KeyError, TypeError, ValueError):
            return False, None

        indirect_jump = cfg.indirect_jumps.get(addr)
        if indirect_jump is not None:
            indirect_jump.jumptable = len(set(targets)) > 1
            indirect_jump.add_jumptable(
                table_addr,
                table_size,
                table_load.entry_size,
                targets,
                is_primary=True,
                entries_guessed=False,
                resolution_evidence=JumptableResolutionEvidence(_RESOLVER_NAME, proof),
            )
            indirect_jump.resolved_targets = set(targets)
            indirect_jump.type = IndirectJumpType.Jumptable_AddressLoadedFromMemory

        l.info("Resolved p-code jump table at %#x with %d entries using %s", addr, count, proof)
        return True, targets
