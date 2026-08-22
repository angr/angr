from __future__ import annotations

from dataclasses import dataclass

import networkx

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


_X86_16_SEGMENT_USEROPS = (
    {
        X86_REAL_MODE_SEGMENT_USEROP_KEY,
        X86_PROTECTED_MODE_SEGMENT_USEROP_KEY,
    }
    if pypcode is not None
    else set()
)


@dataclass(frozen=True)
class _SegmentedMemorySlot:
    segment_register: tuple[int, int]
    offset: int
    size: int


@dataclass(frozen=True)
class _EntryMemoryPop:
    slot: _SegmentedMemorySlot
    address_index: int
    store_index: int


@dataclass(frozen=True)
class _BranchMemory:
    slot: _SegmentedMemorySlot
    address_index: int
    load_index: int


@dataclass(frozen=True)
class PcodeX86ReturnThunk:
    """Machine-level evidence for a near return implemented through a popped continuation token."""

    function_addr: int
    entry_addr: int
    jump_addr: int
    token_kind: str
    token_register: tuple[int, int] | None = None
    token_segment_register: tuple[int, int] | None = None
    token_memory_offset: int | None = None
    token_size: int | None = None


def _varnode_key(varnode) -> tuple[str, int, int]:
    return varnode.space.name, int(varnode.offset), int(varnode.size)


def _definition(ops, varnode, before: int):
    key = _varnode_key(varnode)
    for index in range(before - 1, -1, -1):
        output = ops[index].output
        if output is not None and _varnode_key(output) == key:
            return index, ops[index]
    return None


def _registers_overlap(varnode, register: tuple[int, int]) -> bool:
    if varnode.space.name != "register":
        return False
    offset, size = register
    return int(varnode.offset) < offset + size and offset < int(varnode.offset) + int(varnode.size)


def _writes_register(operation, register: tuple[int, int]) -> bool:
    return operation.output is not None and _registers_overlap(operation.output, register)


def _is_segment_userop(project, operation) -> bool:
    if operation.opcode != pypcode.OpCode.CALLOTHER:
        return False
    try:
        return get_named_userop_key(project.arch.name, operation) in _X86_16_SEGMENT_USEROPS
    except ValueError:
        return False


def _copy_source_is(ops, varnode, before: int, source_key: tuple[str, int, int], seen=frozenset()) -> bool:
    key = _varnode_key(varnode)
    if key == source_key:
        return True
    marker = before, key
    if marker in seen:
        return False
    definition = _definition(ops, varnode, before)
    if definition is None:
        return False
    index, operation = definition
    if (
        operation.opcode != pypcode.OpCode.COPY
        or operation.output is None
        or len(operation.inputs) != 1
        or operation.inputs[0].size != operation.output.size
    ):
        return False
    return _copy_source_is(ops, operation.inputs[0], index, source_key, seen | {marker})


def _constant_from_partial_register_writes(ops, varnode, before: int) -> int | None:
    if varnode.space.name != "register":
        return None

    target_start = int(varnode.offset)
    target_size = int(varnode.size)
    byte_values: dict[int, int] = {}
    for operation in reversed(ops[:before]):
        output = operation.output
        if output is None or output.space.name != "register":
            continue
        output_start = int(output.offset)
        output_size = int(output.size)
        overlap_start = max(target_start, output_start)
        overlap_end = min(target_start + target_size, output_start + output_size)
        uncovered = [address for address in range(overlap_start, overlap_end) if address not in byte_values]
        if not uncovered:
            continue
        if (
            operation.opcode != pypcode.OpCode.COPY
            or len(operation.inputs) != 1
            or operation.inputs[0].space.name != "const"
        ):
            return None
        value = int(operation.inputs[0].offset)
        for address in uncovered:
            byte_values[address] = (value >> ((address - output_start) * 8)) & 0xFF
        if len(byte_values) == target_size:
            return sum(byte_values[target_start + index] << (index * 8) for index in range(target_size))
    return None


def _constant_value(ops, varnode, before: int, seen=frozenset()) -> int | None:
    if varnode.space.name == "const":
        return int(varnode.offset)

    key = _varnode_key(varnode)
    marker = before, key
    if marker in seen:
        return None
    definition = _definition(ops, varnode, before)
    if definition is None:
        return _constant_from_partial_register_writes(ops, varnode, before)
    index, operation = definition
    next_seen = seen | {marker}

    if operation.opcode in {
        pypcode.OpCode.COPY,
        pypcode.OpCode.INT_ZEXT,
        pypcode.OpCode.INT_SEXT,
    }:
        if len(operation.inputs) != 1:
            return None
        value = _constant_value(ops, operation.inputs[0], index, next_seen)
    elif operation.opcode in {
        pypcode.OpCode.INT_ADD,
        pypcode.OpCode.INT_SUB,
        pypcode.OpCode.INT_AND,
        pypcode.OpCode.INT_OR,
    }:
        if len(operation.inputs) != 2:
            return None
        left = _constant_value(ops, operation.inputs[0], index, next_seen)
        right = _constant_value(ops, operation.inputs[1], index, next_seen)
        if left is None or right is None:
            return None
        if operation.opcode == pypcode.OpCode.INT_ADD:
            value = left + right
        elif operation.opcode == pypcode.OpCode.INT_SUB:
            value = left - right
        elif operation.opcode == pypcode.OpCode.INT_AND:
            value = left & right
        else:
            value = left | right
    else:
        return None

    output = operation.output
    if output is None or value is None:
        return None
    return value & ((1 << (int(output.size) * 8)) - 1)


def _segmented_memory_slot(project, ops, address, before: int, size: int):
    address_definition = _definition(ops, address, before)
    if address_definition is None:
        return None
    address_index, address_operation = address_definition
    if not _is_segment_userop(project, address_operation):
        return None
    try:
        _, segment_node, offset_node = get_x86_segment_varnodes(address_operation)
    except ValueError:
        return None
    if segment_node.space.name != "register" or int(segment_node.size) != project.arch.bytes:
        return None
    offset = _constant_value(ops, offset_node, address_index)
    if offset is None:
        return None
    return (
        _SegmentedMemorySlot(
            (int(segment_node.offset), int(segment_node.size)),
            offset,
            size,
        ),
        address_index,
    )


def _copy_origin(ops, varnode, before: int, seen=frozenset()):
    key = _varnode_key(varnode)
    marker = before, key
    if marker in seen:
        return None
    definition = _definition(ops, varnode, before)
    if definition is None:
        return None
    index, operation = definition
    if (
        operation.opcode == pypcode.OpCode.COPY
        and operation.output is not None
        and len(operation.inputs) == 1
        and operation.inputs[0].size == operation.output.size
    ):
        return _copy_origin(ops, operation.inputs[0], index, seen | {marker})
    return index, operation


def _entry_pop_register(project, block):
    """Return the exact register populated by an entry-point near ``POP``, if any."""

    ops = block.vex._ops
    if not ops or ops[0].opcode != pypcode.OpCode.IMARK:
        return None
    instruction_end = next(
        (index for index, operation in enumerate(ops[1:], 1) if operation.opcode == pypcode.OpCode.IMARK),
        len(ops),
    )
    instruction_ops = ops[:instruction_end]
    pointer_size = project.arch.bytes
    sp_register = tuple(map(int, project.arch.registers["sp"]))
    ss_register = tuple(map(int, project.arch.registers["ss"]))
    cs_register = tuple(map(int, project.arch.registers["cs"]))

    candidates = []
    for load_index, load in enumerate(instruction_ops):
        if load.opcode != pypcode.OpCode.LOAD or load.output is None or load.output.size != pointer_size:
            continue
        if len(load.inputs) != 2:
            continue
        address_definition = _definition(instruction_ops, load.inputs[1], load_index)
        if address_definition is None:
            continue
        address_index, address_operation = address_definition
        if not _is_segment_userop(project, address_operation):
            continue
        try:
            _, segment_node, offset_node = get_x86_segment_varnodes(address_operation)
        except ValueError:
            continue
        if _varnode_key(segment_node) != ("register", *ss_register) or _varnode_key(offset_node) != (
            "register",
            *sp_register,
        ):
            continue
        if any(
            _writes_register(operation, sp_register) or _writes_register(operation, ss_register)
            for operation in instruction_ops[:address_index]
        ):
            continue

        stack_updates = [
            (index, operation)
            for index, operation in enumerate(instruction_ops)
            if _writes_register(operation, sp_register)
        ]
        if len(stack_updates) != 1:
            continue
        stack_update_index, stack_update = stack_updates[0]
        if stack_update_index <= load_index or stack_update.opcode != pypcode.OpCode.INT_ADD:
            continue
        if len(stack_update.inputs) != 2:
            continue
        if not (
            _varnode_key(stack_update.inputs[0]) == ("register", *sp_register)
            and stack_update.inputs[1].space.name == "const"
            and int(stack_update.inputs[1].offset) == pointer_size
            and int(stack_update.inputs[1].size) == pointer_size
        ):
            continue

        load_key = _varnode_key(load.output)
        for copy_index in range(load_index + 1, instruction_end):
            copy = instruction_ops[copy_index]
            output = copy.output
            if (
                copy.opcode != pypcode.OpCode.COPY
                or output is None
                or output.space.name != "register"
                or output.size != pointer_size
                or len(copy.inputs) != 1
                or not _copy_source_is(instruction_ops, copy.inputs[0], copy_index, load_key)
            ):
                continue
            destination = int(output.offset), int(output.size)
            if any(
                _registers_overlap(output, special_register)
                for special_register in (sp_register, ss_register, cs_register)
            ):
                continue
            candidates.append((destination, copy_index))

    if len(candidates) != 1:
        return None
    return candidates[0]


def _entry_pop_memory(project, block):
    """Return the exact segmented slot populated by an entry-point near ``POP``."""

    ops = block.vex._ops
    if not ops or ops[0].opcode != pypcode.OpCode.IMARK:
        return None
    instruction_end = next(
        (index for index, operation in enumerate(ops[1:], 1) if operation.opcode == pypcode.OpCode.IMARK),
        len(ops),
    )
    instruction_ops = ops[:instruction_end]
    pointer_size = project.arch.bytes
    sp_register = tuple(map(int, project.arch.registers["sp"]))
    ss_register = tuple(map(int, project.arch.registers["ss"]))

    stack_loads = []
    for load_index, load in enumerate(instruction_ops):
        if load.opcode != pypcode.OpCode.LOAD or load.output is None or load.output.size != pointer_size:
            continue
        if len(load.inputs) != 2:
            continue
        address_definition = _definition(instruction_ops, load.inputs[1], load_index)
        if address_definition is None:
            continue
        address_index, address_operation = address_definition
        if not _is_segment_userop(project, address_operation):
            continue
        try:
            _, segment_node, offset_node = get_x86_segment_varnodes(address_operation)
        except ValueError:
            continue
        if _varnode_key(segment_node) != ("register", *ss_register) or _varnode_key(offset_node) != (
            "register",
            *sp_register,
        ):
            continue
        if any(
            _writes_register(operation, sp_register) or _writes_register(operation, ss_register)
            for operation in instruction_ops[:address_index]
        ):
            continue
        stack_loads.append((load_index, load))

    if len(stack_loads) != 1:
        return None
    load_index, load = stack_loads[0]

    stack_updates = [
        (index, operation)
        for index, operation in enumerate(instruction_ops)
        if _writes_register(operation, sp_register)
    ]
    if len(stack_updates) != 1:
        return None
    stack_update_index, stack_update = stack_updates[0]
    if stack_update_index <= load_index or stack_update.opcode != pypcode.OpCode.INT_ADD:
        return None
    if len(stack_update.inputs) != 2 or not (
        _varnode_key(stack_update.inputs[0]) == ("register", *sp_register)
        and stack_update.inputs[1].space.name == "const"
        and int(stack_update.inputs[1].offset) == pointer_size
        and int(stack_update.inputs[1].size) == pointer_size
    ):
        return None

    stores = []
    load_key = _varnode_key(load.output)
    for store_index, store in enumerate(instruction_ops):
        if store.opcode != pypcode.OpCode.STORE or len(store.inputs) != 3:
            continue
        stored_value = store.inputs[2]
        if stored_value.size != pointer_size or not _copy_source_is(
            instruction_ops, stored_value, store_index, load_key
        ):
            continue
        slot_and_index = _segmented_memory_slot(
            project,
            instruction_ops,
            store.inputs[1],
            store_index,
            pointer_size,
        )
        if slot_and_index is None:
            continue
        slot, address_index = slot_and_index
        stores.append(_EntryMemoryPop(slot, address_index, store_index))

    if len(stores) != 1 or sum(operation.opcode == pypcode.OpCode.STORE for operation in instruction_ops) != 1:
        return None
    return stores[0]


def _branch_register(project, block):
    ops = block.vex._ops
    if not ops or ops[-1].opcode != pypcode.OpCode.BRANCHIND or len(ops[-1].inputs) != 1:
        return None
    target_definition = _definition(ops, ops[-1].inputs[0], len(ops) - 1)
    if target_definition is None:
        return None
    target_index, target_operation = target_definition
    if not _is_segment_userop(project, target_operation):
        return None
    try:
        _, segment_node, offset_node = get_x86_segment_varnodes(target_operation)
    except ValueError:
        return None
    cs_register = tuple(map(int, project.arch.registers["cs"]))
    if _varnode_key(segment_node) != ("register", *cs_register):
        return None
    if offset_node.space.name != "register" or int(offset_node.size) != project.arch.bytes:
        return None
    return (int(offset_node.offset), int(offset_node.size)), target_index


def _branch_memory(project, block):
    ops = block.vex._ops
    if not ops or ops[-1].opcode != pypcode.OpCode.BRANCHIND or len(ops[-1].inputs) != 1:
        return None
    last_imark = max(
        (index for index, operation in enumerate(ops) if operation.opcode == pypcode.OpCode.IMARK),
        default=-1,
    )
    target_definition = _definition(ops, ops[-1].inputs[0], len(ops) - 1)
    if target_definition is None:
        return None
    target_index, target_operation = target_definition
    if target_index <= last_imark or not _is_segment_userop(project, target_operation):
        return None
    try:
        _, segment_node, offset_node = get_x86_segment_varnodes(target_operation)
    except ValueError:
        return None
    cs_register = tuple(map(int, project.arch.registers["cs"]))
    if _varnode_key(segment_node) != ("register", *cs_register):
        return None

    load_definition = _copy_origin(ops, offset_node, target_index)
    if load_definition is None:
        return None
    load_index, load = load_definition
    pointer_size = project.arch.bytes
    if (
        load_index <= last_imark
        or load.opcode != pypcode.OpCode.LOAD
        or load.output is None
        or load.output.size != pointer_size
        or len(load.inputs) != 2
    ):
        return None
    slot_and_index = _segmented_memory_slot(project, ops, load.inputs[1], load_index, pointer_size)
    if slot_and_index is None:
        return None
    slot, address_index = slot_and_index
    if address_index <= last_imark:
        return None
    if sum(operation.opcode == pypcode.OpCode.LOAD for operation in ops[last_imark + 1 :]) != 1:
        return None
    return _BranchMemory(slot, address_index, load_index)


def _slots_overlap(left: _SegmentedMemorySlot, right: _SegmentedMemorySlot) -> bool:
    return left.offset < right.offset + right.size and right.offset < left.offset + left.size


def _memory_slot_is_immutable(
    project, blocks, entry_node, jump_node, pop: _EntryMemoryPop, branch: _BranchMemory
) -> bool:
    """Reject every explicit mutation, overlapping access, or materialized alias of a continuation slot."""

    for node, block in blocks.items():
        ops = block.vex._ops
        for index, operation in enumerate(ops):
            is_entry_store = node is entry_node and index == pop.store_index
            is_terminal_load = node is jump_node and index == branch.load_index

            if operation.opcode in {pypcode.OpCode.LOAD, pypcode.OpCode.STORE}:
                if operation.opcode == pypcode.OpCode.LOAD:
                    if operation.output is None or len(operation.inputs) != 2:
                        return False
                    address = operation.inputs[1]
                    width = int(operation.output.size)
                else:
                    if len(operation.inputs) != 3:
                        return False
                    address = operation.inputs[1]
                    width = int(operation.inputs[2].size)
                slot_and_index = _segmented_memory_slot(project, ops, address, index, width)
                if slot_and_index is not None:
                    accessed_slot, _ = slot_and_index
                    if _slots_overlap(accessed_slot, pop.slot) and not (is_entry_store or is_terminal_load):
                        return False

            is_entry_address = node is entry_node and index == pop.address_index
            is_terminal_address = node is jump_node and index == branch.address_index
            if not (is_entry_address or is_terminal_address) and any(
                input_.space.name == "const" and pop.slot.offset <= int(input_.offset) < pop.slot.offset + pop.slot.size
                for input_ in operation.inputs
            ):
                return False

    return True


def _block_explicitly_accesses_slot(project, block, slot: _SegmentedMemorySlot) -> bool:
    ops = block.vex._ops
    for index, operation in enumerate(ops):
        if operation.opcode in {pypcode.OpCode.LOAD, pypcode.OpCode.STORE}:
            if operation.opcode == pypcode.OpCode.LOAD:
                if operation.output is None or len(operation.inputs) != 2:
                    return True
                address = operation.inputs[1]
                width = int(operation.output.size)
            else:
                if len(operation.inputs) != 3:
                    return True
                address = operation.inputs[1]
                width = int(operation.inputs[2].size)
            slot_and_index = _segmented_memory_slot(project, ops, address, index, width)
            if slot_and_index is not None and _slots_overlap(slot_and_index[0], slot):
                return True

        if any(
            input_.space.name == "const" and slot.offset <= int(input_.offset) < slot.offset + slot.size
            for input_ in operation.inputs
        ):
            return True
    return False


def _called_functions_explicitly_access_slot(project, model, initial_targets, slot: _SegmentedMemorySlot) -> bool:
    pending = list(initial_targets)
    seen = set()
    while pending:
        target = pending.pop()
        if (
            target.simprocedure_name is not None
            or project.loader.find_object_containing(target.addr) is not project.loader.main_object
        ):
            continue
        function_addr = target.function_address
        if function_addr in seen:
            continue
        seen.add(function_addr)

        nodes = {
            node for node in model.graph if node.function_address == function_addr and getattr(node, "size", 0) > 0
        }
        if not nodes:
            return True
        try:
            blocks = [project.factory.block(node.addr, size=node.size) for node in nodes]
        except SimError:
            return True
        if any(not isinstance(block.vex, pcode.lifter.IRSB) for block in blocks):
            return True
        if any(_block_explicitly_accesses_slot(project, block, slot) for block in blocks):
            return True

        for node in nodes:
            pending.extend(
                destination
                for _, destination, data in model.graph.out_edges(node, data=True)
                if data.get("jumpkind") == "Ijk_Call"
            )
    return False


def prove_pcode_x86_return_thunk(
    project,
    cfg,
    *,
    function_addr: int,
    jump_addr: int,
    jumpkind: str = "Ijk_Boring",
) -> PcodeX86ReturnThunk | None:
    """Prove that an indirect near jump returns through a popped return-address token.

    The proof is intentionally narrow. The first machine instruction must be a
    pointer-width ``POP`` from the entry SS:SP into either a register or a fixed
    segmented memory slot. That entry block must dominate the indirect-jump
    block and every path between them must remain in the function. Register
    tokens may cross only ordinary transitions and cannot be overwritten.
    Memory tokens may also cross a call's fake-return edge, but the terminal
    jump must reload the exact same slot and the corridor cannot contain an
    explicit overlapping access or a materialized alias of that slot.
    """

    if (
        pcode is None
        or pypcode is None
        or project.arch.bits != 16
        or project.arch.name not in {key[0] for key in _X86_16_SEGMENT_USEROPS}
        or jumpkind != "Ijk_Boring"
    ):
        return None

    model = getattr(cfg, "model", cfg)
    function_addr = int(function_addr)
    jump_addr = int(jump_addr)
    entry_nodes = [
        node for node in model.get_all_nodes(function_addr) if node.function_address == function_addr and node.size > 0
    ]
    jump_nodes = [
        node for node in model.get_all_nodes(jump_addr) if node.function_address == function_addr and node.size > 0
    ]
    if len(entry_nodes) != 1 or len(jump_nodes) != 1:
        return None
    entry_node = entry_nodes[0]
    jump_node = jump_nodes[0]

    local_nodes = {
        node for node in model.graph if node.function_address == function_addr and getattr(node, "size", 0) > 0
    }
    local_graph = networkx.DiGraph()
    local_graph.add_nodes_from(local_nodes)
    edge_kinds = {}
    for source, destination, data in model.graph.edges(data=True):
        if source in local_nodes and destination in local_nodes:
            local_graph.add_edge(source, destination)
            edge_kinds[source, destination] = data.get("jumpkind")
    if (
        entry_node not in local_graph
        or jump_node not in local_graph
        or not networkx.has_path(local_graph, entry_node, jump_node)
    ):
        return None
    if jump_node is not entry_node:
        dominators = networkx.immediate_dominators(local_graph, entry_node)
        if jump_node not in dominators:
            return None

    corridor = ({entry_node} | networkx.descendants(local_graph, entry_node)) & (
        {jump_node} | networkx.ancestors(local_graph, jump_node)
    )
    corridor_edges = [
        (source, destination, edge_kinds[source, destination])
        for source, destination in local_graph.edges
        if source in corridor and destination in corridor
    ]

    try:
        blocks = {node: project.factory.block(node.addr, size=node.size) for node in corridor}
    except SimError:
        return None
    if any(not isinstance(block.vex, pcode.lifter.IRSB) for block in blocks.values()):
        return None

    register_pop = _entry_pop_register(project, blocks[entry_node])
    register_branch = _branch_register(project, blocks[jump_node])
    if (
        register_pop is not None
        and register_branch is not None
        and register_pop[0] == register_branch[0]
        and all(kind == "Ijk_Boring" for _, _, kind in corridor_edges)
    ):
        token_register, pop_index = register_pop
        _, branch_index = register_branch

        for node, block in blocks.items():
            start = pop_index + 1 if node is entry_node else 0
            end = branch_index if node is jump_node else len(block.vex._ops)
            if node is entry_node and node is jump_node:
                end = branch_index
            if any(_writes_register(operation, token_register) for operation in block.vex._ops[start:end]):
                break
        else:
            return PcodeX86ReturnThunk(
                function_addr,
                int(entry_node.addr),
                int(jump_node.addr),
                "register",
                token_register=token_register,
                token_size=project.arch.bytes,
            )

    memory_pop = _entry_pop_memory(project, blocks[entry_node])
    memory_branch = _branch_memory(project, blocks[jump_node])
    if memory_pop is None or memory_branch is None or memory_pop.slot != memory_branch.slot:
        return None
    if any(kind not in {"Ijk_Boring", "Ijk_FakeRet"} for _, _, kind in corridor_edges):
        return None
    call_targets = []
    for source, _, kind in corridor_edges:
        if kind != "Ijk_FakeRet":
            continue
        source_call_targets = [
            destination
            for _, destination, data in model.graph.out_edges(source, data=True)
            if data.get("jumpkind") == "Ijk_Call"
        ]
        if not source_call_targets:
            return None
        call_targets.extend(source_call_targets)
    if _called_functions_explicitly_access_slot(project, model, call_targets, memory_pop.slot):
        return None
    if not _memory_slot_is_immutable(
        project,
        blocks,
        entry_node,
        jump_node,
        memory_pop,
        memory_branch,
    ):
        return None
    return PcodeX86ReturnThunk(
        function_addr,
        int(entry_node.addr),
        int(jump_node.addr),
        "memory",
        token_segment_register=memory_pop.slot.segment_register,
        token_memory_offset=memory_pop.slot.offset,
        token_size=memory_pop.slot.size,
    )


def is_pcode_x86_return_thunk(project, cfg, jump) -> bool:
    """Return whether ``jump`` has exact :class:`PcodeX86ReturnThunk` evidence."""

    return (
        prove_pcode_x86_return_thunk(
            project,
            cfg,
            function_addr=jump.func_addr,
            jump_addr=jump.addr,
            jumpkind=jump.jumpkind,
        )
        is not None
    )


__all__ = ("PcodeX86ReturnThunk", "is_pcode_x86_return_thunk", "prove_pcode_x86_return_thunk")
