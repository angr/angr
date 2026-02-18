from __future__ import annotations

"""JSON serialization helpers for angr objects."""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg import CFGModel
    from angr.knowledge_plugins.functions import Function
    from angr.knowledge_plugins.xrefs import XRef


def serialize_function(func: Function, include_blocks: bool = False) -> dict[str, Any]:
    """
    Serialize a Function object to a JSON-compatible dict.

    :param func: The angr Function to serialize
    :param include_blocks: Whether to include block addresses
    :return: Dictionary with function information
    """
    result: dict[str, Any] = {
        "address": hex(func.addr),
        "name": func.name,
        "size": func.size,
        "is_plt": func.is_plt,
        "is_syscall": func.is_syscall,
        "is_simprocedure": func.is_simprocedure,
        "returning": func.returning,
        "binary_name": func.binary_name,
        "num_blocks": len(list(func.block_addrs)),
    }

    # Cyclomatic complexity requires a non-empty transition graph
    try:
        if func.transition_graph.number_of_nodes() > 0:
            result["cyclomatic_complexity"] = func.cyclomatic_complexity
        else:
            result["cyclomatic_complexity"] = None
    except Exception:
        result["cyclomatic_complexity"] = None

    if func.calling_convention:
        result["calling_convention"] = str(func.calling_convention)

    if func.prototype:
        result["prototype"] = str(func.prototype)

    if include_blocks:
        result["block_addresses"] = [hex(addr) for addr in func.block_addrs]

    return result


def serialize_function_summary(func: Function) -> dict[str, Any]:
    """
    Serialize minimal function info for list views.

    :param func: The angr Function to serialize
    :return: Dictionary with minimal function information
    """
    return {
        "address": hex(func.addr),
        "name": func.name,
        "is_plt": func.is_plt,
        "is_syscall": func.is_syscall,
    }


def serialize_xref(xref: XRef) -> dict[str, Any]:
    """
    Serialize an XRef object.

    :param xref: The angr XRef to serialize
    :return: Dictionary with cross-reference information
    """
    from angr.knowledge_plugins.xrefs import XRefType

    return {
        "from_address": hex(xref.ins_addr) if xref.ins_addr else None,
        "to_address": hex(xref.dst) if xref.dst else None,
        "type": XRefType.to_string(xref.type),
        "block_address": hex(xref.block_addr) if xref.block_addr else None,
    }


def serialize_basic_block(block: Any, include_disasm: bool = True) -> dict[str, Any]:
    """
    Serialize a basic block.

    :param block: The angr Block to serialize
    :param include_disasm: Whether to include disassembly
    :return: Dictionary with block information
    """
    result: dict[str, Any] = {
        "address": hex(block.addr),
        "size": block.size,
        "instruction_count": block.instructions,
    }

    if include_disasm:
        try:
            result["instructions"] = [
                {
                    "address": hex(insn.address),
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                    "bytes": insn.bytes.hex(),
                }
                for insn in block.capstone.insns
            ]
        except Exception:
            result["instructions"] = []
            result["disasm_error"] = "Failed to disassemble"

    return result


def serialize_cfg_stats(cfg_model: CFGModel) -> dict[str, Any]:
    """
    Serialize CFG statistics.

    :param cfg_model: The angr CFGModel to summarize
    :return: Dictionary with CFG statistics
    """
    return {
        "nodes": cfg_model.graph.number_of_nodes(),
        "edges": cfg_model.graph.number_of_edges(),
        "normalized": cfg_model.normalized,
        "memory_data_count": len(cfg_model.memory_data),
        "jump_table_count": len(cfg_model.jump_tables),
    }


def serialize_symbol(symbol: Any) -> dict[str, Any]:
    """
    Serialize a CLE symbol.

    :param symbol: The CLE Symbol to serialize
    :return: Dictionary with symbol information
    """
    return {
        "name": symbol.name,
        "address": hex(symbol.rebased_addr),
        "size": symbol.size,
        "type": str(symbol.type) if symbol.type else None,
        "is_function": symbol.is_function,
        "is_import": symbol.is_import,
        "is_export": symbol.is_export,
    }
