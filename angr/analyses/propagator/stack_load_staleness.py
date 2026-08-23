from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from angr.ailment import Block, Expr, Stmt

from angr.code_location import CodeLocation


StackRange = Tuple[int, int]
AliasKey = Tuple[Any, ...]
Aliases = Dict[AliasKey, int]


def _children(obj) -> Iterable:
    operands = getattr(obj, "operands", None)
    if operands is not None:
        yield from operands

    for attr in (
        "addr",
        "data",
        "dst",
        "src",
        "condition",
        "target",
        "true_target",
        "false_target",
        "args",
        "ret_expr",
        "fp_ret_expr",
        "ret_exprs",
    ):
        if not hasattr(obj, attr):
            continue
        child = getattr(obj, attr)
        if child is None:
            continue
        if isinstance(child, (list, tuple)):
            yield from (item for item in child if item is not None)
        else:
            yield child


def _alias_key(expr) -> Optional[AliasKey]:
    if isinstance(expr, Expr.Register):
        return "reg", expr.reg_offset, expr.size
    if isinstance(expr, Expr.Tmp):
        return "tmp", expr.tmp_idx
    return None


def _const_int_value(expr) -> Optional[int]:
    if isinstance(expr, Expr.Const) and isinstance(expr.value, int):
        value = expr.value
        bits = getattr(expr, "bits", None)
        if isinstance(bits, int) and bits > 0 and value >= (1 << (bits - 1)):
            value -= 1 << bits
        return value
    return expr if isinstance(expr, int) else None


def stack_base_offset_value(expr, aliases: Optional[Aliases] = None, seen: Optional[Set[int]] = None) -> Optional[int]:
    if aliases is None:
        aliases = {}
    if seen is None:
        seen = set()
    if expr is None:
        return None

    expr_id = id(expr)
    if expr_id in seen:
        return None
    seen.add(expr_id)

    if isinstance(expr, Expr.StackBaseOffset) and isinstance(expr.offset, int):
        return expr.offset

    alias_key = _alias_key(expr)
    if alias_key is not None and alias_key in aliases:
        return aliases[alias_key]

    if isinstance(expr, Expr.Convert):
        return stack_base_offset_value(expr.operand, aliases=aliases, seen=seen)

    if isinstance(expr, Expr.BinaryOp) and len(expr.operands) == 2:
        left, right = expr.operands
        left_stack = stack_base_offset_value(left, aliases=aliases, seen=seen)
        right_stack = stack_base_offset_value(right, aliases=aliases, seen=seen)
        left_const = _const_int_value(left)
        right_const = _const_int_value(right)

        if expr.op in {"Add", "__add__"}:
            if left_stack is not None and right_const is not None:
                return left_stack + right_const
            if right_stack is not None and left_const is not None:
                return right_stack + left_const
        elif expr.op in {"Sub", "__sub__"}:
            if left_stack is not None and right_const is not None:
                return left_stack - right_const

    return None


def _update_stack_aliases_from_stmt(aliases: Aliases, stmt: Stmt.Statement) -> None:
    if not isinstance(stmt, Stmt.Assignment):
        return

    alias_key = _alias_key(stmt.dst)
    if alias_key is None:
        return

    offset = stack_base_offset_value(stmt.src, aliases=aliases)
    if offset is None:
        aliases.pop(alias_key, None)
    else:
        aliases[alias_key] = offset


def block_stack_aliases_by_stmt(block: Block, initial_aliases: Optional[Aliases] = None) -> List[Aliases]:
    aliases = dict(initial_aliases or {})
    aliases_by_stmt = []

    for stmt in block.statements:
        aliases_by_stmt.append(dict(aliases))
        _update_stack_aliases_from_stmt(aliases, stmt)

    return aliases_by_stmt


def _replacement_expr(replacement):
    return replacement["expr"] if isinstance(replacement, dict) else replacement


def replacement_stack_aliases(replacements, base_aliases: Optional[Aliases] = None) -> Aliases:
    aliases = dict(base_aliases or {})
    if not replacements:
        return aliases

    changed = True
    while changed:
        changed = False
        for old, replacement in replacements.items():
            alias_key = _alias_key(old)
            if alias_key is None:
                continue

            offset = stack_base_offset_value(_replacement_expr(replacement), aliases=aliases)
            if offset is not None and aliases.get(alias_key) != offset:
                aliases[alias_key] = offset
                changed = True

    return aliases


def stack_aliases_from_state(state) -> Aliases:
    aliases: Aliases = {}
    for (reg_offset, size), (_, expr, _) in getattr(state, "register_expressions", {}).items():
        offset = stack_base_offset_value(expr, aliases=aliases)
        if offset is not None:
            aliases["reg", reg_offset, size] = offset
    return aliases


def _collect_tmp_ids(
    expr,
    seen: Optional[Set[int]] = None,
    max_expr_depth: int = -1,
    max_nodes: int = -1,
    budget_exhausted: Optional[List[bool]] = None,
) -> Set[int]:
    if seen is None:
        seen = set()
    if budget_exhausted is None:
        budget_exhausted = [False]
    if expr is None:
        return set()
    if max_expr_depth >= 0 and getattr(expr, "depth", 0) > max_expr_depth:
        budget_exhausted[0] = True
        return set()

    expr_id = id(expr)
    if expr_id in seen:
        return set()
    seen.add(expr_id)
    if max_nodes >= 0 and len(seen) > max_nodes:
        budget_exhausted[0] = True
        return set()

    tmp_ids = set()
    if isinstance(expr, Expr.Tmp):
        tmp_ids.add(expr.tmp_idx)

    for child in _children(expr):
        tmp_ids.update(
            _collect_tmp_ids(
                child,
                seen=seen,
                max_expr_depth=max_expr_depth,
                max_nodes=max_nodes,
                budget_exhausted=budget_exhausted,
            )
        )
    return tmp_ids


def _collect_stack_load_ranges(
    expr,
    aliases: Optional[Aliases] = None,
    seen: Optional[Set[int]] = None,
    max_expr_depth: int = -1,
    max_nodes: int = -1,
    budget_exhausted: Optional[List[bool]] = None,
) -> List[StackRange]:
    if aliases is None:
        aliases = {}
    if seen is None:
        seen = set()
    if budget_exhausted is None:
        budget_exhausted = [False]
    if expr is None:
        return []
    if max_expr_depth >= 0 and getattr(expr, "depth", 0) > max_expr_depth:
        budget_exhausted[0] = True
        return []

    expr_id = id(expr)
    if expr_id in seen:
        return []
    seen.add(expr_id)
    if max_nodes >= 0 and len(seen) > max_nodes:
        budget_exhausted[0] = True
        return []

    ranges = []
    if isinstance(expr, Expr.Load):
        offset = stack_base_offset_value(expr.addr, aliases=aliases)
        if offset is not None and isinstance(expr.size, int):
            ranges.append((offset, expr.size))

    for child in _children(expr):
        ranges.extend(
            _collect_stack_load_ranges(
                child,
                aliases=aliases,
                seen=seen,
                max_expr_depth=max_expr_depth,
                max_nodes=max_nodes,
                budget_exhausted=budget_exhausted,
            )
        )
    return ranges


def _stmt_stack_store_range(stmt: Stmt.Statement, aliases: Optional[Aliases] = None) -> Optional[StackRange]:
    if not isinstance(stmt, Stmt.Store):
        return None

    offset = stack_base_offset_value(stmt.addr, aliases=aliases)
    if offset is not None and isinstance(stmt.size, int):
        return offset, stmt.size
    return None


def _ranges_overlap(left: StackRange, right: StackRange) -> bool:
    left_offset, left_size = left
    right_offset, right_size = right
    return left_offset < right_offset + right_size and right_offset < left_offset + left_size


def _tmp_definition_before(block: Block, tmp_idx: int, before_idx: int) -> Optional[Tuple[int, Stmt.Assignment]]:
    for idx in range(min(before_idx - 1, len(block.statements) - 1), -1, -1):
        stmt = block.statements[idx]
        if isinstance(stmt, Stmt.Assignment) and isinstance(stmt.dst, Expr.Tmp) and stmt.dst.tmp_idx == tmp_idx:
            return idx, stmt
    return None


def _stack_load_sources(
    block: Block,
    expr,
    stmt_idx: int,
    aliases_by_stmt: List[Aliases],
    visited: Optional[Set[Tuple[int, int]]] = None,
    depth: int = 0,
    max_depth: int = 64,
    max_expr_depth: int = -1,
    max_expr_nodes: int = -1,
    budget_exhausted: Optional[List[bool]] = None,
) -> List[Tuple[StackRange, int]]:
    if visited is None:
        visited = set()
    if budget_exhausted is None:
        budget_exhausted = [False]
    if max_depth >= 0 and depth > max_depth:
        return []
    if max_expr_depth >= 0 and getattr(expr, "depth", 0) > max_expr_depth:
        budget_exhausted[0] = True
        return []

    aliases = aliases_by_stmt[stmt_idx] if stmt_idx < len(aliases_by_stmt) else {}
    sources = [
        (load_range, stmt_idx)
        for load_range in _collect_stack_load_ranges(
            expr,
            aliases=aliases,
            max_expr_depth=max_expr_depth,
            max_nodes=max_expr_nodes,
            budget_exhausted=budget_exhausted,
        )
    ]

    if budget_exhausted[0]:
        return sources

    for tmp_idx in _collect_tmp_ids(
        expr,
        max_expr_depth=max_expr_depth,
        max_nodes=max_expr_nodes,
        budget_exhausted=budget_exhausted,
    ):
        if budget_exhausted[0]:
            break
        definition = _tmp_definition_before(block, tmp_idx, stmt_idx)
        if definition is None:
            continue
        def_idx, def_stmt = definition
        visit_key = tmp_idx, def_idx
        if visit_key in visited:
            continue
        visited.add(visit_key)
        sources.extend(
            _stack_load_sources(
                block,
                def_stmt.src,
                def_idx,
                aliases_by_stmt,
                visited=visited,
                depth=depth + 1,
                max_depth=max_depth,
                max_expr_depth=max_expr_depth,
                max_expr_nodes=max_expr_nodes,
                budget_exhausted=budget_exhausted,
            )
        )

    return sources


def _stack_store_between(
    block: Block,
    target_range: StackRange,
    start_idx: int,
    end_idx: int,
    aliases_by_stmt: List[Aliases],
) -> bool:
    start = max(start_idx + 1, 0)
    end = min(end_idx, len(block.statements))
    if start >= end:
        return False

    for idx in range(start, end):
        aliases = aliases_by_stmt[idx] if idx < len(aliases_by_stmt) else {}
        store_range = _stmt_stack_store_range(block.statements[idx], aliases=aliases)
        if store_range is not None and _ranges_overlap(store_range, target_range):
            return True
    return False


def _last_stack_store_before(
    block: Block,
    target_range: StackRange,
    before_idx: int,
    aliases_by_stmt: List[Aliases],
) -> Optional[Tuple[int, Stmt.Store, StackRange]]:
    if before_idx < 0:
        return None

    for idx in range(min(before_idx, len(block.statements) - 1), -1, -1):
        aliases = aliases_by_stmt[idx] if idx < len(aliases_by_stmt) else {}
        store_range = _stmt_stack_store_range(block.statements[idx], aliases=aliases)
        if store_range is not None and _ranges_overlap(store_range, target_range):
            return idx, block.statements[idx], store_range
    return None


def _transitive_stack_copy_is_stale(
    block: Block,
    load_range: StackRange,
    load_stmt_idx: int,
    current_stmt_idx: int,
    aliases_by_stmt: List[Aliases],
    memo=None,
    visited=None,
    depth: int = 0,
    max_depth: int = 64,
) -> bool:
    if memo is None:
        memo = {}
    if visited is None:
        visited = set()
    if max_depth >= 0 and depth > max_depth:
        return True

    key = load_range, load_stmt_idx, current_stmt_idx
    if key in memo:
        return memo[key]

    producer = _last_stack_store_before(block, load_range, load_stmt_idx - 1, aliases_by_stmt)
    if producer is None:
        memo[key] = False
        return False

    producer_idx, producer_stmt, producer_range = producer
    visit_key = producer_idx, producer_range, load_range
    if visit_key in visited:
        memo[key] = False
        return False

    visited.add(visit_key)
    producer_aliases = aliases_by_stmt[producer_idx] if producer_idx < len(aliases_by_stmt) else {}
    for source_range in _collect_stack_load_ranges(
        getattr(producer_stmt, "data", producer_stmt), aliases=producer_aliases
    ):
        if _stack_store_between(block, source_range, producer_idx, current_stmt_idx, aliases_by_stmt):
            memo[key] = True
            return True

        if _transitive_stack_copy_is_stale(
            block,
            source_range,
            producer_idx,
            current_stmt_idx,
            aliases_by_stmt,
            memo=memo,
            visited=visited,
            depth=depth + 1,
            max_depth=max_depth,
        ):
            memo[key] = True
            return True

    memo[key] = False
    return False


def _codeloc_for_stmt(block: Block, stmt_idx: int) -> CodeLocation:
    return CodeLocation(block.addr, stmt_idx, block_idx=block.idx)


def _codeloc_stmt_idx_in_block(codeloc: Optional[CodeLocation], block: Block) -> Optional[int]:
    if codeloc is None:
        return None
    if getattr(codeloc, "block_addr", None) != block.addr:
        return None
    codeloc_block_idx = getattr(codeloc, "block_idx", None)
    if codeloc_block_idx is not None and block.idx is not None and codeloc_block_idx != block.idx:
        return None
    stmt_idx = getattr(codeloc, "stmt_idx", None)
    if not isinstance(stmt_idx, int) or stmt_idx < 0:
        return None
    return stmt_idx


def replacement_has_stale_stack_load_source(
    block: Optional[Block],
    codeloc: CodeLocation,
    old,
    new,
    initial_aliases: Optional[Aliases] = None,
    max_depth: int = 64,
    max_expr_depth: int = -1,
    max_expr_nodes: int = -1,
    aliases_by_stmt: Optional[List[Aliases]] = None,
) -> bool:
    """
    Return True if applying a replacement would inline a stack load from a tmp whose saved load source was overwritten.
    """
    if not isinstance(block, Block) or not isinstance(old, Expr.Tmp) or new is None:
        return False

    stmt_idx = _codeloc_stmt_idx_in_block(codeloc, block)
    if stmt_idx is None:
        return False

    definition = _tmp_definition_before(block, old.tmp_idx, stmt_idx)
    if definition is None:
        return False

    def_idx, _ = definition
    return has_stale_stack_load_source(
        block,
        new,
        _codeloc_for_stmt(block, def_idx),
        codeloc,
        initial_aliases=initial_aliases,
        max_depth=max_depth,
        max_expr_depth=max_expr_depth,
        max_expr_nodes=max_expr_nodes,
        aliases_by_stmt=aliases_by_stmt,
    )


def replacement_introduces_stale_stack_load(
    block: Optional[Block],
    codeloc: CodeLocation,
    old_stmt,
    new_stmt,
    old,
    new,
    initial_aliases: Optional[Aliases] = None,
    max_depth: int = 64,
    max_expr_depth: int = -1,
    max_expr_nodes: int = -1,
    aliases_by_stmt: Optional[List[Aliases]] = None,
) -> bool:
    """
    Return True if a replacement introduces or reuses a stack load whose stack-copy source is stale.
    """
    if not isinstance(block, Block) or new is None:
        return False

    if replacement_has_stale_stack_load_source(
        block,
        codeloc,
        old,
        new,
        initial_aliases=initial_aliases,
        max_depth=max_depth,
        max_expr_depth=max_expr_depth,
        max_expr_nodes=max_expr_nodes,
        aliases_by_stmt=aliases_by_stmt,
    ):
        return True

    stmt_idx = _codeloc_stmt_idx_in_block(codeloc, block)
    if stmt_idx is None:
        return False

    if aliases_by_stmt is None:
        aliases_by_stmt = block_stack_aliases_by_stmt(block, initial_aliases=initial_aliases)
    aliases = aliases_by_stmt[stmt_idx] if stmt_idx < len(aliases_by_stmt) else dict(initial_aliases or {})

    load_ranges = []
    old_offset = stack_base_offset_value(old, aliases=aliases)
    new_offset = stack_base_offset_value(new, aliases=aliases)
    if old_offset is not None and new_offset is not None:
        for load_range in _collect_stack_load_ranges(old_stmt, aliases=aliases):
            if load_range[0] == old_offset:
                load_ranges.append(load_range)

    if isinstance(old, Expr.Load):
        load_ranges.extend(_collect_stack_load_ranges(old, aliases=aliases))

    old_stmt_ranges = set(_collect_stack_load_ranges(old_stmt, aliases=aliases))
    if new_stmt is not None:
        for load_range in _collect_stack_load_ranges(new_stmt, aliases=aliases):
            if load_range not in old_stmt_ranges:
                load_ranges.append(load_range)

    load_ranges.extend(_collect_stack_load_ranges(new, aliases=aliases))

    seen_ranges = set()
    for load_range in load_ranges:
        if load_range in seen_ranges:
            continue
        seen_ranges.add(load_range)
        if _transitive_stack_copy_is_stale(
            block,
            load_range,
            stmt_idx,
            stmt_idx,
            aliases_by_stmt,
            max_depth=max_depth,
        ):
            return True

    return False


def has_stale_stack_load_source(
    block: Optional[Block],
    expr,
    expr_defat: Optional[CodeLocation],
    current_loc: CodeLocation,
    initial_aliases: Optional[Aliases] = None,
    max_depth: int = 64,
    max_expr_depth: int = -1,
    max_expr_nodes: int = -1,
    aliases_by_stmt: Optional[List[Aliases]] = None,
) -> bool:
    """
    Return True if propagating expr to current_loc would turn a saved stack load into a fresh load after the
    stack slot was overwritten.
    """
    if not isinstance(block, Block):
        return False

    def_stmt_idx = _codeloc_stmt_idx_in_block(expr_defat, block)
    current_stmt_idx = _codeloc_stmt_idx_in_block(current_loc, block)
    if def_stmt_idx is None or current_stmt_idx is None or current_stmt_idx <= def_stmt_idx:
        return False

    if aliases_by_stmt is None:
        aliases_by_stmt = block_stack_aliases_by_stmt(block, initial_aliases=initial_aliases)
    seen_sources = set()
    budget_exhausted = [False]
    for load_range, source_idx in _stack_load_sources(
        block,
        expr,
        def_stmt_idx,
        aliases_by_stmt,
        max_depth=max_depth,
        max_expr_depth=max_expr_depth,
        max_expr_nodes=max_expr_nodes,
        budget_exhausted=budget_exhausted,
    ):
        key = load_range, source_idx
        if key in seen_sources:
            continue
        seen_sources.add(key)
        if _stack_store_between(block, load_range, source_idx, current_stmt_idx, aliases_by_stmt):
            return True
        if _transitive_stack_copy_is_stale(block, load_range, source_idx, current_stmt_idx, aliases_by_stmt):
            return True

    return budget_exhausted[0]
