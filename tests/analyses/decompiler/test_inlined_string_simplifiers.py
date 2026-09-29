# pylint: disable=protected-access
from __future__ import annotations

import networkx
from archinfo import Endness

import angr
from angr.ailment import Block
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Insert,
    StackBaseOffset,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, SideEffectStatement, Store
from angr.analyses.decompiler.optimization_passes.inlined_strcpy_simplifier import (
    InlinedStrcpySimplifier,
    InlinedStrcpySimplifierLate,
)
from angr.analyses.decompiler.optimization_passes.inlined_wcscpy_simplifier import (
    InlinedWcscpySimplifier,
    InlinedWcscpySimplifierLate,
)
from angr.analyses.decompiler.variable_map import variable_map_of


def _simplifier(cls):
    project = angr.load_shellcode(b"\x90", arch="AMD64")
    func = project.kb.functions.function(addr=0, name="dummy", create=True)
    simplifier = object.__new__(cls)
    simplifier._func = func  # pyright: ignore[reportAttributeAccessIssue]
    simplifier.manager = Manager()
    simplifier._vvar_value_uses = {}  # pyright: ignore[reportAttributeAccessIssue]
    return simplifier


def _stack_vvar(varid: int, offset: int, bits: int = 32):
    return VirtualVariable(varid, varid, bits, VirtualVariableCategory.STACK, oident=offset)


def _register_vvar(varid: int, bits: int = 64):
    return VirtualVariable(varid, varid, bits, VirtualVariableCategory.REGISTER, oident=0)


def _float_const(idx: int, value: float = 1.0, bits: int = 32):
    return Const(idx, value, bits)  # pyright: ignore[reportArgumentType]


def _integer_stack_assignment(idx: int, offset: int):
    return Assignment(idx, _stack_vvar(idx, offset), Const(idx, 0x41414141, 32))


def _integer_stack_store(idx: int, offset: int):
    return Store(idx, StackBaseOffset(idx, 64, offset), Const(idx, 0x41414141, 32), 4, "Iend_LE")


def _inlined_wcsncpy(simplifier, idx: int, offset: int, data: bytes, count=None):
    string_id = simplifier.kb.custom_strings.allocate(data)
    string_const = Const(idx, string_id, 64)
    variable_map_of(simplifier.manager).set_custom_string(string_const)
    if count is None:
        count = Const(idx + 1, len(data) // 2, 64)
    call = Call(
        idx + 2,
        "wcsncpy",
        args=[StackBaseOffset(idx + 3, 64, offset), string_const, count],
    )
    return SideEffectStatement(idx + 4, call)


def test_strcpy_collector_rejects_float_stack_assignment():
    simplifier = _simplifier(InlinedStrcpySimplifier)
    statements = [
        _integer_stack_store(0, -8),
        Assignment(1, _stack_vvar(1, -4), _float_const(1)),
    ]

    collected = simplifier._collect_constant_stores(statements, 0)

    assert collected[-4][1] is None


def test_strcpy_collector_rejects_float_insert_value_and_offset():
    simplifier = _simplifier(InlinedStrcpySimplifier)
    dst = _stack_vvar(1, -4)
    statements = [
        _integer_stack_store(0, -8),
        Assignment(1, dst, Insert(1, dst, Const(2, 0, 32), _float_const(3), "Iend_LE")),
    ]
    collected = simplifier._collect_constant_stores(statements, 0)
    assert collected[-4][1] is None

    statements[1] = Assignment(
        1,
        dst,
        Insert(1, dst, _float_const(2, 0.0), Const(3, 0x41, 8), "Iend_LE"),
    )
    collected = simplifier._collect_constant_stores(statements, 0)
    assert collected[-4][1] is None


def test_strcpy_collector_rejects_float_insert_base():
    simplifier = _simplifier(InlinedStrcpySimplifier)
    dst = _stack_vvar(1, -8)
    statements = [
        Assignment(
            1,
            dst,
            Insert(1, _float_const(2), Const(3, 4, 32), Const(4, 0x44434241, 32), "Iend_LE"),
        )
    ]

    collected = simplifier._collect_constant_stores(statements, 0)

    assert -4 not in collected
    assert collected[-8][1] is None


def test_strcpy_single_statement_rejects_float_insert_offset():
    simplifier = _simplifier(InlinedStrcpySimplifier)
    dst = _stack_vvar(0, -4)
    stmt = Assignment(
        0,
        dst,
        Insert(0, dst, _float_const(1, 0.0), Const(2, 0x44434241, 32), "Iend_LE"),
    )

    assert simplifier._optimize_single_stmt(stmt, 0, [stmt]) is None


def test_strcpy_single_statement_rejects_float_insert_base():
    simplifier = _simplifier(InlinedStrcpySimplifier)
    dst = _stack_vvar(0, -4)
    stmt = Assignment(
        0,
        dst,
        Insert(0, _float_const(1), Const(2, 0, 32), Const(3, 0x44434241, 32), "Iend_LE"),
    )

    assert simplifier._optimize_single_stmt(stmt, 0, [stmt]) is None


def test_strcpy_collector_rejects_float_stack_store():
    simplifier = _simplifier(InlinedStrcpySimplifier)
    statements = [
        _integer_stack_store(0, -8),
        Store(1, StackBaseOffset(1, 64, -4), _float_const(1), 4, "Iend_LE"),
    ]

    collected = simplifier._collect_constant_stores(statements, 0)

    assert collected[-4][1] is None


def test_strcpy_collector_keeps_integer_insert_and_stack_store():
    simplifier = _simplifier(InlinedStrcpySimplifier)
    dst = _stack_vvar(0, -8)
    statements = [
        Assignment(0, dst, Insert(0, dst, Const(1, 0, 32), Const(2, 0x44434241, 32), "Iend_LE")),
        Store(1, StackBaseOffset(1, 64, -4), Const(3, 0x48474645, 32), 4, "Iend_LE"),
    ]

    collected = simplifier._collect_constant_stores(statements, 0)

    assert collected[-8][1].is_int
    assert collected[-4][1].is_int


def test_strcpy_consolidation_rejects_float_store():
    simplifier = _simplifier(InlinedStrcpySimplifier)
    dst = StackBaseOffset(0, 64, -8)
    string_id = simplifier.kb.custom_strings.allocate(b"abcd")
    string_const = Const(1, string_id, 64)
    variable_map_of(simplifier.manager).set_custom_string(string_const)
    call = Call(2, "strncpy", args=[dst, string_const, Const(3, 4, 64)])
    inlined_strcpy = SideEffectStatement(4, call)
    float_store = Store(5, StackBaseOffset(5, 64, -4), _float_const(6), 4, "Iend_LE")

    assert simplifier._consolidate_pair(inlined_strcpy, float_store) is None


def test_strcpy_address_parser_rejects_float_offset():
    base = _register_vvar(0)
    addr = BinaryOp(1, "Add", [base, _float_const(2, 4.0, 64)])

    assert InlinedStrcpySimplifier._get_delta(base, addr) is None


def test_wcscpy_collector_rejects_float_stack_assignment():
    simplifier = _simplifier(InlinedWcscpySimplifier)
    statements = [
        _integer_stack_assignment(0, -8),
        Assignment(1, _stack_vvar(1, -4), _float_const(1)),
    ]

    collected = simplifier._collect_constant_stores(statements, 0)

    assert collected[-4][1] is None


def test_wcscpy_collector_rejects_float_store_and_offset():
    simplifier = _simplifier(InlinedWcscpySimplifier)
    base = _register_vvar(0)
    statements = [
        Store(0, base, Const(0, 0x41004200, 32), 4, "Iend_LE"),
        Store(
            1,
            BinaryOp(1, "Add", [base, Const(1, 4, 64)]),
            _float_const(1),
            4,
            "Iend_LE",
        ),
    ]
    collected = simplifier._collect_constant_stores(statements, 0)
    assert collected[4][1] is None

    statements[1] = Store(
        1,
        BinaryOp(1, "Add", [base, _float_const(1, 4.0, 64)]),
        Const(1, 0x43004400, 32),
        4,
        "Iend_LE",
    )
    collected = simplifier._collect_constant_stores(statements, 0)
    assert 4 not in collected


def test_wcscpy_collector_keeps_integer_store_and_offset():
    simplifier = _simplifier(InlinedWcscpySimplifier)
    base = _register_vvar(0)
    statements = [
        Store(0, base, Const(0, 0x41004200, 32), 4, "Iend_LE"),
        Store(
            1,
            BinaryOp(1, "Add", [base, Const(1, 4, 64)]),
            Const(2, 0x43004400, 32),
            4,
            "Iend_LE",
        ),
    ]

    collected = simplifier._collect_constant_stores(statements, 0)

    assert collected[0][1].is_int
    assert collected[4][1].is_int


def test_wcscpy_consolidation_preserves_float_store_as_overlap_barrier():
    simplifier = _simplifier(InlinedWcscpySimplifier)
    call = _inlined_wcsncpy(simplifier, 0, 0, b"A\x00B\x00")
    float_store = Store(5, StackBaseOffset(6, 64, 4), _float_const(7, bits=16), 2, "Iend_LE")
    final_store = Store(8, StackBaseOffset(9, 64, 4), Const(10, 0, 16), 2, "Iend_LE")

    assert simplifier._consolidate_wcscpy_calls([call, final_store]) is not None
    assert simplifier._consolidate_wcscpy_calls([call, float_store, final_store]) is None


def test_wcscpy_consolidation_preserves_float_assignment_as_overlap_barrier():
    simplifier = _simplifier(InlinedWcscpySimplifier)
    call = _inlined_wcsncpy(simplifier, 0, 0, b"A\x00B\x00")
    float_assignment = Assignment(5, _stack_vvar(6, 4, bits=16), _float_const(7, bits=16))
    final_assignment = Assignment(8, _stack_vvar(9, 4, bits=16), Const(10, 0x43, 16))

    assert simplifier._consolidate_wcscpy_calls([call, final_assignment]) is not None
    assert simplifier._consolidate_wcscpy_calls([call, float_assignment, final_assignment]) is None


def test_wcscpy_consolidation_aborts_on_noninteger_wcsncpy_count():
    simplifier = _simplifier(InlinedWcscpySimplifier)
    invalid_call = _inlined_wcsncpy(simplifier, 0, 8, b"C\x00", count=_float_const(1, 1.0, 64))
    valid_call = _inlined_wcsncpy(simplifier, 10, 0, b"A\x00B\x00")
    final_store = Store(20, StackBaseOffset(21, 64, 4), Const(22, 0, 16), 2, "Iend_LE")

    assert simplifier._consolidate_wcscpy_calls([valid_call, final_store]) is not None
    assert simplifier._consolidate_wcscpy_calls([invalid_call, valid_call, final_store]) is None


def test_wcscpy_wide_string_predicates_reject_floats():
    assert not InlinedWcscpySimplifier.even_offsets_are_zero([0.0, 65.0])
    assert not InlinedWcscpySimplifier.odd_offsets_are_zero([65.0, 0.0])
    assert InlinedWcscpySimplifier.is_integer_likely_a_wide_string(1.0, 4, "Iend_LE") == (False, None)


class _WcscpyBlockBuilder:
    """
    Builds a single AIL block of stack writes and runs InlinedWcscpySimplifierLate on it.
    """

    def __init__(self):
        self.project = angr.load_shellcode(b"\x90", arch="AMD64")
        self.func = self.project.kb.functions.function(addr=0, name="dummy", create=True)
        self.manager = Manager()
        self.statements = []
        self._varid = 0

    def vvar(self, offset: int, bits: int = 8):
        self._varid += 1
        return VirtualVariable(
            self.manager.next_atom(), self._varid, bits, VirtualVariableCategory.STACK, oident=offset
        )

    def write_bytes(self, offset: int, data: bytes):
        vvars = []
        for i, byte in enumerate(data):
            dst = self.vvar(offset + i)
            self.statements.append(Assignment(self.manager.next_atom(), dst, Const(self.manager.next_atom(), byte, 8)))
            vvars.append(dst)
        return vvars

    def insert_bytes(self, offset: int, data: bytes):
        base = self.vvar(offset, bits=len(data) * 8)
        vvars = []
        for i, byte in enumerate(data):
            dst = self.vvar(offset, bits=len(data) * 8)
            update = Insert(
                self.manager.next_atom(),
                base,
                Const(self.manager.next_atom(), i, 64),
                Const(self.manager.next_atom(), byte, 8),
                "Iend_LE",
            )
            self.statements.append(Assignment(self.manager.next_atom(), dst, update))
            vvars.append(dst)
            base = dst
        return vvars

    def store_bytes(self, offset: int, data: bytes):
        for i, byte in enumerate(data):
            addr = StackBaseOffset(self.manager.next_atom(), 64, offset + i)
            self.statements.append(
                Store(self.manager.next_atom(), addr, Const(self.manager.next_atom(), byte, 8), 1, "Iend_LE")
            )

    def call(self, name: str, *args):
        self.statements.append(
            SideEffectStatement(self.manager.next_atom(), Call(self.manager.next_atom(), name, args=list(args)))
        )

    def run(self, simplifier_cls=InlinedWcscpySimplifierLate):
        block = Block(0, 1, self.statements)
        graph = networkx.DiGraph()
        graph.add_node(block)
        simplifier = simplifier_cls(
            self.func,
            self.manager,
            graph=graph,
            blocks_by_addr={0: {block}},
            blocks_by_addr_and_idx={(0, None): block},
        )
        out_graph = simplifier.out_graph if simplifier.out_graph is not None else graph
        (out_block,) = out_graph.nodes
        return simplifier, out_block.statements

    def wide_copies(self, simplifier, statements):
        """
        Return (dst stack offset, string bytes, number of bytes written) of each inlined wide string copy.
        """
        copies = []
        for stmt in statements:
            if simplifier._is_inlined_wide_copy(stmt):
                dst, str_const = stmt.expr.args[:2]
                _, offset = simplifier._parse_addr(dst)
                text = self.project.kb.custom_strings[str_const.value_int]
                copies.append((offset, text, len(simplifier._copied_bytes(stmt))))
        return copies


APPDATA_PATH = r"%AppData%\Thunderbird\Profiles".encode("utf-16le")


def test_wcscpy_folds_valid_prefix_before_partial_updates():
    # issue 7285: constant Insert updates after the path used to discard the whole path
    builder = _WcscpyBlockBuilder()
    builder.write_bytes(-108, APPDATA_PATH)
    builder.insert_bytes(-48, b"\x00\x00\xde\xdf")
    builder.insert_bytes(-44, b"\xe0\xe1\xe2\xe3")
    simplifier, statements = builder.run()

    assert builder.wide_copies(simplifier, statements) == [(-108, APPDATA_PATH, 60)]
    # the partial updates are preserved
    assert sum(isinstance(stmt, Assignment) and isinstance(stmt.src, Insert) for stmt in statements) == 8


def test_wcscpy_writes_to_start_of_stride():
    builder = _WcscpyBlockBuilder()
    builder.write_bytes(-120, b"A")
    builder.write_bytes(-108, "abcd".encode("utf-16le"))
    simplifier, statements = builder.run()

    assert builder.wide_copies(simplifier, statements) == [(-108, "abcd".encode("utf-16le"), 8)]
    assert isinstance(statements[0], Assignment) and statements[0].dst.stack_offset == -120


def test_wcscpy_does_not_hoist_writes_across_calls():
    builder = _WcscpyBlockBuilder()
    data = "abcd".encode("utf-16le")
    vvars = builder.write_bytes(-108, data[:4])
    builder.call("consume", UnaryOp(builder.manager.next_atom(), "Reference", vvars[0], bits=64))
    builder.write_bytes(-104, data[4:])
    simplifier, statements = builder.run()

    assert builder.wide_copies(simplifier, statements) == [(-108, data[:4], 4), (-104, data[4:], 4)]
    assert isinstance(statements[1], SideEffectStatement) and statements[1].expr.target == "consume"


def test_wcscpy_keeps_writes_whose_values_are_used():
    builder = _WcscpyBlockBuilder()
    vvars = builder.write_bytes(-108, "abcd".encode("utf-16le"))
    builder.call("consume", vvars[2])
    _, statements = builder.run()

    assert [stmt.dst.stack_offset for stmt in statements[:3]] == [-108, -107, -106]


def test_wcscpy_keeps_terminator():
    builder = _WcscpyBlockBuilder()
    builder.write_bytes(-108, APPDATA_PATH + b"\x00\x00")
    simplifier, statements = builder.run()

    assert builder.wide_copies(simplifier, statements) == [(-108, APPDATA_PATH, 62)]
    assert len(statements) == 1
    assert simplifier.is_inlined_wcscpy(statements[0])


def test_wcscpy_wide_string_check_returns_all_bytes():
    data = APPDATA_PATH + b"\x00\x00"
    for endness, byteorder in ((Endness.BE, "big"), (Endness.LE, "little")):
        r, s = InlinedWcscpySimplifier.is_integer_likely_a_wide_string(
            int.from_bytes(data, byteorder), len(data), endness, min_length=2, char_endness=Endness.LE
        )
        assert r and s == data
    # half a code unit is not a wide string
    assert InlinedWcscpySimplifier.is_integer_likely_a_wide_string(0x41, 1, Endness.LE, min_length=1) == (False, None)
    # characters must be in the requested byte order
    assert InlinedWcscpySimplifier.is_integer_likely_a_wide_string(
        int.from_bytes(b"\x00c\x00d", "big"), 4, Endness.BE, min_length=1, char_endness=Endness.LE
    ) == (False, None)


def test_wcscpy_does_not_merge_half_code_units():
    builder = _WcscpyBlockBuilder()
    vvars = builder.write_bytes(-108, "abcd".encode("utf-16le"))
    builder.call("consume", vvars[7])
    simplifier, statements = builder.run()

    # the stride is cut before the used byte, and the lone "d" byte must stay a byte write
    assert builder.wide_copies(simplifier, statements) == [(-108, "abc".encode("utf-16le"), 6)]
    assert [stmt.dst.stack_offset for stmt in statements if isinstance(stmt, Assignment)] == [-102, -101]


def test_wcscpy_consolidation_keeps_terminator_of_second_call():
    simplifier = _simplifier(InlinedWcscpySimplifier)
    first = _inlined_wcsncpy(simplifier, 0, 0, b"A\x00B\x00")
    second = _inlined_wcsncpy(simplifier, 10, 4, b"C\x00", count=Const(11, 2, 64))

    (merged,) = simplifier._consolidate_wcscpy_calls([first, second])
    assert simplifier.is_inlined_wcscpy(merged)
    assert simplifier._copied_bytes(merged) == b"A\x00B\x00C\x00\x00\x00"
    # nothing is appended after a terminator
    third = _inlined_wcsncpy(simplifier, 20, 10, b"D\x00")
    assert simplifier._consolidate_wcscpy_calls([merged, third]) is None


def test_wcscpy_keeps_bytes_after_terminator():
    builder = _WcscpyBlockBuilder()
    builder.write_bytes(-108, "abc".encode("utf-16le") + b"\x00" * 4)
    simplifier, statements = builder.run()

    assert builder.wide_copies(simplifier, statements) == [(-108, "abc".encode("utf-16le"), 8)]
    assert simplifier.is_inlined_wcscpy(statements[0])
    assert [stmt.dst.stack_offset for stmt in statements[1:]] == [-100, -99]


def test_wcscpy_padded_copy_stays_wcsncpy():
    # wcscpy would only write one of the two null characters
    simplifier = _simplifier(InlinedWcscpySimplifier)
    call = simplifier._make_wide_copy_call(StackBaseOffset(0, 64, 0), b"A\x00\x00\x00\x00\x00", {})

    assert call.target == "wcsncpy"
    assert call.args[2].value_int == 3


def test_wcscpy_consolidation_merges_into_trailing_wcscpy():
    simplifier = _simplifier(InlinedWcscpySimplifier)
    first = _inlined_wcsncpy(simplifier, 0, 0, b"A\x00B\x00")
    second = _inlined_wcsncpy(simplifier, 10, 4, b"C\x00", count=Const(11, 2, 64))
    (wcscpy_stmt,) = simplifier._consolidate_wcscpy_calls([first, second])
    later = _inlined_wcsncpy(simplifier, 20, -4, b"Z\x00Y\x00")

    (merged,) = simplifier._consolidate_wcscpy_calls([later, wcscpy_stmt])
    assert simplifier.is_inlined_wcscpy(merged)
    assert simplifier._copied_bytes(merged) == b"Z\x00Y\x00A\x00B\x00C\x00\x00\x00"


def test_wcscpy_destination_is_lowest_stack_variable():
    builder = _WcscpyBlockBuilder()
    vvars = builder.write_bytes(-108, APPDATA_PATH + b"\x00\x00")
    _, statements = builder.run()

    (stmt,) = statements
    dst = stmt.expr.args[0]
    # the call now defines the variable whose assignment it replaced
    assert isinstance(dst, UnaryOp) and dst.op == "Reference" and dst.tags.get("extra_def", False)
    assert dst.operand.varid == vvars[0].varid
    assert stmt.tags["extra_defs"] == [vvars[0].varid]


def test_wcscpy_early_folds_stack_stores():
    builder = _WcscpyBlockBuilder()
    builder.store_bytes(-108, APPDATA_PATH + b"\x00\x00")
    simplifier, statements = builder.run(InlinedWcscpySimplifier)

    assert builder.wide_copies(simplifier, statements) == [(-108, APPDATA_PATH, 62)]
    (stmt,) = statements
    assert simplifier.is_inlined_wcscpy(stmt)
    # stack variable recovery turns the stack offset into a variable later
    assert isinstance(stmt.expr.args[0], StackBaseOffset)


def test_wcscpy_early_folds_prefix_before_unknown_store():
    builder = _WcscpyBlockBuilder()
    builder.store_bytes(-108, APPDATA_PATH)
    unknown = VirtualVariable(builder.manager.next_atom(), 100, 32, VirtualVariableCategory.REGISTER, oident=0)
    builder.statements.append(
        Store(builder.manager.next_atom(), StackBaseOffset(builder.manager.next_atom(), 64, -48), unknown, 4, "Iend_LE")
    )
    builder.store_bytes(-44, b"\xe0\xe1")
    simplifier, statements = builder.run(InlinedWcscpySimplifier)

    assert builder.wide_copies(simplifier, statements) == [(-108, APPDATA_PATH, 60)]
    assert len(statements) == 4


def test_wcscpy_early_stride_starts_at_later_statement():
    # stores in descending address order: the lowest one is written last
    builder = _WcscpyBlockBuilder()
    data = "abcd".encode("utf-16le")
    for offset in range(6, -1, -2):
        builder.store_bytes(-108 + offset, data[offset : offset + 2])
    simplifier, statements = builder.run(InlinedWcscpySimplifier)

    assert builder.wide_copies(simplifier, statements) == [(-108, data, 8)]


def test_wcscpy_early_writes_to_start_of_stride():
    builder = _WcscpyBlockBuilder()
    builder.store_bytes(-120, b"A")
    builder.store_bytes(-108, "abcd".encode("utf-16le"))
    simplifier, statements = builder.run(InlinedWcscpySimplifier)

    assert builder.wide_copies(simplifier, statements) == [(-108, "abcd".encode("utf-16le"), 8)]
    assert isinstance(statements[0], Store) and statements[0].addr.offset == -120


def test_wcscpy_early_does_not_hoist_stores_across_barriers():
    data = "abcd".encode("utf-16le")
    pointer = VirtualVariable(0, 100, 64, VirtualVariableCategory.REGISTER, oident=0)
    for barrier in ("call", "store"):
        builder = _WcscpyBlockBuilder()
        builder.store_bytes(-108, data[:4])
        if barrier == "call":
            builder.call("consume", StackBaseOffset(builder.manager.next_atom(), 64, -108))
        else:
            # may alias the stack buffer
            builder.statements.append(
                Store(builder.manager.next_atom(), pointer, Const(builder.manager.next_atom(), 0x41, 8), 1, "Iend_LE")
            )
        builder.store_bytes(-104, data[4:])
        simplifier, statements = builder.run(InlinedWcscpySimplifier)

        assert builder.wide_copies(simplifier, statements) == [(-108, data[:4], 4), (-104, data[4:], 4)]
        assert len(statements) == 3


def test_strcpy_late_destination_is_lowest_stack_variable():
    # after SSA, the string is written through partial updates of dword stack variables
    builder = _WcscpyBlockBuilder()
    vvars = builder.insert_bytes(-108, b"hell")
    for i, chunk in enumerate((b"o, w", b"orld")):
        builder.insert_bytes(-104 + i * 4, chunk)
    _, statements = builder.run(InlinedStrcpySimplifierLate)

    (stmt,) = statements
    assert isinstance(stmt, SideEffectStatement) and stmt.expr.target == "strncpy"
    dst = stmt.expr.args[0]
    # a raw stack offset created after SSA is never turned into a stack variable
    assert isinstance(dst, UnaryOp) and dst.op == "Reference" and dst.tags.get("extra_def", False)
    assert dst.operand.varid == vvars[0].varid
    assert stmt.tags["extra_defs"] == [vvars[0].varid]


def _strcpy_copies(builder, simplifier, statements):
    """
    Return (dst stack offset, string, count or None for strcpy) of each inlined string copy.
    """
    copies = []
    for stmt in statements:
        if (
            isinstance(stmt, SideEffectStatement)
            and stmt.expr.target in {"strcpy", "strncpy"}
            and stmt.expr.args is not None
            and variable_map_of(simplifier.manager).custom_string(stmt.expr.args[1])
        ):
            _, offset = simplifier._parse_addr(stmt.expr.args[0])
            text = builder.project.kb.custom_strings[stmt.expr.args[1].value_int]
            count = stmt.expr.args[2].value_int if len(stmt.expr.args) == 3 else None
            copies.append((offset, text, count))
    return copies


def test_strcpy_does_not_hoist_stores_across_barriers():
    pointer = VirtualVariable(0, 100, 64, VirtualVariableCategory.REGISTER, oident=0)
    for barrier in ("call", "store"):
        builder = _WcscpyBlockBuilder()
        builder.store_bytes(-108, b"hello, ")
        if barrier == "call":
            builder.call("consume", StackBaseOffset(builder.manager.next_atom(), 64, -108))
        else:
            # may alias the stack buffer
            builder.statements.append(
                Store(builder.manager.next_atom(), pointer, Const(builder.manager.next_atom(), 0x41, 8), 1, "Iend_LE")
            )
        builder.store_bytes(-101, b"world!!")
        simplifier, statements = builder.run(InlinedStrcpySimplifier)

        assert _strcpy_copies(builder, simplifier, statements) == [(-108, b"hello, ", 7), (-101, b"world!!", 7)]
        assert len(statements) == 3


def test_strcpy_folds_prefix_before_unknown_store():
    builder = _WcscpyBlockBuilder()
    builder.store_bytes(-108, b"hello, world")
    unknown = VirtualVariable(builder.manager.next_atom(), 100, 32, VirtualVariableCategory.REGISTER, oident=0)
    builder.statements.append(
        Store(builder.manager.next_atom(), StackBaseOffset(builder.manager.next_atom(), 64, -96), unknown, 4, "Iend_LE")
    )
    simplifier, statements = builder.run(InlinedStrcpySimplifier)

    assert _strcpy_copies(builder, simplifier, statements) == [(-108, b"hello, world", 12)]
    assert len(statements) == 2


def test_strcpy_late_keeps_updates_whose_values_are_used():
    builder = _WcscpyBlockBuilder()
    builder.insert_bytes(-108, b"hell")
    vvars = builder.insert_bytes(-104, b"o, w")
    builder.call("consume", vvars[-1])
    simplifier, statements = builder.run(InlinedStrcpySimplifierLate)

    # removing the updates at -104 would leave the variable passed to consume() undefined
    assert _strcpy_copies(builder, simplifier, statements) == [(-108, b"hell", 4)]
    assert sum(isinstance(stmt, Assignment) and isinstance(stmt.src, Insert) for stmt in statements) == 4


def test_strcpy_late_folds_constant_stack_assignments():
    builder = _WcscpyBlockBuilder()
    vvars = builder.write_bytes(-108, b"hello, world")
    simplifier, statements = builder.run(InlinedStrcpySimplifierLate)

    assert _strcpy_copies(builder, simplifier, statements) == [(-108, b"hello, world", 12)]
    (stmt,) = statements
    assert stmt.expr.args[0].operand.varid == vvars[0].varid


def test_strcpy_late_rejects_insert_into_a_different_variable():
    # the base covers a different range than the destination, so the other bytes of the destination change too
    builder = _WcscpyBlockBuilder()
    builder.insert_bytes(-108, b"hell")
    base = builder.vvar(-104, bits=64)
    for i, byte in enumerate(b"o, w"):
        dst = builder.vvar(-104, bits=32)
        update = Insert(
            builder.manager.next_atom(),
            base,
            Const(builder.manager.next_atom(), i, 64),
            Const(builder.manager.next_atom(), byte, 8),
            "Iend_LE",
        )
        builder.statements.append(Assignment(builder.manager.next_atom(), dst, update))
        base = dst
    simplifier, statements = builder.run(InlinedStrcpySimplifierLate)

    assert _strcpy_copies(builder, simplifier, statements) == [(-108, b"hell", 4)]
    assert len(statements) == 5


def test_strcpy_late_keeps_terminator():
    builder = _WcscpyBlockBuilder()
    builder.write_bytes(-108, b"hello, world\x00")
    simplifier, statements = builder.run(InlinedStrcpySimplifierLate)

    # strcpy writes the terminator
    assert _strcpy_copies(builder, simplifier, statements) == [(-108, b"hello, world", None)]
    assert len(statements) == 1


def test_strcpy_keeps_padding_after_terminator():
    builder = _WcscpyBlockBuilder()
    builder.store_bytes(-108, b"hello\x00\x00\x00")
    simplifier, statements = builder.run(InlinedStrcpySimplifier)

    # strncpy pads the destination with zeros up to the count
    assert _strcpy_copies(builder, simplifier, statements) == [(-108, b"hello", 8)]
    assert len(statements) == 1


def test_strcpy_string_check_returns_all_bytes():
    data = b"hello\x00\x00\x00"
    for endness, byteorder in ((Endness.BE, "big"), (Endness.LE, "little")):
        r, s = InlinedStrcpySimplifier.is_integer_likely_a_string(int.from_bytes(data, byteorder), len(data), endness)
        assert r and s == data
    # a nonzero byte after the terminator is not part of the string
    assert InlinedStrcpySimplifier.is_integer_likely_a_string(int.from_bytes(b"hello\x00ab", "big"), 8, Endness.BE) == (
        False,
        None,
    )


def test_strcpy_consolidation_uses_copied_bytes():
    builder = _WcscpyBlockBuilder()
    builder.store_bytes(-108, b"hello, ")
    zero = Store(
        builder.manager.next_atom(),
        StackBaseOffset(builder.manager.next_atom(), 64, -101),
        Const(builder.manager.next_atom(), 0, 16),
        2,
        "Iend_LE",
    )
    builder.statements.append(zero)
    simplifier, statements = builder.run(InlinedStrcpySimplifier)

    # the zero store is merged, and both of its bytes are still written
    assert _strcpy_copies(builder, simplifier, statements) == [(-108, b"hello, ", 9)]
    assert len(statements) == 1
