# AIL Subsystem (angr Intermediate Language)

All under `ailment/`. Higher-level IR than VEX for decompiler readability. VEX temps eliminated; uses explicit Register/VirtualVariable references.

## Core Types
- tagged_object.py — `TaggedObject`: base with `idx` (unique ID), `tags` dict (ins_addr, type, reg_name)
- block.py — `Block`: container with `addr`, `original_size`, `statements: list[Statement]`
- manager.py — `Manager`: factory; `next_atom()` generates unique IDs

## Expression Hierarchy (expression.py)
`Expression(TaggedObject)` — has `bits`, `depth`. All support `likes()`, `matches()`, `replace()`, `copy()`.

- Atom(Expression) — leaf base; depth=0; has `variable`, `variable_offset`
  - Const — `value` (int/float), `bits`
  - Tmp — `tmp_idx`, `bits` (early pipeline only)
  - Register — `reg_offset`, `bits`
  - VirtualVariable — `varid`, `category` (REGISTER/STACK/MEMORY/PARAMETER/TMP); SSA variable
  - Phi — `src_and_vvars`; SSA phi node
- Op(Expression) — base for operators; has `op` (str)
  - UnaryOp — `operand` (Not, Neg)
  - Convert(UnaryOp) — `from_bits`, `to_bits`, `is_signed`, `from_type`, `to_type`
  - Reinterpret(UnaryOp) — bitwise reinterpret (no value change)
  - BinaryOp — `operands` list[2], `signed` (Add, Sub, CmpEQ, Sar, etc.)
- Load — `addr`, `size`, `endness`, `guard`; memory read
- ITE — `cond`, `iftrue`, `iffalse`
- DirtyExpression — `callee`, `guard`, `args`; VEX dirty helper call
- VEXCCallExpression — `callee`, `operands`; VEX CCall (e.g. x86g_calculate_condition)
- CallExpr — `target`, `args`, `ret_expr`, `prototype`, `calling_convention`; a call that produces a return value (used as sub-expression)
- BasePointerOffset/StackBaseOffset — `offset`, `bits`
- Extract/Insert — bit range extraction/insertion on operands
- MultiStatementExpression — wraps multiple stmts as one expr

## Statement Hierarchy (statement.py)
`Statement(TaggedObject)` — all support `likes()`, `matches()`, `replace()`, `copy()`.

- Assignment — `dst` (Atom), `src` (Expression)
- WeakAssignment — non-defining assignment
- Store — `addr`, `data`, `size`, `endness`, `guard`; memory write
- Jump — `target`, `target_idx`; unconditional goto
- ConditionalJump — `condition`, `true_target`, `false_target`
- SideEffectStatement — `target`, `args`, `prototype`, `calling_convention`; a call invoked only for side effects (no return value used). Replaces old unified `Call` node.
- Return — `ret_exprs`
- CAS — `addr`, `expected`, `desired`, `size`; compare-and-swap
- DirtyStatement — wraps dirty helper as stmt
- Label — `name`, `block_idx`

## Block Walker (block_walker.py)
- `AILBlockWalker` — generic visitor; dispatches by type to handler dicts
- `AILBlockViewer` — side-effect-only traversal
- `AILBlockRewriter` — returns new exprs/stmts (transformed Block)

## Converters
- converter_vex.py — `VEXIRSBConverter`: pyvex IRSB → AIL Block
- converter_pcode.py — `PCodeIRSBConverter`: P-Code → AIL Block
- `__init__.py` — `IRSBConverter`: auto-dispatches to VEX or PCode
