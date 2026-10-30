from __future__ import annotations

from angr import ailment
from angr.ailment import AILBlockRewriter, Block
from angr.ailment.expression import Call, Const
from angr.ailment.statement import Jump, Label, SideEffectStatement, Statement
from angr.utils.loader import is_in_section, is_known_writable_address, is_readable_address, object_has_sections

# An upper bound on the length of a literal to read. A misidentified constant's length word is arbitrary,
# and Clemory.load materialises the bytes before anything can reject them.
MAX_STR_LEN = 0x100000

# The shortest string to believe when the object it came from publishes no sections at all. One byte of a
# pointer is valid UTF-8 about half the time.
MIN_UNVERIFIED_STR_LEN = 2


def extract_callee(obj, kb):
    if isinstance(obj, ailment.Block) and obj.statements:
        for stmt in reversed(obj.statements):
            if isinstance(stmt, Call):
                return extract_callee(stmt, kb)
            if not isinstance(stmt, Label) or not isinstance(stmt, Jump):
                break
    if isinstance(obj, Call) and isinstance(obj.target, Const):
        callee_addr = obj.target.value
        if callee_addr in kb.functions:
            return kb.functions[callee_addr]
    return None


def looks_like_text(decoded_str: str) -> bool:
    """
    Decide whether a decoded string is good enough to believe with no section behind it.
    """
    return len(decoded_str) >= MIN_UNVERIFIED_STR_LEN and all(c in "\t\n\r" or c.isprintable() for c in decoded_str)


def _is_described_data(project, addr):
    """
    Decide whether `addr` is somewhere worth reading a literal out of.

    An object that publishes sections and does not cover an address with one is saying something about that
    address; an object with no sections at all -- a blob -- is not, and there the bytes have to speak for
    themselves. So the loosening applies to the second and not to a hole in the first.
    """
    return is_readable_address(project, addr) and (
        is_in_section(project, addr) or not object_has_sections(project, addr)
    )


def _points_at_constant_data(project, addr):
    """
    Decide whether `addr` may hold a string literal, before its bytes are read.
    """
    return _is_described_data(project, addr) and not is_known_writable_address(project, addr)


def extract_str(project, str_ptr, str_len):
    """
    Extract a Rust string literal with the given pointer and length.
    """
    if str_len == 0:
        return ""
    if str_ptr < 0 or not 0 < str_len <= MAX_STR_LEN:
        return None
    if not _points_at_constant_data(project, str_ptr) or not is_readable_address(project, str_ptr + str_len - 1):
        return None
    try:
        data = project.loader.memory.load(str_ptr, str_len)
    except KeyError:
        return None
    if len(data) != str_len:
        # Clemory.load stops at the end of a backer rather than raising
        return None
    try:
        decoded_str = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not is_in_section(project, str_ptr) and not looks_like_text(decoded_str):
        return None
    return decoded_str


def extract_str_from_addr(project, addr):
    """
    Read a Rust &str fat pointer -- a data pointer followed by a length word -- at the given address.

    Reading the pointer says nothing about the word beside it: a constant at the end of a backer has no
    following word, and cle reports that as a KeyError.
    """
    if addr < 0 or not _is_described_data(project, addr):
        return None
    try:
        memory = project.loader.memory
        str_ptr = memory.unpack(addr, project.arch.struct_fmt())[0]
        str_len = memory.unpack(addr + project.arch.bytes, project.arch.struct_fmt())[0]
    except KeyError:
        return None
    if str_len == 0:
        # extract_str's short-circuit does not look at the pointer, and here we have not established that
        # this is a fat pointer at all. An empty literal carries no bytes for looks_like_text to judge, so
        # it is taken only where a section says the pointer is constant data -- never on the strength of an
        # object having no sections, which is what the rest of this reader loosens for.
        if is_in_section(project, str_ptr) and is_readable_address(project, str_ptr):
            return "" if not is_known_writable_address(project, str_ptr) else None
        return None
    return extract_str(project, str_ptr, str_len)


class SideEffectStatementRewriter(AILBlockRewriter):
    """Rewrite SideEffectStatement nodes via a callback."""

    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def _handle_SideEffectStatement(self, stmt_idx: int, stmt: SideEffectStatement, block: Block | None):
        new_stmt = self.callback(stmt, block, stmt)
        if new_stmt and block is not None:
            block.statements[stmt_idx] = new_stmt
        return new_stmt


class CallRewriter(AILBlockRewriter):
    """Rewrite Call expressions and SideEffectStatements via a callback."""

    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def _handle_Call(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement | None, block: Block | None):
        new_stmt = self.callback(expr, block, stmt)
        if new_stmt and block is not None:
            block.statements[stmt_idx] = new_stmt
        # Fall back to the input expression so the walker treats this as "no change."
        return new_stmt if new_stmt is not None else expr


def replace_argument_pairs(call: Call, callback) -> Call:
    if not call.args:
        return call
    queue = list(call.args)
    new_args = []
    changed = False
    while len(queue) > 1:
        arg = queue.pop(0)
        next_arg = queue.pop(0)
        replaced, replacement = callback(arg, next_arg)
        if replaced:
            new_args.extend(replacement)
            changed = True
        else:
            new_args.append(arg)
            queue.insert(0, next_arg)
    if changed:
        new_args.extend(queue)
        new_call = call.copy()
        new_call.args = new_args
        return new_call
    return call
