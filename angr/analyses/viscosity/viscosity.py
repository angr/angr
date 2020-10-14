import struct
import math
from typing import List, Dict, Optional
import logging

from pyvex.stmt import IRStmt, IMark

from ..analysis import Analysis, AnalysesHub
from .edits import BaseEdit, BytesEdit, MaskedBytesEdit
from .differ import VEXBlockDiffer
from .encoding.amd64 import encodings as AMD64_ENCODINGS
from .encoding.armhf import encodings as ARMHF_ENCODINGS
from .encoding.base import VEXStatementsSkeleton, InstructionEncoding

_l = logging.getLogger(name=__name__)


class Diff:
    def __init__(self, ins_addr: int, original_statements: List[IRStmt], new_statements: List[IRStmt],
                 diff_stmts: Optional[List[int]]=None):
        self.ins_addr = ins_addr
        self.original_statements = original_statements
        self.new_statements = new_statements
        self.diff_stmts = diff_stmts


_all_encodings = {
    'AMD64': AMD64_ENCODINGS,
    'ARMHF': ARMHF_ENCODINGS,
}


class Viscosity(Analysis):
    """
    Viscosity is an analysis that performs experimental point-to-point instruction patching.

    Both original_block and new_vex_block must be lifted with cross_insn_opt=False.
    """
    def __init__(self, original_block, new_vex_block):

        self._original_block = original_block
        self._new_vex_block = new_vex_block

        self.result: List[BaseEdit] = [ ]

        # calculate instruction sizes
        self._ins_addrs = self._original_block.vex.instruction_addresses
        self._ins_sizes = [b - a for a, b in zip(self._ins_addrs,
                                                 list(self._ins_addrs[1:]) +
                                                      [self._original_block.addr + self._original_block.size])
                           ]

        self._analyze()

    def _analyze(self):

        if self.project.arch.name not in _all_encodings:
            raise KeyError("No instruction encoding information is available for architecture %s."
                           % self.project.arch.name)

        # find differences in terms of IRs between two blocks
        g_original = self._group_vex_statements(self._original_block.vex.statements)
        g_new = self._group_vex_statements(self._new_vex_block.statements)

        diffs: Dict[int,Diff] = { }

        for ins_addr in sorted(set(g_original.keys()) | set(g_new.keys())):
            if ins_addr in g_original and ins_addr in g_new:
                # compare every statement
                stmts_ori = g_original[ins_addr]
                stmts_new = g_new[ins_addr]

                if len(stmts_ori) != len(stmts_new):
                    d = Diff(ins_addr, stmts_ori, stmts_new, diff_stmts=None)
                    diffs[ins_addr] = d
                    continue

                # compare every statement
                diff_stmts = [ ]
                for idx, (stmt_ori, stmt_new) in enumerate(zip(stmts_ori, stmts_new)):
                    if stmt_ori != stmt_new:
                        diff_stmts.append(idx)
                if diff_stmts:
                    d = Diff(ins_addr, stmts_ori, stmts_new, diff_stmts=diff_stmts)
                    diffs[ins_addr] = d
                    continue

            elif ins_addr in g_original and ins_addr not in g_new:
                # an instruction is removed in the new block
                d = Diff(ins_addr, g_original[ins_addr], [ ])
                diffs[ins_addr] = d

            else:
                raise NotImplementedError()

        # determine which bytes/bits to modify
        if not diffs:
            return
        fallthrough_addr = self._original_block.addr + self._original_block.size
        proposed_edits: List[BaseEdit] = [ ]
        for ins_addr, diff in diffs.items():
            matching_required: bool = False
            if diff.diff_stmts:
                skeleton_ori = VEXStatementsSkeleton.from_statements(diff.original_statements, fallthrough_addr)
                skeleton_new = VEXStatementsSkeleton.from_statements(diff.new_statements, fallthrough_addr)
                for diff_stmt in diff.diff_stmts:
                    # compare the skeleton
                    sk_ori = skeleton_ori.skeleton[diff_stmt]
                    sk_new = skeleton_new.skeleton[diff_stmt]
                    if sk_ori == sk_new:
                        # we need to change the data - fall back to heuristics
                        _l.debug("skeletons are the same. attempt heuristics.")
                    else:
                        matching_required = True
                        _l.debug("skeletons are different. attempt smart matching.")

                if matching_required:
                    edits = self._attempt_skeleton_matching(diff, skeleton_new)
                    proposed_edits += edits
                else:
                    # heuristics
                    edits = self._attempt_heuristics(diff)
                    proposed_edits += edits

            else:
                # special case: an entire instruction is removed
                if not diff.new_statements:
                    # calculate the size of the instruction
                    ins_idx = self._ins_addrs.index(diff.ins_addr)
                    ins_size = self._ins_sizes[ins_idx]
                    edit = BytesEdit(diff.ins_addr, b"\x90" * ins_size)
                    proposed_edits.append(edit)

                else:
                    raise NotImplementedError()

        # TODO: Verify the proposed edits

        self.result = proposed_edits

    def _attempt_heuristics(self, diff: Diff) -> List[BaseEdit]:
        # find all data differences
        differ = VEXBlockDiffer(diff.original_statements, diff.new_statements, different_statements=diff.diff_stmts)

        edits: List[BaseEdit] = [ ]

        for stmt_idx, expr_idx, old_value, new_value in differ.diffs:
            # search in the instruction bytes for old_value, then replace it with new_value and relift

            # determine the minimal size
            v = old_value if old_value >= new_value else new_value
            size = (math.ceil(math.log(v + 1, 2)) + 7) // 8
            value_bytes = self._uint_to_bytes(old_value, size)

            # determine the instruction offset and size
            ins_offset = diff.ins_addr - self._original_block.addr
            ins_idx = self._ins_addrs.index(diff.ins_addr)
            ins_size = self._ins_sizes[ins_idx]

            # if not the first instruction, include the previous instruction
            if ins_idx != 0:
                ins_offset -= self._ins_sizes[ins_idx - 1]
                ins_size += self._ins_sizes[ins_idx - 1]

            # search
            ins_bytes = self._original_block.bytes[ins_offset : ins_offset + ins_size]
            value_bytes_offset = ins_bytes.find(value_bytes)
            if value_bytes_offset == -1:
                # not found
                continue
            # found it! replace?
            edit = BytesEdit(self._original_block.addr + ins_offset + value_bytes_offset,
                             self._uint_to_bytes(new_value, size),
                             orig=self._uint_to_bytes(old_value, size))
            edits.append(edit)

        return edits

    def _attempt_skeleton_matching(self, diff: Diff, skeleton: VEXStatementsSkeleton) -> List[BaseEdit]:

        edits: List[BaseEdit] = [ ]
        try:
            encodings = _all_encodings[self.project.arch.name]
        except KeyError:
            raise KeyError("No instruction encoding information is available for architecture %s."
                           % self.project.arch.name)
        for enc in encodings:
            if enc.vex_skeleton == skeleton:
                # we replace the bytes in the old block with the bytes in this matched encoding item, and then re-lift
                # to see if we achieve structural equivalence
                new_block_bytes = self._replace_block_bytes(self._original_block.bytes,
                                                            diff.ins_addr - self._original_block.addr,
                                                            enc)
                new_block = self.project.factory.block(self._original_block.addr, byte_string=new_block_bytes,
                                                       cross_insn_opt=False)
                grouped_stmts = self._group_vex_statements(new_block.vex.statements)
                fallthrough_addr = self._original_block.addr + self._original_block.size
                new_skeleton = VEXStatementsSkeleton.from_statements(grouped_stmts[diff.ins_addr],
                                                                     fallthrough_addr=fallthrough_addr)
                if new_skeleton == skeleton:
                    # yes we achieved structural equivalence!
                    # TODO: We probably need to run heuristics again but that's the story for another day
                    edit = MaskedBytesEdit(self._original_block.addr + diff.ins_addr - self._original_block.addr,
                                           enc.instr, enc.instr_mask
                                           )
                    edits.append(edit)
                    break
        return edits

    @staticmethod
    def _replace_block_bytes(block_bytes: bytes, offset: int, encoding: InstructionEncoding) -> bytes:
        new_block = block_bytes[:offset]
        assert len(encoding.instr) == len(encoding.instr_mask)
        for idx, (instr_byte, mask_byte) in enumerate(zip(encoding.instr, encoding.instr_mask)):
            b = (mask_byte & instr_byte) | (~mask_byte & block_bytes[idx + offset])
            new_block = new_block + bytes([b])
        new_block += block_bytes[offset+len(encoding.instr):]
        return new_block

    @staticmethod
    def _group_vex_statements(statements: List[IRStmt]) -> Dict[int,List[IRStmt]]:
        d: Dict[int,List[IRStmt]] = { }

        ins_addr = None
        curr: Optional[List[IRStmt]] = None
        for stmt in statements:
            if isinstance(stmt, IMark):
                # we come across a new instruction
                if curr:
                    d[ins_addr] = curr

                ins_addr = stmt.addr + stmt.delta
                curr = [ ]
            else:
                curr.append(stmt)

        if curr:
            d[ins_addr] = curr
        return d

    @staticmethod
    def _uint_to_bytes(n, size) -> bytes:
        if size == 1:
            fmtstr = "<B"
        elif size == 2:
            fmtstr = "<H"
        elif size == 4:
            fmtstr = "<I"
        elif size == 8:
            fmtstr = "<Q"
        else:
            raise ValueError("Unsupported size value %d." % size)

        return struct.pack(fmtstr, n)

    @staticmethod
    def edit_to_patch(edit: BaseEdit, project) -> 'Patch':
        if isinstance(edit, BytesEdit):
            return Patch(edit.addr, edit.new, comment="Generated by Viscosity. Original: %r" % edit)
        elif isinstance(edit, MaskedBytesEdit):
            # we need the original bytes
            orig = project.loader.memory.load(edit.addr, len(edit.new))
            new = b""
            for idx, (instr_byte, mask_byte) in enumerate(zip(edit.new, edit.mask)):
                b = (mask_byte & instr_byte) | (~mask_byte & orig[idx])
                new += bytes([b])
            return Patch(edit.addr, new, comment="Generated by Viscosity. Original: %r" % edit)
        raise NotImplementedError("Unsupported edit type %s." % type(edit))


AnalysesHub.register_default('Viscosity', Viscosity)

from ...knowledge_plugins.patches import Patch
