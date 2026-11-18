//! `AMD64ElfGotResolver`: `call/jmp qword ptr [rip + disp]` through a GOT slot.
//!
//! The Python resolver disassembles the block's last instruction with capstone and checks its first operand. Here
//! the instruction bytes are decoded directly; forms whose capstone operand is not obvious decline to the twin.

use pyo3::prelude::*;

use super::{Decision, Effects, JumpSite, Outcome, ResolveCx, Resolver};
use crate::vexir::Stmt;
use crate::vexlift::jumpkind_name;

pub struct Amd64ElfGotResolver;

/// What capstone reports as the first operand of an x86-64 instruction ending a block with an indirect exit.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IndirectOperand {
    /// `[rip + disp]` of `call`/`jmp` (FF /2, FF /4) with a non-zero displacement: the slot address.
    RipSlot(u64),
    /// An operand that is not `[rip + non-zero disp]` (registers, other bases, SIB forms, a zero displacement).
    Other,
}

/// Decode the instruction at `addr` (`bytes` is exactly one instruction). None when capstone's view is not
/// reproduced here.
pub(crate) fn decode_indirect_operand(addr: u64, bytes: &[u8]) -> Option<IndirectOperand> {
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            // segment overrides, notrack (3e), bnd (f2)
            0x2e | 0x3e | 0x26 | 0x36 | 0x64 | 0x65 | 0xf2 => i += 1,
            _ => break,
        }
    }
    if i < bytes.len() && (0x40..=0x4f).contains(&bytes[i]) {
        i += 1;
    }
    if bytes.get(i) != Some(&0xff) {
        return None;
    }
    let modrm = *bytes.get(i + 1)?;
    let (md, reg, rm) = (modrm >> 6, (modrm >> 3) & 7, modrm & 7);
    if reg != 2 && reg != 4 {
        return None;
    }
    if md == 3 {
        // register operand
        return (bytes.len() == i + 2).then_some(IndirectOperand::Other);
    }
    if md == 0 && rm == 5 {
        // rip-relative: ff /r disp32
        if bytes.len() != i + 6 {
            return None;
        }
        let disp = i32::from_le_bytes(bytes[i + 2..i + 6].try_into().ok()?) as i64;
        if disp == 0 {
            return Some(IndirectOperand::Other);
        }
        let next = addr.wrapping_add(bytes.len() as u64);
        return Some(IndirectOperand::RipSlot(next.wrapping_add(disp as u64)));
    }
    // a memory operand with a register base or a SIB byte: never rip-based
    let sib = rm == 4;
    let disp_len = match md {
        0 => {
            if sib && bytes.get(i + 2).is_some_and(|s| s & 7 == 5) {
                4
            } else {
                0
            }
        }
        1 => 1,
        _ => 4,
    };
    let expected = i + 2 + sib as usize + disp_len;
    (bytes.len() == expected).then_some(IndirectOperand::Other)
}

impl Resolver for Amd64ElfGotResolver {
    fn kind(&self) -> &'static str {
        "AMD64ElfGotResolver"
    }

    fn timeless(&self) -> bool {
        true
    }

    fn filter(
        &mut self,
        _py: Python<'_>,
        _cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
    ) -> PyResult<Decision<bool>> {
        let jk = jumpkind_name(j.jumpkind);
        Ok(Decision::Done(
            jk == "Ijk_Call" || (jk == "Ijk_Boring" && j.addr == j.func_addr),
        ))
    }

    fn resolve(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
        _fx: &mut Effects,
    ) -> PyResult<Decision<Outcome>> {
        let ir = match cx.ir(py, &j.block)? {
            Ok(ir) => ir,
            Err(fb) => return Ok(Decision::Python(fb.name())),
        };
        // the last instruction, from the last IMark
        let Some((insn_addr, insn_len)) = ir.stmts.iter().rev().find_map(|s| match s {
            Stmt::IMark { addr, len, .. } => Some((*addr, *len)),
            _ => None,
        }) else {
            return Ok(Decision::Done(Outcome::Unresolved));
        };
        let Some(bytes) = cx.snap.load_bytes(insn_addr, insn_len as usize) else {
            return Ok(Decision::Python("no_bytes"));
        };
        if bytes.len() != insn_len as usize {
            return Ok(Decision::Python("short_bytes"));
        }
        let slot = match decode_indirect_operand(insn_addr, &bytes) {
            Some(IndirectOperand::RipSlot(slot)) => slot,
            Some(IndirectOperand::Other) => return Ok(Decision::Done(Outcome::Unresolved)),
            None => return Ok(Decision::Python("operand")),
        };
        // cfg._fast_memory_load_pointer(slot)
        let Some(target) = cx.snap.load_word(slot, cx.arch.bytes as usize) else {
            return Ok(Decision::Done(Outcome::Unresolved));
        };
        if cx.snap.symbol_at(target).is_some() || cx.is_hooked(py, target)? {
            return Ok(Decision::Done(Outcome::Resolved(vec![target])));
        }
        Ok(Decision::Done(Outcome::Unresolved))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operands() {
        // call qword ptr [rip + 0x10]
        assert_eq!(
            decode_indirect_operand(0x1000, &[0xff, 0x15, 0x10, 0, 0, 0]),
            Some(IndirectOperand::RipSlot(0x1016))
        );
        // bnd jmp qword ptr [rip - 0x10]
        assert_eq!(
            decode_indirect_operand(0x1000, &[0xf2, 0xff, 0x25, 0xf0, 0xff, 0xff, 0xff]),
            Some(IndirectOperand::RipSlot(0x0ff7))
        );
        // jmp rax, call qword ptr [rax + 8], notrack jmp qword ptr [rax*8 + 0x1234]
        assert_eq!(
            decode_indirect_operand(0, &[0xff, 0xe0]),
            Some(IndirectOperand::Other)
        );
        assert_eq!(
            decode_indirect_operand(0, &[0xff, 0x50, 0x08]),
            Some(IndirectOperand::Other)
        );
        assert_eq!(
            decode_indirect_operand(0, &[0x3e, 0xff, 0x24, 0xc5, 0x34, 0x12, 0, 0]),
            Some(IndirectOperand::Other)
        );
        // address-size prefix, other opcodes
        assert_eq!(
            decode_indirect_operand(0, &[0x67, 0xff, 0x15, 1, 0, 0, 0]),
            None
        );
        assert_eq!(decode_indirect_operand(0, &[0xe8, 0, 0, 0, 0]), None);
    }
}
