//! x86 table resolvers: `X86PeIatResolver` and `AMD64PeIatResolver` (calls and jumps through an import address
//! table slot), and the filter of `X86ElfPicPltResolver` (its resolve executes the stub symbolically).

use pyo3::prelude::*;

use super::amd64_got::{IndirectOperand, decode_indirect_operand};
use super::cx::IrSpec;
use super::{Decision, Effects, JumpSite, Outcome, ResolveCx, Resolver};
use crate::vexir::{Stmt, VexIrsb};
use crate::vexlift::{VEX_IRSB_MAX_SIZE, jumpkind_name};

/// The last instruction of a lifted block, from its last IMark.
fn last_insn(ir: &VexIrsb) -> Option<(u64, u32)> {
    ir.stmts.iter().rev().find_map(|s| match s {
        Stmt::IMark { addr, len, .. } => Some((*addr, *len)),
        _ => None,
    })
}

/// The first operand of a 32-bit `FF /2` or `FF /4`: Some(Some(disp)) for `[disp32]` (no base, no index, non-zero
/// displacement), Some(None) for any other operand, None when capstone's view is not reproduced here.
fn decode_x86_abs_operand(bytes: &[u8]) -> Option<Option<u64>> {
    let mut i = 0;
    while i < bytes.len() && matches!(bytes[i], 0x2e | 0x3e | 0x26 | 0x36 | 0x64 | 0x65 | 0xf2) {
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
        return (bytes.len() == i + 2).then_some(None);
    }
    if md == 0 && rm == 5 {
        if bytes.len() != i + 6 {
            return None;
        }
        let disp = u32::from_le_bytes(bytes[i + 2..i + 6].try_into().ok()?);
        // capstone sign-extends disp; the slot read uses its value as an address
        let disp = disp as i32 as i64 as u64;
        return Some((disp != 0).then_some(disp));
    }
    let sib = rm == 4;
    if sib
        && md == 0
        && bytes
            .get(i + 2)
            .is_some_and(|s| s & 7 == 5 && (s >> 3) & 7 == 4)
    {
        // [disp32] through a SIB byte without base and index: capstone reports it like the plain form
        return None;
    }
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
    (bytes.len() == i + 2 + sib as usize + disp_len).then_some(None)
}

pub struct X86PeIatResolver;

impl X86PeIatResolver {
    /// `factory.block(addr).capstone.insns[-1]`'s first operand.
    fn operand(
        py: Python<'_>,
        cx: &mut ResolveCx,
        addr: u64,
    ) -> PyResult<Result<Option<u64>, &'static str>> {
        let spec = IrSpec {
            addr,
            max_size: VEX_IRSB_MAX_SIZE as i64,
            opt_level: cx.default_opt_level,
            cross_insn_opt: true,
            extra_stops: false,
        };
        let ir = match cx.ir(py, &spec)? {
            Ok(ir) => ir,
            Err(fb) => return Ok(Err(fb.name())),
        };
        let Some((a, len)) = last_insn(&ir) else {
            return Ok(Err("no_insn"));
        };
        let Some(bytes) = cx
            .snap
            .load_bytes(a, len as usize)
            .filter(|b| b.len() == len as usize)
        else {
            return Ok(Err("no_bytes"));
        };
        Ok(decode_x86_abs_operand(&bytes).ok_or("operand"))
    }
}

impl Resolver for X86PeIatResolver {
    fn kind(&self) -> &'static str {
        "X86PeIatResolver"
    }

    fn timeless(&self) -> bool {
        true
    }

    fn filter(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
    ) -> PyResult<Decision<bool>> {
        if !matches!(jumpkind_name(j.jumpkind), "Ijk_Call" | "Ijk_Boring") {
            return Ok(Decision::Done(false));
        }
        Ok(match Self::operand(py, cx, j.addr)? {
            Ok(op) => Decision::Done(op.is_some()),
            Err(d) => Decision::Python(d),
        })
    }

    fn resolve(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
        _fx: &mut Effects,
    ) -> PyResult<Decision<Outcome>> {
        let slot = match Self::operand(py, cx, j.addr)? {
            Ok(Some(slot)) => slot,
            Ok(None) => return Ok(Decision::Python("operand")),
            Err(d) => return Ok(Decision::Python(d)),
        };
        let Some(target) = cx.snap.load_word(slot, cx.arch.bytes as usize) else {
            return Ok(Decision::Done(Outcome::Unresolved));
        };
        if cx.is_hooked(py, target)? {
            return Ok(Decision::Done(Outcome::Resolved(vec![target])));
        }
        Ok(Decision::Done(Outcome::Unresolved))
    }
}

pub struct Amd64PeIatResolver {
    /// `isinstance(project.simos, SimWindows)`
    pub windows: bool,
}

impl Amd64PeIatResolver {
    /// `factory.block(addr, size=block.size).capstone.insns[-1]`'s rip-relative slot.
    fn slot(
        py: Python<'_>,
        cx: &mut ResolveCx,
        j: &JumpSite,
    ) -> PyResult<Result<Option<u64>, &'static str>> {
        let ir = match cx.ir(py, &j.block)? {
            Ok(ir) => ir,
            Err(fb) => return Ok(Err(fb.name())),
        };
        // the bytes of factory.block(addr, size=block.size): the last instruction is the one ending the block
        let Some((a, len)) = last_insn(&ir) else {
            return Ok(Err("no_insn"));
        };
        let Some(bytes) = cx
            .snap
            .load_bytes(a, len as usize)
            .filter(|b| b.len() == len as usize)
        else {
            return Ok(Err("no_bytes"));
        };
        Ok(match decode_indirect_operand(a, &bytes) {
            Some(IndirectOperand::RipSlot(s)) => Ok(Some(s)),
            Some(IndirectOperand::Other) => Ok(None),
            None => Err("operand"),
        })
    }
}

impl Resolver for Amd64PeIatResolver {
    fn kind(&self) -> &'static str {
        "AMD64PeIatResolver"
    }

    fn timeless(&self) -> bool {
        true
    }

    fn filter(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
    ) -> PyResult<Decision<bool>> {
        if !self.windows || !matches!(jumpkind_name(j.jumpkind), "Ijk_Call" | "Ijk_Boring") {
            return Ok(Decision::Done(false));
        }
        Ok(match Self::slot(py, cx, j)? {
            Ok(s) => Decision::Done(s.is_some()),
            Err(d) => Decision::Python(d),
        })
    }

    fn resolve(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
        _fx: &mut Effects,
    ) -> PyResult<Decision<Outcome>> {
        let slot = match Self::slot(py, cx, j)? {
            Ok(Some(s)) => s,
            Ok(None) => return Ok(Decision::Python("operand")),
            Err(d) => return Ok(Decision::Python(d)),
        };
        let Some(target) = cx.snap.load_word(slot, cx.arch.bytes as usize) else {
            return Ok(Decision::Done(Outcome::Unresolved));
        };
        if cx.is_hooked(py, target)? {
            return Ok(Decision::Done(Outcome::Resolved(vec![target])));
        }
        Ok(Decision::Done(Outcome::Unresolved))
    }
}

/// `X86ElfPicPltResolver`: the filter in Rust (a one-instruction, 6-byte block in `.plt`).
pub struct X86ElfPicPltResolver {
    /// `isinstance(project.arch, ArchX86)`
    pub is_x86: bool,
}

impl Resolver for X86ElfPicPltResolver {
    fn kind(&self) -> &'static str {
        "X86ElfPicPltResolver"
    }

    fn timeless(&self) -> bool {
        true
    }

    fn filter(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
    ) -> PyResult<Decision<bool>> {
        if !self.is_x86 {
            return Ok(Decision::Done(false));
        }
        let snap = cx.snap.clone();
        let Some((oi, si)) = snap.find_section_containing(j.addr) else {
            return Ok(Decision::Done(false));
        };
        if snap.objects[oi].sections[si].name.as_deref() != Some(".plt") {
            return Ok(Decision::Done(false));
        }
        let ir = match cx.ir(py, &j.block)? {
            Ok(ir) => ir,
            Err(fb) => return Ok(Decision::Python(fb.name())),
        };
        Ok(Decision::Done(ir.size == 6 && ir.instructions == 1))
    }

    fn resolve(
        &mut self,
        _py: Python<'_>,
        _cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        _j: &JumpSite,
        _fx: &mut Effects,
    ) -> PyResult<Decision<Outcome>> {
        Ok(Decision::Python("symbolic"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abs_operands() {
        assert_eq!(
            decode_x86_abs_operand(&[0xff, 0x15, 0x10, 0x20, 0x40, 0]),
            Some(Some(0x402010))
        );
        assert_eq!(
            decode_x86_abs_operand(&[0xff, 0x25, 0, 0, 0, 0]),
            Some(None)
        );
        assert_eq!(decode_x86_abs_operand(&[0xff, 0xd0]), Some(None));
        assert_eq!(decode_x86_abs_operand(&[0xff, 0x50, 0x08]), Some(None));
        assert_eq!(decode_x86_abs_operand(&[0xe8, 0, 0, 0, 0]), None);
    }
}
