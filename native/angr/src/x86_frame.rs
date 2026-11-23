//! `CFGFast._bp_as_gpr_by_capstone` without capstone: does an X86/AMD64 block not set up the frame pointer?
//!
//! A small length decoder walks the block from its start like capstone's linear disassembly and recognizes
//! `mov ebp/rbp, esp/rsp` and `lea ebp/rbp, [esp/rsp ...]`. It accepts only encodings whose length and validity
//! capstone agrees on, and every instruction must start where VEX says one does; anything else is None (ask
//! capstone).

use pyo3::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Other,
    /// `mov ebp/rbp, esp/rsp` or `lea ebp/rbp, [esp/rsp ...]` at the native operand size.
    FrameSetup,
}

const BP: u8 = 5;
const SP: u8 = 4;

/// Length of ModRM + SIB + displacement at `b[i..]` (32/64-bit addressing).
fn modrm_len(b: &[u8], i: usize) -> Option<usize> {
    let m = *b.get(i)?;
    let (md, rm) = (m >> 6, m & 7);
    if md == 3 {
        return Some(1);
    }
    let mut n = 1;
    let mut base = rm;
    if rm == 4 {
        base = *b.get(i + 1)? & 7;
        n += 1;
    }
    n += match md {
        0 if base == 5 => 4,
        0 => 0,
        1 => 1,
        _ => 4,
    };
    Some(n)
}

/// The instruction at the start of `b`: its length and kind, or None when capstone's answer is not certain.
fn decode(b: &[u8], amd64: bool) -> Option<(usize, Kind)> {
    let mut i = 0;
    let mut opsize16 = false;
    let mut rep: Option<u8> = None;
    let mut seg = false;
    loop {
        match *b.get(i)? {
            0x66 => opsize16 = true,
            c @ (0xF2 | 0xF3) => {
                if rep.is_some() {
                    return None;
                }
                rep = Some(c);
            }
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 => {
                if seg {
                    return None;
                }
                seg = true;
            }
            // address size changes ModRM decoding on X86 and moffs/branches on AMD64; lock validity is per opcode
            0x67 | 0xF0 => return None,
            _ => break,
        }
        i += 1;
    }
    if opsize16 && rep.is_some() {
        return None;
    }
    let legacy = i > 0;
    let mut rex = 0u8;
    if amd64 && (0x40..=0x4F).contains(b.get(i)?) {
        rex = b[i];
        i += 1;
    }
    let (w, r, x_b) = (rex & 8 != 0, rex & 4 != 0, rex & 1 != 0);
    let op = *b.get(i)?;
    i += 1;
    // Iz
    let immz = if opsize16 && !w { 2 } else { 4 };
    let reg_of = |i: usize| -> Option<u8> { Some((*b.get(i)? >> 3) & 7) };
    let mod_of = |i: usize| -> Option<u8> { Some(*b.get(i)? >> 6) };

    let (has_modrm, imm) = if op == 0x0F {
        let op2 = *b.get(i)?;
        i += 1;
        // the mandatory prefix of the SSE opcodes
        let mp = if opsize16 { 0x66 } else { rep.unwrap_or(0) };
        let plain = mp == 0 || mp == 0x66;
        match op2 {
            // syscall, ud2, rdtsc, cpuid, push/pop fs/gs, bswap
            0x05 | 0x0B | 0x31 | 0xA2 | 0xA0 | 0xA1 | 0xA8 | 0xA9 | 0xC8..=0xCF if mp == 0 => {
                (false, 0)
            }
            0x1F if plain && reg_of(i)? == 0 => (true, 0),
            // endbr64 / endbr32
            0x1E if mp == 0xF3 && matches!(*b.get(i)?, 0xFA | 0xFB) => (true, 0),
            0x10 | 0x11 | 0x2A | 0x2C | 0x2D | 0x51 | 0x58 | 0x59 | 0x5A | 0x5C..=0x5F => (true, 0),
            0x14 | 0x15 | 0x28 | 0x29 | 0x2E | 0x2F | 0x54..=0x57 | 0x6E | 0x74..=0x76 | 0xEF
                if plain =>
            {
                (true, 0)
            }
            0x5B | 0x6F | 0x7F | 0x7E | 0xBC | 0xBD if mp != 0xF2 => (true, 0),
            0xD6 if mp == 0x66 => (true, 0),
            0xB8 if mp == 0xF3 => (true, 0),
            0x70 => (true, 1),
            0xC6 if plain => (true, 1),
            // cmovcc, imul, movzx/movsx, bt*, shld/shrd, xadd, cmpxchg
            0x40..=0x4F
            | 0xAF
            | 0xB6
            | 0xB7
            | 0xBE
            | 0xBF
            | 0xA3
            | 0xAB
            | 0xB3
            | 0xBB
            | 0xA5
            | 0xAD
            | 0xC0
            | 0xC1
            | 0xB0
            | 0xB1
                if plain =>
            {
                (true, 0)
            }
            0xA4 | 0xAC if plain => (true, 1),
            0xBA if plain && reg_of(i)? >= 4 => (true, 1),
            0x80..=0x8F if mp == 0 => (false, 4),
            0x90..=0x9F if mp == 0 && reg_of(i)? == 0 => (true, 0),
            // fxsave, fxrstor, ldmxcsr, stmxcsr; lfence, mfence, sfence
            0xAE if mp == 0 && mod_of(i)? != 3 && reg_of(i)? <= 3 => (true, 0),
            0xAE if mp == 0 && matches!(*b.get(i)?, 0xE8 | 0xF0 | 0xF8) => (true, 0),
            _ => return None,
        }
    } else {
        if rep.is_some()
            && !matches!(op, 0xA4..=0xA7 | 0xAA..=0xAF | 0xC3)
            && !(op == 0x90 && rep == Some(0xF3))
        {
            return None;
        }
        // relative branches and returns with an operand-size prefix
        if opsize16
            && matches!(op, 0x70..=0x7F | 0xC2 | 0xC3 | 0xCA | 0xCB | 0xE0..=0xE3 | 0xE8 | 0xE9 | 0xEB | 0xFF)
        {
            return None;
        }
        let (has_modrm, imm) = match op {
            o if o < 0x40 && (o & 7) < 4 => (true, 0),
            o if o < 0x40 && (o & 7) == 4 => (false, 1),
            o if o < 0x40 && (o & 7) == 5 => (false, immz),
            // push/pop of segment registers, daa/das/aaa/aas, inc/dec
            0x06
            | 0x07
            | 0x0E
            | 0x16
            | 0x17
            | 0x1E
            | 0x1F
            | 0x27
            | 0x2F
            | 0x37
            | 0x3F
            | 0x40..=0x4F
                if !amd64 =>
            {
                (false, 0)
            }
            0x50..=0x5F => (false, 0),
            0x63 if amd64 => (true, 0),
            0x68 => (false, immz),
            0x69 => (true, immz),
            0x6A => (false, 1),
            0x6B => (true, 1),
            0x70..=0x7F => (false, 1),
            0x80 | 0x83 => (true, 1),
            0x81 => (true, immz),
            0x84..=0x8B => (true, 0),
            0x8D if mod_of(i)? != 3 => (true, 0),
            0x8F if reg_of(i)? == 0 => (true, 0),
            // xchg/nop, cbw/cwd, pushf/popf, sahf/lahf (not 0x9A far call, 0x9B fwait)
            0x90..=0x99 | 0x9C..=0x9F => (false, 0),
            0xA0..=0xA3 => (false, if amd64 { 8 } else { 4 }),
            0xA4..=0xA7 | 0xAA..=0xAF => (false, 0),
            0xA8 => (false, 1),
            0xA9 => (false, immz),
            0xB0..=0xB7 => (false, 1),
            0xB8..=0xBF => (false, if w { 8 } else { immz }),
            0xC0 | 0xC1 if reg_of(i)? != 6 => (true, 1),
            0xC2 => (false, 2),
            0xC3 | 0xC9 | 0xCB | 0xCC | 0xCF => (false, 0),
            0xC6 if reg_of(i)? == 0 => (true, 1),
            0xC7 if reg_of(i)? == 0 => (true, immz),
            0xC8 => (false, 3),
            0xCA => (false, 2),
            0xCD => (false, 1),
            0xD0..=0xD3 if reg_of(i)? != 6 => (true, 0),
            0xE0..=0xE7 | 0xEB => (false, 1),
            0xE8 | 0xE9 => (false, 4),
            0xEC..=0xEF | 0xF4 | 0xF5 | 0xF8..=0xFD => (false, 0),
            0xF6 if reg_of(i)? == 0 => (true, 1),
            0xF7 if reg_of(i)? == 0 => (true, immz),
            0xF6 | 0xF7 if reg_of(i)? >= 2 => (true, 0),
            0xFE if reg_of(i)? <= 1 => (true, 0),
            0xFF if matches!(reg_of(i)?, 0 | 1 | 2 | 4 | 6) => (true, 0),
            0xFF if matches!(reg_of(i)?, 3 | 5) && mod_of(i)? != 3 => (true, 0),
            _ => return None,
        };
        // REX on an instruction without a ModRM byte only where it selects a register or the operand size
        if rex != 0
            && !has_modrm
            && !matches!(op, 0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D | 0x50..=0x5F | 0x90..=0x99 | 0xA4..=0xAF | 0xB0..=0xBF)
        {
            return None;
        }
        (has_modrm, imm)
    };

    let mut kind = Kind::Other;
    if has_modrm {
        let m = *b.get(i)?;
        let (md, reg, rm) = (
            m >> 6,
            ((m >> 3) & 7) | (u8::from(r) << 3),
            (m & 7) | (u8::from(x_b) << 3),
        );
        let pattern = match op {
            0x89 if md == 3 => rm == BP && reg == SP,
            0x8B if md == 3 => reg == BP && rm == SP,
            0x8D if reg == BP && m & 7 == 4 => {
                let base = (*b.get(i + 1)? & 7) | (u8::from(x_b) << 3);
                base == SP
            }
            _ => false,
        };
        if pattern {
            if legacy {
                return None;
            }
            // capstone compares with rbp/rsp on AMD64 and ebp/esp on X86: the operand size must match
            if !amd64 || w {
                kind = Kind::FrameSetup;
            }
        }
        i += modrm_len(b, i)?;
    }
    i += imm;
    if i > 15 || i > b.len() {
        return None;
    }
    Some((i, kind))
}

/// `CFGFast._bp_as_gpr_by_capstone` on the block `bytes` at `addr` whose VEX instruction starts are `insn_addrs`:
/// Some(verdict), or None when it cannot be sure what capstone answers.
pub fn bp_as_gpr(bytes: &[u8], addr: u64, insn_addrs: &[u64], amd64: bool) -> Option<bool> {
    let mut off = 0usize;
    let mut k = 0usize;
    while off < bytes.len() {
        if insn_addrs.get(k) != Some(&(addr + off as u64)) {
            return None;
        }
        let (len, kind) = decode(&bytes[off..], amd64)?;
        if kind == Kind::FrameSetup {
            return Some(false);
        }
        off += len;
        k += 1;
    }
    (k == insn_addrs.len()).then_some(true)
}

/// `bp_as_gpr(block bytes, block addr, VEX instruction addresses, is AMD64)`: what capstone decides, or None.
#[pyfunction(name = "bp_as_gpr")]
pub fn py_bp_as_gpr(bytes: &[u8], addr: u64, insn_addrs: Vec<u64>, amd64: bool) -> Option<bool> {
    bp_as_gpr(bytes, addr, &insn_addrs, amd64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn starts(addr: u64, lens: &[u64]) -> Vec<u64> {
        let mut a = addr;
        lens.iter()
            .map(|l| {
                let s = a;
                a += l;
                s
            })
            .collect()
    }

    #[test]
    fn frame_setup() {
        // push rbp; mov rbp, rsp; sub rsp, 0x10
        let b = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10];
        assert_eq!(
            bp_as_gpr(&b, 0x1000, &starts(0x1000, &[1, 3, 4]), true),
            Some(false)
        );
        // mov ebp, esp in 64-bit mode is not rbp, rsp
        let b = [0x55, 0x89, 0xE5, 0xC3];
        assert_eq!(
            bp_as_gpr(&b, 0x1000, &starts(0x1000, &[1, 2, 1]), true),
            Some(true)
        );
        assert_eq!(
            bp_as_gpr(&b, 0x1000, &starts(0x1000, &[1, 2, 1]), false),
            Some(false)
        );
        // lea rbp, [rsp - 0x5f]; mov r13, rsp
        let b = [0x48, 0x8D, 0x6C, 0x24, 0xA1];
        assert_eq!(bp_as_gpr(&b, 0, &[0], true), Some(false));
        let b = [0x49, 0x89, 0xE5, 0xC3];
        assert_eq!(bp_as_gpr(&b, 0, &[0, 3], true), Some(true));
        // VEX disagrees on the boundaries
        assert_eq!(bp_as_gpr(&b, 0, &[0, 2], true), None);
        // an x87 instruction is not decoded
        let b = [0xD9, 0xEE, 0x89, 0xE5];
        assert_eq!(bp_as_gpr(&b, 0, &[0, 2], false), None);
    }
}
