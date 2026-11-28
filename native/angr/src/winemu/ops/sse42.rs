//! CRC32 and the string compares of SSE4.2.

use icicle_vm::cpu::{Cpu, exec::helpers::PcodeOpHelper};
use pcode::VarNode;

use super::*;

// bit-reflected CRC-32C with the Castagnoli polynomial
fn crc32(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let mut crc = rd(cpu, args[0]) as u32;
    let data = rd(cpu, args[1]) as u64;
    for i in 0..args[1].size() {
        crc ^= (data >> (8 * i)) as u8 as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82F6_3B78 & (crc & 1).wrapping_neg());
        }
    }
    write_trunc(cpu, dst, crc as u128);
}

/// This function implements pcmpistri, pcmpistrm, pcmpestri and pcmpestrm with the arguments
/// `(a, b, imm[, eax, edx, rex.w])`. This function sets the flags and returns IntRes2, the element
/// count and IntRes2 expanded to element masks. Explicit lengths come from eax and edx. We added
/// the last argument to the SLEIGH spec to tell whether eax and edx are 64 bits wide.
fn string_compare(cpu: &mut Cpu, args: Args, explicit: bool) -> (u32, u8, u128) {
    let (a, b, imm) = (rd(cpu, args[0]), rd(cpu, args[1]), cpu.args[0] as u8);
    let width = if imm & 1 != 0 { 2 } else { 1 };
    let n = 16 / width;
    let wide = cpu.args[3] != 0;
    let length = |v: u128, raw: u128| -> u8 {
        if explicit {
            let magnitude = if wide {
                (raw as i64).unsigned_abs()
            } else {
                (raw as i32).unsigned_abs() as u64
            };
            magnitude.min(n as u64) as u8
        } else {
            (0..n).find(|&i| lane(v, i, width) == 0).unwrap_or(n)
        }
    };
    let (la, lb) = (length(a, cpu.args[1]), length(b, cpu.args[2]));
    let value = |v: u128, i: u8| -> i64 {
        let x = lane(v, i, width);
        match (imm & 2 != 0, width) {
            (true, 1) => x as i8 as i64,
            (true, _) => x as i16 as i64,
            _ => x as i64,
        }
    };
    let mut res1 = 0u32;
    for j in 0..n {
        let bit = match (imm >> 2) & 3 {
            // equal any, where b[j] is in the set a
            0 => j < lb && (0..la).any(|i| value(a, i) == value(b, j)),
            // ranges, where b[j] is in one of the ranges a[2k] ..= a[2k + 1]
            1 => {
                j < lb
                    && (0..la / 2).any(|k| {
                        value(a, 2 * k) <= value(b, j) && value(b, j) <= value(a, 2 * k + 1)
                    })
            }
            // equal each
            2 => match (j < la, j < lb) {
                (true, true) => value(a, j) == value(b, j),
                (false, false) => true,
                _ => false,
            },
            // equal ordered, where a occurs in b at j
            _ => (0..n - j).all(|i| i >= la || (j + i < lb && value(a, i) == value(b, j + i))),
        };
        res1 |= (bit as u32) << j;
    }
    let res2 = match (imm >> 4) & 3 {
        1 => res1 ^ ((1u32 << n) - 1),
        3 => res1 ^ ((1u32 << lb) - 1),
        _ => res1,
    };
    set_flag(cpu, "CF", res2 != 0);
    set_flag(cpu, "ZF", lb < n);
    set_flag(cpu, "SF", la < n);
    set_flag(cpu, "OF", res2 & 1 != 0);
    set_flag(cpu, "AF", false);
    set_flag(cpu, "PF", false);
    let expanded = build(n, width, |i| if res2 & (1 << i) != 0 { u64::MAX } else { 0 });
    (res2, n, expanded)
}

fn string_index(cpu: &mut Cpu, dst: VarNode, args: Args, explicit: bool) {
    let imm = cpu.args[0] as u8;
    let (res2, n, _) = string_compare(cpu, args, explicit);
    let index = if res2 == 0 {
        n as u32
    } else if imm & 0x40 != 0 {
        31 - res2.leading_zeros()
    } else {
        res2.trailing_zeros()
    };
    write_trunc(cpu, dst, index as u128);
}

fn string_mask(cpu: &mut Cpu, dst: VarNode, args: Args, explicit: bool) {
    let imm = cpu.args[0] as u8;
    let (res2, _, expanded) = string_compare(cpu, args, explicit);
    let out = if imm & 0x40 != 0 { expanded } else { res2 as u128 };
    write_trunc(cpu, dst, out);
}

pub const HELPERS: &[(&str, PcodeOpHelper)] = &[
    ("crc32", crc32),
    ("pcmpistri", |c, d, a| string_index(c, d, a, false)),
    ("pcmpistrm", |c, d, a| string_mask(c, d, a, false)),
    ("pcmpestri", |c, d, a| string_index(c, d, a, true)),
    ("pcmpestrm", |c, d, a| string_mask(c, d, a, true)),
];
