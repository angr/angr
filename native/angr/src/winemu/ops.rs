//! x86 user ops that Icicle's helper table lacks: MMX/SSE through SSE4.2, AES-NI, SHA, CRC32 and the x87 leftovers.
//!
//! A helper gets the destination and the first two arguments; further arguments arrive in `cpu.args`. x87 values
//! are doubles kept in the low eight bytes of the ten-byte registers, as everywhere in Icicle.

use icicle_vm::cpu::{Cpu, ValueSource};
use pcode::{Value, VarNode};

use super::write_trunc;

pub mod crypto;
pub mod sse2;
pub mod sse41;
pub mod sse42;
pub mod ssse3;

pub(super) type Args = [Value; 2];

/// The zero-extended value of an operand of up to 16 bytes (the low half of a wider one).
pub(super) fn rd(cpu: &Cpu, value: Value) -> u128 {
    match value {
        Value::Const(c, _) => c as u128,
        Value::Var(var) => (0..var.size.min(16))
            .map(|i| (cpu.read_var::<u8>(var.slice(i, 1)) as u128) << (8 * i))
            .sum(),
    }
}

pub(super) fn reg(cpu: &Cpu, name: &str) -> VarNode {
    cpu.arch
        .sleigh
        .get_reg(name)
        .and_then(|reg| reg.get_var())
        .unwrap_or(VarNode::NONE)
}

pub(super) fn set_flag(cpu: &mut Cpu, name: &str, value: bool) {
    let var = reg(cpu, name);
    cpu.write_var::<u8>(var, value as u8);
}

pub(super) fn mask(bytes: u8) -> u128 {
    if bytes >= 16 {
        u128::MAX
    } else {
        (1u128 << (8 * bytes)) - 1
    }
}

pub(super) fn lane(v: u128, index: u8, width: u8) -> u64 {
    ((v >> (8 * index as u32 * width as u32)) & mask(width)) as u64
}

pub(super) fn build(count: u8, width: u8, f: impl Fn(u8) -> u64) -> u128 {
    (0..count).fold(0, |acc, i| {
        acc | ((f(i) as u128 & mask(width)) << (8 * i as u32 * width as u32))
    })
}

/// dst = f(a, b) per lane of `width` bytes.
pub(super) fn zip(
    cpu: &mut Cpu,
    dst: VarNode,
    args: Args,
    width: u8,
    f: impl Fn(u64, u64) -> u64,
) {
    let (a, b) = (rd(cpu, args[0]), rd(cpu, args[1]));
    let out = build(dst.size / width, width, |i| {
        f(lane(a, i, width), lane(b, i, width))
    });
    write_trunc(cpu, dst, out);
}

pub(super) fn zip_f32(cpu: &mut Cpu, dst: VarNode, args: Args, f: impl Fn(f32, f32) -> f32) {
    zip(cpu, dst, args, 4, |a, b| {
        f(f32::from_bits(a as u32), f32::from_bits(b as u32)).to_bits() as u64
    });
}

pub(super) fn zip_f64(cpu: &mut Cpu, dst: VarNode, args: Args, f: impl Fn(f64, f64) -> f64) {
    zip(cpu, dst, args, 8, |a, b| {
        f(f64::from_bits(a), f64::from_bits(b)).to_bits()
    });
}

/// Scalar forms: the low lane is f(low lane of the second operand), the rest is the first operand.
pub(super) fn low_f32(cpu: &mut Cpu, dst: VarNode, args: Args, f: impl Fn(f32) -> f32) {
    let (a, b) = (rd(cpu, args[0]), rd(cpu, args[1]));
    let low = f(f32::from_bits(b as u32)).to_bits() as u128;
    write_trunc(cpu, dst, (a & !mask(4)) | low);
}

pub(super) fn low_f64(cpu: &mut Cpu, dst: VarNode, args: Args, f: impl Fn(f64) -> f64) {
    let (a, b) = (rd(cpu, args[0]), rd(cpu, args[1]));
    let low = f(f64::from_bits(b as u64)).to_bits() as u128;
    write_trunc(cpu, dst, (a & !mask(8)) | low);
}

pub(super) fn sat_i16(v: i64) -> u64 {
    v.clamp(i16::MIN as i64, i16::MAX as i64) as u16 as u64
}

/// Narrow the lanes of a, then of b, to half their width.
pub(super) fn pack(cpu: &mut Cpu, dst: VarNode, args: Args, width: u8, sat: fn(i64) -> u64) {
    let (a, b) = (rd(cpu, args[0]), rd(cpu, args[1]));
    let half = dst.size / width;
    let sext = |v: u64| {
        if width == 2 {
            v as i16 as i64
        } else {
            v as i32 as i64
        }
    };
    let out = build(half * 2, width / 2, |i| {
        let src = if i < half { a } else { b };
        sat(sext(lane(src, i % half, width)))
    });
    write_trunc(cpu, dst, out);
}

/// Per lane of `width` bytes, the second operand's where `pick` says so, else the first's.
pub(super) fn blend(cpu: &mut Cpu, dst: VarNode, args: Args, width: u8, pick: impl Fn(u8) -> bool) {
    let (a, b) = (rd(cpu, args[0]), rd(cpu, args[1]));
    let out = build(dst.size / width, width, |i| {
        lane(if pick(i) { b } else { a }, i, width)
    });
    write_trunc(cpu, dst, out);
}
