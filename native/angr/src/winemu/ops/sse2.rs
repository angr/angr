//! MMX, SSE and SSE2 operations the SLEIGH spec leaves to user ops.

use icicle_vm::cpu::{Cpu, exec::helpers::PcodeOpHelper};
use pcode::{Value, VarNode};

use super::*;

fn sat_i8(v: i64) -> u64 {
    v.clamp(i8::MIN as i64, i8::MAX as i64) as u8 as u64
}

/// The shift count of the packed shifts: the low quadword of the count operand.
fn shift_count(cpu: &Cpu, value: Value) -> u64 {
    rd(cpu, value) as u64
}

fn sign_bits(cpu: &mut Cpu, dst: VarNode, args: Args, width: u8) {
    let src = rd(cpu, args[1]);
    let out = (0..16 / width).fold(0u128, |acc, i| {
        acc | (((lane(src, i, width) >> (8 * width - 1)) & 1) as u128) << i
    });
    write_trunc(cpu, dst, out);
}

fn cmp_predicate(a: f64, b: f64, imm: u64) -> u64 {
    let holds = match imm & 7 {
        0 => a == b,
        1 => a < b,
        2 => a <= b,
        3 => a.is_nan() || b.is_nan(),
        4 => a != b,
        5 => !(a < b),
        6 => !(a <= b),
        _ => !(a.is_nan() || b.is_nan()),
    };
    (holds as u64).wrapping_neg()
}

fn cmp_f32(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let imm = cpu.args[0] as u64;
    zip(cpu, dst, args, 4, |x, y| {
        cmp_predicate(f32::from_bits(x as u32) as f64, f32::from_bits(y as u32) as f64, imm)
    });
}

fn cmp_f64(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let imm = cpu.args[0] as u64;
    zip(cpu, dst, args, 8, |x, y| {
        cmp_predicate(f64::from_bits(x), f64::from_bits(y), imm)
    });
}

/// maskmovdqu / maskmovq, as patched in the SLEIGH spec: (data, mask, old memory) -> new memory.
fn masked_move(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let (data, select, old) = (rd(cpu, args[0]), rd(cpu, args[1]), cpu.args[0]);
    let out = build(dst.size, 1, |i| {
        let source = if lane(select, i, 1) & 0x80 != 0 { data } else { old };
        lane(source, i, 1)
    });
    write_trunc(cpu, dst, out);
}

fn second(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let value = rd(cpu, args[1]);
    write_trunc(cpu, dst, value);
}

pub const HELPERS: &[(&str, PcodeOpHelper)] = &[
    ("packsswb", |c, d, a| pack(c, d, a, 2, sat_i8)),
    ("packssdw", |c, d, a| pack(c, d, a, 4, sat_i16)),
    ("paddsb", |c, d, a| {
        zip(c, d, a, 1, |x, y| (x as i8).saturating_add(y as i8) as u8 as u64)
    }),
    ("paddsw", |c, d, a| {
        zip(c, d, a, 2, |x, y| (x as i16).saturating_add(y as i16) as u16 as u64)
    }),
    ("paddusb", |c, d, a| {
        zip(c, d, a, 1, |x, y| (x as u8).saturating_add(y as u8) as u64)
    }),
    ("paddusw", |c, d, a| {
        zip(c, d, a, 2, |x, y| (x as u16).saturating_add(y as u16) as u64)
    }),
    ("psubsb", |c, d, a| {
        zip(c, d, a, 1, |x, y| (x as i8).saturating_sub(y as i8) as u8 as u64)
    }),
    ("psubsw", |c, d, a| {
        zip(c, d, a, 2, |x, y| (x as i16).saturating_sub(y as i16) as u16 as u64)
    }),
    ("psubusb", |c, d, a| {
        zip(c, d, a, 1, |x, y| (x as u8).saturating_sub(y as u8) as u64)
    }),
    ("psubusw", |c, d, a| {
        zip(c, d, a, 2, |x, y| (x as u16).saturating_sub(y as u16) as u64)
    }),
    ("pavgb", |c, d, a| zip(c, d, a, 1, |x, y| (x + y + 1) >> 1)),
    ("pavgw", |c, d, a| zip(c, d, a, 2, |x, y| (x + y + 1) >> 1)),
    ("pmulhuw", |c, d, a| zip(c, d, a, 2, |x, y| (x * y) >> 16)),
    ("pmulhw", |c, d, a| {
        zip(c, d, a, 2, |x, y| ((x as i16 as i64 * y as i16 as i64) >> 16) as u64)
    }),
    ("psadbw", |c, d, a| {
        zip(c, d, a, 8, |x, y| {
            (0..8)
                .map(|i| ((x >> (8 * i)) as u8).abs_diff((y >> (8 * i)) as u8) as u64)
                .sum()
        })
    }),
    ("psllw", |c, d, a| {
        let count = shift_count(c, a[1]);
        zip(c, d, a, 2, |x, _| if count > 15 { 0 } else { x << count })
    }),
    ("psraw", |c, d, a| {
        let count = shift_count(c, a[1]).min(15);
        zip(c, d, a, 2, |x, _| ((x as i16) >> count) as u16 as u64)
    }),
    ("pshufw", |c, d, a| {
        let (src, order) = (rd(c, a[1]), c.args[0] as u8);
        let out = build(4, 2, |i| lane(src, (order >> (2 * i)) & 3, 2));
        write_trunc(c, d, out);
    }),
    ("movmskps", |c, d, a| sign_bits(c, d, a, 4)),
    ("movdq2q", second),
    ("lddqu", second),
    ("maskmovdqu", masked_move),
    ("MaskedMoveQWord", masked_move),
    ("divps", |c, d, a| zip_f32(c, d, a, |x, y| x / y)),
    ("divpd", |c, d, a| zip_f64(c, d, a, |x, y| x / y)),
    // the second operand wins unless the comparison holds (NaNs, zeros of either sign)
    ("maxps", |c, d, a| zip_f32(c, d, a, |x, y| if x > y { x } else { y })),
    ("maxpd", |c, d, a| zip_f64(c, d, a, |x, y| if x > y { x } else { y })),
    ("minps", |c, d, a| zip_f32(c, d, a, |x, y| if x < y { x } else { y })),
    ("minpd", |c, d, a| zip_f64(c, d, a, |x, y| if x < y { x } else { y })),
    ("sqrtps", |c, d, a| zip_f32(c, d, a, |_, y| y.sqrt())),
    ("sqrtpd", |c, d, a| zip_f64(c, d, a, |_, y| y.sqrt())),
    // the estimates are computed exactly, as QEMU does
    ("rcpps", |c, d, a| zip_f32(c, d, a, |_, y| 1.0 / y)),
    ("rsqrtps", |c, d, a| zip_f32(c, d, a, |_, y| 1.0 / y.sqrt())),
    ("rcpss", |c, d, a| low_f32(c, d, a, |y| 1.0 / y)),
    ("rsqrtss", |c, d, a| low_f32(c, d, a, |y| 1.0 / y.sqrt())),
    // predicates above 7, which the spec does not expand
    ("cmpps", cmp_f32),
    ("cmpss", cmp_f32),
    ("cmppd", cmp_f64),
    ("cmpsd", cmp_f64),
];
