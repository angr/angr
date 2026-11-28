//! SSE4.1.

use icicle_vm::cpu::{Cpu, ValueSource, exec::helpers::PcodeOpHelper};
use pcode::VarNode;

use super::*;

fn sat_u16(v: i64) -> u64 {
    v.clamp(0, u16::MAX as i64) as u64
}

fn extend(cpu: &mut Cpu, dst: VarNode, args: Args, from: u8, to: u8, signed: bool) {
    let src = rd(cpu, args[1]);
    let out = build(dst.size / to, to, |i| {
        let v = lane(src, i, from);
        if signed {
            let shift = 64 - 8 * from as u32;
            (((v << shift) as i64) >> shift) as u64
        } else {
            v
        }
    });
    write_trunc(cpu, dst, out);
}

/// The rounding mode is 0 for nearest with ties to even, 1 for down, 2 for up and 3 towards zero.
/// The rounding mode comes from MXCSR.RC if bit 2 of the immediate is set, and from the immediate
/// otherwise.
fn rounding_mode(cpu: &Cpu, imm: u64) -> u64 {
    if imm & 4 != 0 {
        (cpu.read_var::<u32>(reg(cpu, "MXCSR")) as u64 >> 13) & 3
    } else {
        imm & 3
    }
}

fn round_f64(v: f64, mode: u64) -> f64 {
    match mode {
        0 => v.round_ties_even(),
        1 => v.floor(),
        2 => v.ceil(),
        _ => v.trunc(),
    }
}

fn round_f32(v: f32, mode: u64) -> f32 {
    match mode {
        0 => v.round_ties_even(),
        1 => v.floor(),
        2 => v.ceil(),
        _ => v.trunc(),
    }
}

fn mpsadbw(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let (a, b, imm) = (rd(cpu, args[0]), rd(cpu, args[1]), cpu.args[0] as u8);
    let (a_off, b_off) = (4 * ((imm >> 2) & 1), 4 * (imm & 3));
    let out = build(8, 2, |i| {
        (0..4)
            .map(|j| lane(a, a_off + i + j, 1).abs_diff(lane(b, b_off + j, 1)))
            .sum()
    });
    write_trunc(cpu, dst, out);
}

fn phminposuw(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let src = rd(cpu, args[0]);
    let (index, min) = (0..8u8)
        .map(|i| (i, lane(src, i, 2)))
        .min_by_key(|&(i, v)| (v, i))
        .unwrap_or((0, 0));
    write_trunc(cpu, dst, min as u128 | (index as u128) << 16);
}

fn dpps(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let (a, b, imm) = (rd(cpu, args[0]), rd(cpu, args[1]), cpu.args[0] as u8);
    let p = |i: u8| {
        if imm & (0x10 << i) != 0 {
            f32::from_bits(lane(a, i, 4) as u32) * f32::from_bits(lane(b, i, 4) as u32)
        } else {
            0.0
        }
    };
    let sum = ((p(0) + p(1)) + (p(2) + p(3))).to_bits() as u64;
    let out = build(4, 4, |i| if imm & (1 << i) != 0 { sum } else { 0 });
    write_trunc(cpu, dst, out);
}

fn dppd(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let (a, b, imm) = (rd(cpu, args[0]), rd(cpu, args[1]), cpu.args[0] as u8);
    let p = |i: u8| {
        if imm & (0x10 << i) != 0 {
            f64::from_bits(lane(a, i, 8)) * f64::from_bits(lane(b, i, 8))
        } else {
            0.0
        }
    };
    let sum = (p(0) + p(1)).to_bits();
    let out = build(2, 8, |i| if imm & (1 << i) != 0 { sum } else { 0 });
    write_trunc(cpu, dst, out);
}

fn insertps(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let (a, b, imm) = (rd(cpu, args[0]), rd(cpu, args[1]), cpu.args[0] as u8);
    // a memory source is one dword, and the top two bits of the immediate pick the dword of a
    // register source
    let src = if args[1].size() == 4 {
        b as u32 as u64
    } else {
        lane(b, imm >> 6, 4)
    };
    let at = (imm >> 4) & 3;
    let out = build(4, 4, |i| {
        if imm & (1 << i) != 0 {
            0
        } else if i == at {
            src
        } else {
            lane(a, i, 4)
        }
    });
    write_trunc(cpu, dst, out);
}

pub const HELPERS: &[(&str, PcodeOpHelper)] = &[
    ("mpsadbw", mpsadbw),
    ("phminposuw", phminposuw),
    ("pmuldq", |c, d, a| {
        zip(c, d, a, 8, |x, y| (x as i32 as i64).wrapping_mul(y as i32 as i64) as u64)
    }),
    ("pmulld", |c, d, a| zip(c, d, a, 4, |x, y| x.wrapping_mul(y))),
    ("packusdw", |c, d, a| pack(c, d, a, 4, sat_u16)),
    ("pblendw", |c, d, a| {
        let imm = c.args[0] as u8;
        blend(c, d, a, 2, |i| imm >> i & 1 != 0)
    }),
    ("pblendvb", |c, d, a| {
        let select = c.args[0];
        blend(c, d, a, 1, |i| lane(select, i, 1) & 0x80 != 0)
    }),
    ("blendps", |c, d, a| {
        let imm = c.args[0] as u8;
        blend(c, d, a, 4, |i| imm >> i & 1 != 0)
    }),
    ("blendpd", |c, d, a| {
        let imm = c.args[0] as u8;
        blend(c, d, a, 8, |i| imm >> i & 1 != 0)
    }),
    ("blendvps", |c, d, a| {
        let select = c.args[0];
        blend(c, d, a, 4, |i| lane(select, i, 4) >> 31 != 0)
    }),
    ("blendvpd", |c, d, a| {
        let select = c.args[0];
        blend(c, d, a, 8, |i| lane(select, i, 8) >> 63 != 0)
    }),
    ("insertps", insertps),
    ("extractps", |c, d, a| {
        let (src, index) = (rd(c, a[0]), rd(c, a[1]) as u8 & 3);
        write_trunc(c, d, lane(src, index, 4) as u128);
    }),
    ("movntdqa", |c, d, a| {
        let value = rd(c, a[1]);
        write_trunc(c, d, value);
    }),
    ("pmovsxbw", |c, d, a| extend(c, d, a, 1, 2, true)),
    ("pmovsxbd", |c, d, a| extend(c, d, a, 1, 4, true)),
    ("pmovsxbq", |c, d, a| extend(c, d, a, 1, 8, true)),
    ("pmovsxwd", |c, d, a| extend(c, d, a, 2, 4, true)),
    ("pmovsxwq", |c, d, a| extend(c, d, a, 2, 8, true)),
    ("pmovsxdq", |c, d, a| extend(c, d, a, 4, 8, true)),
    ("pmovzxbw", |c, d, a| extend(c, d, a, 1, 2, false)),
    ("pmovzxbd", |c, d, a| extend(c, d, a, 1, 4, false)),
    ("pmovzxbq", |c, d, a| extend(c, d, a, 1, 8, false)),
    ("pmovzxwd", |c, d, a| extend(c, d, a, 2, 4, false)),
    ("pmovzxwq", |c, d, a| extend(c, d, a, 2, 8, false)),
    ("pmovzxdq", |c, d, a| extend(c, d, a, 4, 8, false)),
    ("dpps", dpps),
    ("dppd", dppd),
    ("roundps", |c, d, a| {
        let mode = rounding_mode(c, c.args[0] as u64);
        zip_f32(c, d, a, |_, y| round_f32(y, mode))
    }),
    ("roundpd", |c, d, a| {
        let mode = rounding_mode(c, c.args[0] as u64);
        zip_f64(c, d, a, |_, y| round_f64(y, mode))
    }),
    ("roundss", |c, d, a| {
        let mode = rounding_mode(c, c.args[0] as u64);
        low_f32(c, d, a, |y| round_f32(y, mode))
    }),
    ("roundsd", |c, d, a| {
        let mode = rounding_mode(c, c.args[0] as u64);
        low_f64(c, d, a, |y| round_f64(y, mode))
    }),
];
