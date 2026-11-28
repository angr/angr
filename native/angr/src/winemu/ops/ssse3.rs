//! SSSE3.

use icicle_vm::cpu::{Cpu, exec::helpers::PcodeOpHelper};
use pcode::VarNode;

use super::*;

/// This function combines adjacent pairs of the lanes of `a` and then of the lanes of `b`.
fn horizontal(cpu: &mut Cpu, dst: VarNode, args: Args, width: u8, f: impl Fn(i64, i64) -> u64) {
    let (a, b) = (rd(cpu, args[0]), rd(cpu, args[1]));
    let count = dst.size / width;
    let sext = |v: u64| {
        if width == 2 {
            v as i16 as i64
        } else {
            v as i32 as i64
        }
    };
    let out = build(count, width, |i| {
        let src = if i < count / 2 { a } else { b };
        let k = 2 * (i % (count / 2));
        f(sext(lane(src, k, width)), sext(lane(src, k + 1, width)))
    });
    write_trunc(cpu, dst, out);
}

pub const HELPERS: &[(&str, PcodeOpHelper)] = &[
    ("pshufb", |c, d, a| {
        let (x, y) = (rd(c, a[0]), rd(c, a[1]));
        let n = d.size;
        let out = build(n, 1, |i| {
            let select = lane(y, i, 1) as u8;
            if select & 0x80 != 0 {
                0
            } else {
                lane(x, select & (n - 1), 1)
            }
        });
        write_trunc(c, d, out);
    }),
    ("pabsb", |c, d, a| {
        zip(c, d, a, 1, |_, y| (y as i8).unsigned_abs() as u64)
    }),
    ("pabsw", |c, d, a| {
        zip(c, d, a, 2, |_, y| (y as i16).unsigned_abs() as u64)
    }),
    ("pabsd", |c, d, a| {
        zip(c, d, a, 4, |_, y| (y as i32).unsigned_abs() as u64)
    }),
    ("phaddw", |c, d, a| {
        horizontal(c, d, a, 2, |x, y| (x + y) as u64)
    }),
    ("phaddd", |c, d, a| {
        horizontal(c, d, a, 4, |x, y| (x + y) as u64)
    }),
    ("phaddsw", |c, d, a| {
        horizontal(c, d, a, 2, |x, y| sat_i16(x + y))
    }),
    ("phsubw", |c, d, a| {
        horizontal(c, d, a, 2, |x, y| (x - y) as u64)
    }),
    ("phsubd", |c, d, a| {
        horizontal(c, d, a, 4, |x, y| (x - y) as u64)
    }),
    ("phsubsw", |c, d, a| {
        horizontal(c, d, a, 2, |x, y| sat_i16(x - y))
    }),
    // pmaddubsw multiplies unsigned bytes of the destination by signed bytes of the source
    ("pmaddubsw", |c, d, a| {
        zip(c, d, a, 2, |x, y| {
            let p = |s: u32| ((x >> s) as u8 as i64) * ((y >> s) as i8 as i64);
            sat_i16(p(0) + p(8))
        })
    }),
    ("pmulhrsw", |c, d, a| {
        zip(c, d, a, 2, |x, y| {
            ((((x as i16 as i64 * y as i16 as i64) >> 14) + 1) >> 1) as u64
        })
    }),
    ("psignb", |c, d, a| {
        zip(c, d, a, 1, |x, y| {
            ((x as i8 as i64) * (y as i8 as i64).signum()) as u64
        })
    }),
    ("psignw", |c, d, a| {
        zip(c, d, a, 2, |x, y| {
            ((x as i16 as i64) * (y as i16 as i64).signum()) as u64
        })
    }),
    ("psignd", |c, d, a| {
        zip(c, d, a, 4, |x, y| {
            ((x as i32 as i64) * (y as i32 as i64).signum()) as u64
        })
    }),
];
