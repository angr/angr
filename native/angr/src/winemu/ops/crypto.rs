//! AES-NI and the SHA extensions.

use std::sync::LazyLock;

use icicle_vm::cpu::{Cpu, exec::helpers::PcodeOpHelper};
use pcode::VarNode;

use super::*;

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut out = 0;
    while b != 0 {
        if b & 1 != 0 {
            out ^= a;
        }
        a = (a << 1) ^ (if a & 0x80 != 0 { 0x1B } else { 0 });
        b >>= 1;
    }
    out
}

/// The AES S-box and the inverse S-box.
static SBOX: LazyLock<([u8; 256], [u8; 256])> = LazyLock::new(|| {
    let (mut sbox, mut inverse) = ([0u8; 256], [0u8; 256]);
    for x in 0..=255u8 {
        let inv = (1..=255u8).find(|&y| gf_mul(x, y) == 1).unwrap_or(0);
        let s = inv
            ^ inv.rotate_left(1)
            ^ inv.rotate_left(2)
            ^ inv.rotate_left(3)
            ^ inv.rotate_left(4)
            ^ 0x63;
        sbox[x as usize] = s;
        inverse[s as usize] = x;
    }
    (sbox, inverse)
});

/// This function applies MixColumns with the matrix whose first row is `row`.
/// Each further row is the previous row rotated right by one.
fn mix_columns(state: [u8; 16], row: [u8; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for c in 0..4 {
        for r in 0..4 {
            out[4 * c + r] = (0..4).fold(0, |acc, k| {
                acc ^ gf_mul(state[4 * c + k], row[(k + 4 - r) % 4])
            });
        }
    }
    out
}

const MIX: [u8; 4] = [2, 3, 1, 1];
const INV_MIX: [u8; 4] = [14, 11, 13, 9];

fn aes_round(cpu: &mut Cpu, dst: VarNode, args: Args, decrypt: bool, mix: bool) {
    let state = rd(cpu, args[0]).to_le_bytes();
    let key = rd(cpu, args[1]);
    let table = if decrypt { &SBOX.1 } else { &SBOX.0 };
    let mut out = [0u8; 16];
    for c in 0..4 {
        for r in 0..4 {
            // ShiftRows moves row r left by r columns, and the inverse moves row r right
            let from = if decrypt {
                (c + 4 - r) % 4
            } else {
                (c + r) % 4
            };
            out[4 * c + r] = table[state[4 * from + r] as usize];
        }
    }
    if mix {
        out = mix_columns(out, if decrypt { INV_MIX } else { MIX });
    }
    write_trunc(cpu, dst, u128::from_le_bytes(out) ^ key);
}

fn aesimc(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let out = mix_columns(rd(cpu, args[0]).to_le_bytes(), INV_MIX);
    write_trunc(cpu, dst, u128::from_le_bytes(out));
}

fn aeskeygenassist(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let (src, rcon) = (rd(cpu, args[0]), rd(cpu, args[1]) as u32 & 0xFF);
    let sub = |w: u32| u32::from_le_bytes(w.to_le_bytes().map(|b| SBOX.0[b as usize]));
    let (x1, x3) = (sub(lane(src, 1, 4) as u32), sub(lane(src, 3, 4) as u32));
    let words = [x1, x1.rotate_right(8) ^ rcon, x3, x3.rotate_right(8) ^ rcon];
    write_trunc(cpu, dst, build(4, 4, |i| words[i as usize] as u64));
}

/// This function returns the four dwords of an operand with the most significant dword first, which
/// is the order in the manuals.
fn dwords(v: u128) -> [u32; 4] {
    [3, 2, 1, 0].map(|i| lane(v, i, 4) as u32)
}

fn from_dwords(w: [u32; 4]) -> u128 {
    build(4, 4, |i| w[3 - i as usize] as u64)
}

fn sha1rnds4(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let [mut a, mut b, mut c, mut d] = dwords(rd(cpu, args[0]));
    let w = dwords(rd(cpu, args[1]));
    let func = cpu.args[0] as u8 & 3;
    let k = [0x5A82_7999u32, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6][func as usize];
    let mut e = 0u32;
    for wi in w {
        let f = match func {
            0 => (b & c) ^ (!b & d),
            2 => (b & c) ^ (b & d) ^ (c & d),
            _ => b ^ c ^ d,
        };
        let next = f
            .wrapping_add(a.rotate_left(5))
            .wrapping_add(wi)
            .wrapping_add(e)
            .wrapping_add(k);
        (e, d, c, b, a) = (d, c, b.rotate_left(30), a, next);
    }
    write_trunc(cpu, dst, from_dwords([a, b, c, d]));
}

fn sha1nexte(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let e = dwords(rd(cpu, args[0]))[0].rotate_left(30);
    let mut w = dwords(rd(cpu, args[1]));
    w[0] = w[0].wrapping_add(e);
    write_trunc(cpu, dst, from_dwords(w));
}

fn sha1msg1(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let (w, s) = (dwords(rd(cpu, args[0])), dwords(rd(cpu, args[1])));
    let out = [w[2] ^ w[0], w[3] ^ w[1], s[0] ^ w[2], s[1] ^ w[3]];
    write_trunc(cpu, dst, from_dwords(out));
}

fn sha1msg2(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let (w, s) = (dwords(rd(cpu, args[0])), dwords(rd(cpu, args[1])));
    let w16 = (w[0] ^ s[1]).rotate_left(1);
    let w17 = (w[1] ^ s[2]).rotate_left(1);
    let w18 = (w[2] ^ s[3]).rotate_left(1);
    let w19 = (w[3] ^ w16).rotate_left(1);
    write_trunc(cpu, dst, from_dwords([w16, w17, w18, w19]));
}

fn sha256rnds2(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let [mut c, mut d, mut g, mut h] = dwords(rd(cpu, args[0]));
    let [mut a, mut b, mut e, mut f] = dwords(rd(cpu, args[1]));
    // the low half of xmm0 holds the two message words plus the round constants
    let wk = cpu.args[0];
    for i in 0..2 {
        let t1 = ((e & f) ^ (!e & g))
            .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
            .wrapping_add(lane(wk, i, 4) as u32)
            .wrapping_add(h);
        let t2 = ((a & b) ^ (a & c) ^ (b & c))
            .wrapping_add(a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22));
        (h, g, f, e, d, c, b, a) = (g, f, e, t1.wrapping_add(d), c, b, a, t1.wrapping_add(t2));
    }
    write_trunc(cpu, dst, from_dwords([a, b, e, f]));
}

fn sigma0(w: u32) -> u32 {
    w.rotate_right(7) ^ w.rotate_right(18) ^ (w >> 3)
}

fn sigma1(w: u32) -> u32 {
    w.rotate_right(17) ^ w.rotate_right(19) ^ (w >> 10)
}

fn sha256msg1(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let (w, s) = (dwords(rd(cpu, args[0])), dwords(rd(cpu, args[1])));
    let out = [0, 1, 2, 3].map(|i| {
        let next = if i == 0 { s[3] } else { w[i - 1] };
        w[i].wrapping_add(sigma0(next))
    });
    write_trunc(cpu, dst, from_dwords(out));
}

fn sha256msg2(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let (w, s) = (dwords(rd(cpu, args[0])), dwords(rd(cpu, args[1])));
    let w16 = w[3].wrapping_add(sigma1(s[1]));
    let w17 = w[2].wrapping_add(sigma1(s[0]));
    let w18 = w[1].wrapping_add(sigma1(w16));
    let w19 = w[0].wrapping_add(sigma1(w17));
    write_trunc(cpu, dst, from_dwords([w19, w18, w17, w16]));
}

pub const HELPERS: &[(&str, PcodeOpHelper)] = &[
    ("aesenc", |c, d, a| aes_round(c, d, a, false, true)),
    ("aesenclast", |c, d, a| aes_round(c, d, a, false, false)),
    ("aesdec", |c, d, a| aes_round(c, d, a, true, true)),
    ("aesdeclast", |c, d, a| aes_round(c, d, a, true, false)),
    ("aesimc", aesimc),
    ("aeskeygenassist", aeskeygenassist),
    ("sha1rnds4_sha", sha1rnds4),
    ("sha1nexte_sha", sha1nexte),
    ("sha1msg1_sha", sha1msg1),
    ("sha1msg2_sha", sha1msg2),
    ("sha256rnds2_sha", sha256rnds2),
    ("sha256msg1_sha", sha256msg1),
    ("sha256msg2_sha", sha256msg2),
];
