//! The remaining x87 instructions, FXSAVE, XSAVE and small state instructions.

use icicle_vm::cpu::{Cpu, Exception, ExceptionCode, ValueSource, exec::helpers::PcodeOpHelper, mem::perm};
use pcode::{Value, VarNode};

use super::{super::is_x64, *};

fn st(cpu: &Cpu, value: Value) -> f64 {
    f64::from_bits(rd(cpu, value) as u64)
}

fn set_st(cpu: &mut Cpu, dst: VarNode, value: f64) {
    write_trunc(cpu, dst, value.to_bits() as u128);
}

fn f80_to_f64(raw: u128) -> f64 {
    let (mantissa, exponent) = (raw as u64, (raw >> 64) as i32 & 0x7FFF);
    let sign = ((raw >> 79) as u64 & 1) << 63;
    if exponent != 0 && mantissa >> 63 == 0 {
        // an unnormal is invalid, so we return the default NaN
        return f64::from_bits(0xFFF8_0000_0000_0000);
    }
    if exponent == 0x7FFF && mantissa << 1 != 0 {
        // a NaN keeps the payload and becomes quiet
        return f64::from_bits(sign | 0x7FF8_0000_0000_0000 | ((mantissa << 1) >> 12));
    }
    let magnitude = if exponent == 0x7FFF {
        f64::INFINITY
    } else if mantissa == 0 {
        0.0
    } else {
        // The value is mantissa * 2^(exponent - 16383 - 63). We scale in two steps so that a
        // subnormal result is only rounded once.
        let lead = mantissa.leading_zeros() as i32;
        let m = (mantissa << lead) as f64;
        let e = exponent.max(1) - 16383 - 63 - lead;
        m * 2f64.powi(e.clamp(-2000, 2000) / 2) * 2f64.powi(e.clamp(-2000, 2000) - e.clamp(-2000, 2000) / 2)
    };
    if sign != 0 { -magnitude } else { magnitude }
}

fn f64_to_f80(value: f64) -> u128 {
    let bits = value.to_bits();
    let exponent = (bits >> 52) as i32 & 0x7FF;
    let fraction = bits & ((1 << 52) - 1);
    let (e, m) = if exponent == 0x7FF {
        // infinity, or a NaN with the payload
        (0x7FFF, (1 << 63) | (fraction << 11))
    } else if exponent == 0 {
        if fraction == 0 {
            (0, 0)
        } else {
            let lead = fraction.leading_zeros() as i32;
            (16383 - 1022 - (lead - 11), fraction << lead)
        }
    } else {
        (exponent - 1023 + 16383, (1 << 63) | (fraction << 11))
    };
    ((bits >> 63) as u128) << 79 | ((e as u128 & 0x7FFF) << 64) | m as u128
}

/// The number of spare registers that keep exact x87 values.
/// We added the spare registers to the SLEIGH spec.
///
/// A double cannot hold every value loaded from an 80-bit operand, a 64-bit integer or a BCD
/// operand, so we also keep the exact 80-bit value in a spare register. The two bytes of the x87
/// register that the double does not use hold the tag of the spare register. A register move copies
/// the tag and arithmetic clears the tag, so fstp m80, fistp m64 and fbstp store a tagged value as
/// loaded.
const SLOTS: u16 = 16;

/// This function returns the two registers of a spare slot. The first register holds the double
/// and the second register holds the exact 80-bit value.
fn slot(cpu: &Cpu, index: u16) -> (VarNode, VarNode) {
    (reg(cpu, &format!("X87K{index}")), reg(cpu, &format!("X87V{index}")))
}

/// This function returns the ten bytes of an x87 register for `value`. We add a tag if the double
/// cannot hold the 80-bit value `exact`.
fn tagged(cpu: &mut Cpu, value: f64, exact: u128) -> u128 {
    let bits = value.to_bits() as u128;
    if f64_to_f80(value) == exact {
        return bits;
    }
    let counter = reg(cpu, "X87XN");
    let index = cpu.read_var::<u8>(counter) as u16 % SLOTS;
    cpu.write_var::<u8>(counter, (index + 1) as u8);
    let (key, value) = slot(cpu, index);
    write_trunc(cpu, key, bits);
    write_trunc(cpu, value, exact);
    bits | ((index as u128 + 1) << 64)
}

/// This function returns the exact 80-bit value of an x87 register operand. We widen the double if
/// the operand has no tag.
fn exact(cpu: &Cpu, value: Value) -> u128 {
    let raw = rd(cpu, value);
    let (bits, tag) = (raw as u64, (raw >> 64) as u16);
    if (1..=SLOTS).contains(&tag) {
        let (key, value) = slot(cpu, tag - 1);
        if rd(cpu, Value::Var(key)) as u64 == bits {
            return rd(cpu, Value::Var(value));
        }
    }
    f64_to_f80(f64::from_bits(bits))
}

fn int_to_f80(value: i128) -> u128 {
    let magnitude = value.unsigned_abs();
    if magnitude == 0 {
        return 0;
    }
    let lead = magnitude.leading_zeros();
    // the top bit of the magnitude becomes the explicit integer bit
    let mantissa = ((magnitude << lead) >> 64) as u64;
    let exponent = 16383 + 127 - lead as u128;
    ((value < 0) as u128) << 79 | exponent << 64 | mantissa as u128
}

/// This function converts an 80-bit value to a 64-bit integer, either rounded to nearest even or
/// truncated. This function returns `None` if the value does not fit.
fn f80_to_int(raw: u128, truncate: bool) -> Option<i64> {
    let (mantissa, exponent, negative) = (raw as u64, (raw >> 64) as i32 & 0x7FFF, raw >> 79 & 1 != 0);
    if exponent == 0x7FFF || (exponent != 0 && mantissa >> 63 == 0) {
        return None;
    }
    // value = mantissa * 2^-shift
    let shift = 16383 + 63 - exponent.max(1);
    let magnitude: u128 = if shift < 0 {
        return None;
    } else if shift == 0 {
        mantissa as u128
    } else if shift > 64 {
        0
    } else {
        let wide = (mantissa as u128) << 64 >> shift;
        let (whole, rest) = (wide >> 64, wide as u64);
        let up = !truncate && (rest > 1 << 63 || (rest == 1 << 63 && whole & 1 == 1));
        whole + up as u128
    };
    let value = if negative { -(magnitude as i128) } else { magnitude as i128 };
    i64::try_from(value).ok()
}

fn from_int(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let value = rd(cpu, args[0]) as u64 as i64;
    let out = tagged(cpu, value as f64, int_to_f80(value as i128));
    write_trunc(cpu, dst, out);
}

/// `x87_to_int(st, truncate)` implements fistp m64 and fisttp m64.
/// We return the integer indefinite if the value does not fit.
fn to_int(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let truncate = rd(cpu, args[1]) != 0;
    let value = f80_to_int(exact(cpu, args[0]), truncate).unwrap_or(i64::MIN);
    write_trunc(cpu, dst, value as u64 as u128);
}

/// This function computes the remainder for fprem and fprem1 in our patched SLEIGH spec.
/// C0, C3 and C1 get the low bits of the quotient.
fn partial_remainder(cpu: &mut Cpu, dst: VarNode, args: Args, nearest: bool) {
    let (x, y) = (st(cpu, args[0]), st(cpu, args[1]));
    let mut rem = x % y;
    let mut quotient = ((x - rem) / y).abs();
    if nearest && rem.is_finite() {
        let (half, r) = ((y / 2.0).abs(), rem.abs());
        if r > half || (r == half && quotient % 2.0 == 1.0) {
            rem -= y.abs().copysign(rem);
            quotient += 1.0;
        }
    }
    let q = if quotient.is_finite() {
        (quotient % 8.0) as u8
    } else {
        0
    };
    set_flag(cpu, "C0", q & 4 != 0);
    set_flag(cpu, "C3", q & 2 != 0);
    set_flag(cpu, "C1", q & 1 != 0);
    set_flag(cpu, "C2", false);
    set_st(cpu, dst, rem);
}

fn from_bcd(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let raw = rd(cpu, args[0]);
    let magnitude = (0..18)
        .rev()
        .fold(0i128, |acc, i| acc * 10 + ((raw >> (4 * i)) & 0xF) as i128);
    let value = if raw >> 79 & 1 != 0 { -magnitude } else { magnitude };
    let mut out = tagged(cpu, value as f64, int_to_f80(value));
    if value == 0 && raw >> 79 & 1 != 0 {
        out = (-0.0f64).to_bits() as u128;
    }
    write_trunc(cpu, dst, out);
}

fn to_bcd(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let source = exact(cpu, args[0]);
    let out = match f80_to_int(source, false) {
        Some(value) if value.unsigned_abs() < 1_000_000_000_000_000_000 => {
            let mut magnitude = value.unsigned_abs();
            let mut digits = 0u128;
            for i in 0..18 {
                digits |= ((magnitude % 10) as u128) << (4 * i);
                magnitude /= 10;
            }
            digits | (source >> 79 & 1) << 79
        }
        // the packed-decimal indefinite
        _ => 0xFFFF_C000_0000_0000_0000u128,
    };
    write_trunc(cpu, dst, out);
}

fn extract_exponent(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let value = st(cpu, args[0]);
    let exponent = if value == 0.0 {
        f64::NEG_INFINITY
    } else if value.is_finite() {
        let bits = value.abs().to_bits();
        if bits >> 52 == 0 {
            // subnormal
            -1011.0 - (bits.leading_zeros() as f64)
        } else {
            (bits >> 52) as f64 - 1023.0
        }
    } else {
        value.abs()
    };
    set_st(cpu, dst, exponent);
}

fn extract_significand(cpu: &mut Cpu, dst: VarNode, args: Args) {
    let value = st(cpu, args[0]);
    let significand = if value == 0.0 || !value.is_finite() {
        value
    } else {
        let bits = value.to_bits();
        let fraction = if (bits >> 52) & 0x7FF == 0 {
            let lead = (bits << 12).leading_zeros();
            (bits << (lead + 1)) & ((1 << 52) - 1)
        } else {
            bits & ((1 << 52) - 1)
        };
        f64::from_bits((bits & (1 << 63)) | (1023 << 52) | fraction)
    };
    set_st(cpu, dst, significand);
}

fn xmm_count(cpu: &Cpu) -> usize {
    if is_x64(cpu) { 16 } else { 8 }
}

/// This function builds the FXSAVE image, which holds the x87 control state, the x87 registers as
/// 80-bit values, MXCSR and the XMM registers.
fn fxsave_image(cpu: &Cpu) -> [u8; 512] {
    let mut image = [0u8; 512];
    let word = |name: &str| cpu.read_var::<u16>(reg(cpu, name));
    image[0..2].copy_from_slice(&word("FPUControlWord").to_le_bytes());
    image[2..4].copy_from_slice(&word("FPUStatusWord").to_le_bytes());
    let tag = word("FPUTagWord");
    // the abridged tag has one bit per register, and the bit is set unless the register is empty
    image[4] = (0..8).fold(0, |acc, i| acc | (((tag >> (2 * i)) & 3 != 3) as u8) << i);
    image[24..28].copy_from_slice(&cpu.read_var::<u32>(reg(cpu, "MXCSR")).to_le_bytes());
    image[28..32].copy_from_slice(&0xFFFFu32.to_le_bytes());
    for i in 0..8 {
        let value = exact(cpu, Value::Var(reg(cpu, &format!("ST{i}"))));
        let at = 32 + 16 * i;
        image[at..at + 10].copy_from_slice(&value.to_le_bytes()[..10]);
    }
    for i in 0..xmm_count(cpu) {
        let value = rd(cpu, Value::Var(reg(cpu, &format!("XMM{i}"))));
        let at = 160 + 16 * i;
        image[at..at + 16].copy_from_slice(&value.to_le_bytes());
    }
    image
}

fn load_fxsave_image(cpu: &mut Cpu, image: &[u8; 512], x87: bool, sse: bool) {
    let chunk = |at: usize, len: usize| {
        let mut raw = [0u8; 16];
        raw[..len].copy_from_slice(&image[at..at + len]);
        u128::from_le_bytes(raw)
    };
    if x87 {
        let tag = (0..8).fold(0u128, |acc, i| {
            acc | (if image[4] >> i & 1 != 0 { 0 } else { 3 }) << (2 * i)
        });
        for (name, value) in [("FPUControlWord", chunk(0, 2)), ("FPUStatusWord", chunk(2, 2)), ("FPUTagWord", tag)] {
            let var = reg(cpu, name);
            write_trunc(cpu, var, value);
        }
        for i in 0..8 {
            let var = reg(cpu, &format!("ST{i}"));
            let raw = chunk(32 + 16 * i, 10);
            let value = tagged(cpu, f80_to_f64(raw), raw);
            write_trunc(cpu, var, value);
        }
    }
    if sse {
        let var = reg(cpu, "MXCSR");
        write_trunc(cpu, var, chunk(24, 4));
        for i in 0..xmm_count(cpu) {
            let var = reg(cpu, &format!("XMM{i}"));
            write_trunc(cpu, var, chunk(160 + 16 * i, 16));
        }
    }
}

fn store(cpu: &mut Cpu, addr: u64, data: &[u8]) -> bool {
    match cpu.mem.write_bytes(addr, data, perm::WRITE) {
        Ok(()) => true,
        Err(err) => {
            cpu.exception = Exception::new(ExceptionCode::from_store_error(err), addr);
            false
        }
    }
}

fn load<const N: usize>(cpu: &mut Cpu, addr: u64) -> Option<[u8; N]> {
    let mut data = [0u8; N];
    match cpu.mem.read_bytes(addr, &mut data, perm::READ) {
        Ok(()) => Some(data),
        Err(err) => {
            cpu.exception = Exception::new(ExceptionCode::from_load_error(err), addr);
            None
        }
    }
}

fn fxsave(cpu: &mut Cpu, _: VarNode, args: Args) {
    let addr = rd(cpu, args[0]) as u64;
    let image = fxsave_image(cpu);
    // FXSAVE does not write the last 96 bytes of the area
    store(cpu, addr, &image[..416]);
}

fn fxrstor(cpu: &mut Cpu, _: VarNode, args: Args) {
    let addr = rd(cpu, args[0]) as u64;
    if let Some(image) = load::<512>(cpu, addr) {
        load_fxsave_image(cpu, &image, true, true);
    }
}

/// This function returns the state components that XCR0 and eax request. We only handle x87, which
/// is 1, and SSE, which is 2.
fn xsave_components(cpu: &mut Cpu) -> u64 {
    let (eax, xcr0) = (reg(cpu, "EAX"), reg(cpu, "XCR0"));
    cpu.read_reg(eax) & cpu.read_reg(xcr0) & 3
}

fn xsave(cpu: &mut Cpu, _: VarNode, args: Args) {
    let addr = rd(cpu, args[0]) as u64;
    let components = xsave_components(cpu);
    let image = fxsave_image(cpu);
    let Some(header) = load::<8>(cpu, addr + 512) else {
        return;
    };
    let x87 = components & 1 == 0 || (store(cpu, addr, &image[..24]) && store(cpu, addr + 32, &image[32..160]));
    // XSAVE saves MXCSR with either component
    let done = x87
        && store(cpu, addr + 24, &image[24..32])
        && (components & 2 == 0 || store(cpu, addr + 160, &image[160..416]));
    if done {
        let saved = (u64::from_le_bytes(header) & !3) | components;
        store(cpu, addr + 512, &saved.to_le_bytes());
    }
}

fn xrstor(cpu: &mut Cpu, _: VarNode, args: Args) {
    let addr = rd(cpu, args[0]) as u64;
    let components = xsave_components(cpu);
    let (Some(image), Some(header)) = (load::<512>(cpu, addr), load::<8>(cpu, addr + 512)) else {
        return;
    };
    let present = u64::from_le_bytes(header);
    // XRSTOR resets a requested component that is absent from the image to the initial state
    let mut initial = [0u8; 512];
    initial[0..2].copy_from_slice(&0x37Fu16.to_le_bytes());
    initial[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
    for (bit, x87) in [(1, true), (2, false)] {
        if components & bit != 0 {
            let source = if present & bit != 0 { &image } else { &initial };
            load_fxsave_image(cpu, source, x87, !x87);
        }
    }
}

/// rdrand and rdseed return a repeatable sequence, which is splitmix64 of the instruction count.
fn random(cpu: &mut Cpu, dst: VarNode, _: Args) {
    let mut z = (cpu.icount ^ 0x9E37_79B9_7F4A_7C15).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    write_trunc(cpu, dst, (z ^ (z >> 31)) as u128);
}

fn one(cpu: &mut Cpu, dst: VarNode, _: Args) {
    write_trunc(cpu, dst, 1);
}

fn nop(_: &mut Cpu, _: VarNode, _: Args) {}

pub const HELPERS: &[(&str, PcodeOpHelper)] = &[
    // we added these user ops to the SLEIGH spec for 80-bit fld and fstp, fprem and fprem1
    ("f80_decode", |c, d, a| {
        let raw = rd(c, a[0]);
        let value = tagged(c, f80_to_f64(raw), raw);
        write_trunc(c, d, value)
    }),
    ("f80_encode", |c, d, a| {
        let value = exact(c, a[0]);
        write_trunc(c, d, value)
    }),
    ("x87_from_int", from_int),
    ("x87_to_int", to_int),
    ("fprem", |c, d, a| partial_remainder(c, d, a, false)),
    ("fprem1", |c, d, a| partial_remainder(c, d, a, true)),
    ("fpatan", |c, d, a| {
        let value = st(c, a[0]).atan2(st(c, a[1]));
        set_st(c, d, value)
    }),
    ("log2", |c, d, a| {
        let value = st(c, a[0]).log2();
        set_st(c, d, value)
    }),
    ("extract_significand", extract_significand),
    ("extract_exponent", extract_exponent),
    ("from_bcd", from_bcd),
    ("to_bcd", to_bcd),
    // we do not keep the tag word per register, so ffree leaves the tag word unchanged
    ("ffree", |c, d, _| {
        let tag = c.read_var::<u16>(reg(c, "FPUTagWord"));
        write_trunc(c, d, tag as u128)
    }),
    ("_fxsave", fxsave),
    ("_fxsave64", fxsave),
    ("_fxrstor", fxrstor),
    ("_fxrstor64", fxrstor),
    ("xsave", xsave),
    ("xsave64", xsave),
    ("xsaveopt", xsave),
    ("xsaveopt64", xsave),
    ("xrstor", xrstor),
    ("xrstor64", xrstor),
    ("rdrand", random),
    ("rdseed", random),
    ("rdrandIsValid", one),
    ("rdseedIsValid", one),
    ("clflush", nop),
    ("clflushopt", nop),
];
