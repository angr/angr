//! Known-bits (tristate) folding over bitvector terms.
//!
//! Every bit of a term is known-0, known-1 or unknown. Known bits are propagated bottom-up
//! through the bitwise, shift, extension, concat, select and add/sub operators (with
//! carry-aware propagation for the latter) and the unsigned bounds of urem/udiv, and a node
//! whose bits are all known is folded to that constant. Comparisons whose outcome the known
//! bits decide fold to a Bool. Nothing is done on partial knowledge: the shape of a
//! non-folding term is left to the other rules. Results are memoised per simplify call by
//! hash-consed node.

use ahash::AHashMap;
use num_bigint::{BigInt, BigUint};

use crate::prelude::*;

/// Upper bound on nodes analysed per query (nodes already memoised are free).
const MAX_NEW_NODES: usize = 512;

/// `value & known == value`: `known` masks the bits whose value is `value`.
#[derive(Clone, Debug)]
pub(super) struct KnownBits {
    known: BitVec,
    value: BitVec,
}

pub(super) type KnownMemo = AHashMap<u64, KnownBits>;

fn low_mask(width: u32, bits: u32) -> BitVec {
    if bits >= width {
        BitVec::ones(width)
    } else if bits == 0 {
        BitVec::zeros(width)
    } else {
        (BitVec::ones(width) >> (width - bits)).expect("shift")
    }
}

fn high_mask(width: u32, bits: u32) -> BitVec {
    (!low_mask(width, width.saturating_sub(bits))).expect("not")
}

impl KnownBits {
    pub(super) fn unknown(width: u32) -> Self {
        Self {
            known: BitVec::zeros(width),
            value: BitVec::zeros(width),
        }
    }

    pub(super) fn constant(value: BitVec) -> Self {
        Self {
            known: BitVec::ones(value.len()),
            value,
        }
    }

    /// `value` restricted to `known`; the canonical form of a (known, value) pair.
    pub(super) fn new(known: BitVec, value: BitVec) -> Result<Self, ClarirsError> {
        let value = (value & known.clone())?;
        Ok(Self { known, value })
    }

    pub(super) fn width(&self) -> u32 {
        self.known.len()
    }

    #[cfg(test)]
    pub(super) fn known(&self) -> &BitVec {
        &self.known
    }

    #[cfg(test)]
    pub(super) fn value(&self) -> &BitVec {
        &self.value
    }

    /// Bits known to be 1.
    fn ones(&self) -> BitVec {
        self.value.clone()
    }

    /// Bits known to be 0.
    fn zeros(&self) -> Result<BitVec, ClarirsError> {
        Ok((self.known.clone() & (!self.value.clone())?)?)
    }

    pub(super) fn all_known(&self) -> Option<&BitVec> {
        self.known.is_all_ones().then_some(&self.value)
    }

    fn sign_known(&self) -> Option<bool> {
        self.known.sign().then_some(self.value.sign())
    }

    fn trailing_known_zeros(&self) -> u32 {
        let w = self.width();
        match (!self.zeros().expect("zeros")).expect("not").to_biguint().trailing_zeros() {
            Some(n) => (n as u32).min(w),
            None => w,
        }
    }

    pub(super) fn not(&self) -> Result<Self, ClarirsError> {
        Self::new(self.known.clone(), (!self.value.clone())?)
    }

    pub(super) fn and(&self, other: &Self) -> Result<Self, ClarirsError> {
        let ones = (self.ones() & other.ones())?;
        let zeros = (self.zeros()? | other.zeros()?)?;
        Self::new((ones.clone() | zeros)?, ones)
    }

    pub(super) fn or(&self, other: &Self) -> Result<Self, ClarirsError> {
        let ones = (self.ones() | other.ones())?;
        let zeros = (self.zeros()? & other.zeros()?)?;
        Self::new((ones.clone() | zeros)?, ones)
    }

    pub(super) fn xor(&self, other: &Self) -> Result<Self, ClarirsError> {
        Self::new(
            (self.known.clone() & other.known.clone())?,
            (self.value.clone() ^ other.value.clone())?,
        )
    }

    /// `self + other + carry` where `carry` is None when unknown. A carry into bit i is known
    /// 0 when even the largest consistent operands produce none, known 1 when the smallest
    /// consistent operands produce one; a sum bit is known when both operand bits and the
    /// carry are.
    pub(super) fn add_with_carry(
        &self,
        other: &Self,
        carry: Option<bool>,
    ) -> Result<Self, ClarirsError> {
        let w = self.width();
        let one = BitVec::from((1u64, w));
        let zero = BitVec::zeros(w);
        let (carry_zero, carry_one) = match carry {
            Some(true) => (false, true),
            Some(false) => (true, false),
            None => (false, false),
        };
        let lhs_max = (!self.zeros()?)?;
        let rhs_max = (!other.zeros()?)?;
        let sum_max = ((lhs_max + rhs_max)? + if carry_zero { zero.clone() } else { one.clone() })?;
        let sum_min = ((self.ones() + other.ones())? + if carry_one { one } else { zero })?;
        let carry_known_zero = (!((sum_max.clone() ^ self.zeros()?)? ^ other.zeros()?)?)?;
        let carry_known_one = ((sum_min.clone() ^ self.ones())? ^ other.ones())?;
        let known = ((self.known.clone() & other.known.clone())?
            & (carry_known_zero | carry_known_one)?)?;
        Self::new(known, sum_min)
    }

    pub(super) fn add(&self, other: &Self) -> Result<Self, ClarirsError> {
        self.add_with_carry(other, Some(false))
    }

    /// `self - other = self + !other + 1`.
    pub(super) fn sub(&self, other: &Self) -> Result<Self, ClarirsError> {
        self.add_with_carry(&other.not()?, Some(true))
    }

    pub(super) fn neg(&self) -> Result<Self, ClarirsError> {
        Self::constant(BitVec::zeros(self.width())).sub(self)
    }

    pub(super) fn shl(&self, amount: u32) -> Result<Self, ClarirsError> {
        let w = self.width();
        if amount >= w {
            return Ok(Self::constant(BitVec::zeros(w)));
        }
        Self::new(
            ((self.known.clone() << amount)? | low_mask(w, amount))?,
            (self.value.clone() << amount)?,
        )
    }

    pub(super) fn lshr(&self, amount: u32) -> Result<Self, ClarirsError> {
        let w = self.width();
        if amount >= w {
            return Ok(Self::constant(BitVec::zeros(w)));
        }
        Self::new(
            ((self.known.clone() >> amount)? | high_mask(w, amount))?,
            (self.value.clone() >> amount)?,
        )
    }

    pub(super) fn ashr(&self, amount: u32) -> Result<Self, ClarirsError> {
        let w = self.width();
        // Shifting by w - 1 or more leaves only copies of the sign bit.
        let amount = amount.min(w - 1);
        let (known_fill, value_fill) = match self.sign_known() {
            Some(sign) => (
                high_mask(w, amount),
                if sign { high_mask(w, amount) } else { BitVec::zeros(w) },
            ),
            None => (BitVec::zeros(w), BitVec::zeros(w)),
        };
        Self::new(
            ((self.known.clone() >> amount)? | known_fill)?,
            ((self.value.clone() >> amount)? | value_fill)?,
        )
    }

    pub(super) fn rotate_left(&self, amount: u32) -> Result<Self, ClarirsError> {
        Self::new(
            self.known.rotate_left(amount)?,
            self.value.rotate_left(amount)?,
        )
    }

    pub(super) fn rotate_right(&self, amount: u32) -> Result<Self, ClarirsError> {
        Self::new(
            self.known.rotate_right(amount)?,
            self.value.rotate_right(amount)?,
        )
    }

    pub(super) fn zero_ext(&self, bits: u32) -> Result<Self, ClarirsError> {
        let w = self.width() + bits;
        Self::new(
            (self.known.zero_extend(bits)? | high_mask(w, bits))?,
            self.value.zero_extend(bits)?,
        )
    }

    /// The extension bits are known exactly when the sign bit is; `value`'s sign bit is the
    /// sign when known and 0 otherwise, so sign-extending both masks is exact.
    pub(super) fn sign_ext(&self, bits: u32) -> Result<Self, ClarirsError> {
        Self::new(self.known.sign_extend(bits)?, self.value.sign_extend(bits)?)
    }

    pub(super) fn extract(&self, high: u32, low: u32) -> Result<Self, ClarirsError> {
        Self::new(self.known.extract(low, high)?, self.value.extract(low, high)?)
    }

    /// `self` becomes the high part.
    pub(super) fn concat(&self, low: &Self) -> Result<Self, ClarirsError> {
        Self::new(self.known.concat(&low.known)?, self.value.concat(&low.value)?)
    }

    pub(super) fn byte_reverse(&self) -> Result<Self, ClarirsError> {
        Self::new(self.known.reverse_bytes()?, self.value.reverse_bytes()?)
    }

    /// Either branch: bits known in both with the same value.
    pub(super) fn select(&self, other: &Self) -> Result<Self, ClarirsError> {
        let agree = (!(self.value.clone() ^ other.value.clone())?)?;
        let known = ((self.known.clone() & other.known.clone())? & agree)?;
        Self::new(known, self.value.clone())
    }

    /// Product: low bits are known 0 up to the sum of the factors' trailing known zeros;
    /// a power-of-two constant factor is a shift of the other factor.
    pub(super) fn mul(&self, other: &Self) -> Result<Self, ClarirsError> {
        let w = self.width();
        for (a, b) in [(self, other), (other, self)] {
            if let Some(c) = a.all_known()
                && !c.is_zero()
            {
                let tz = c.to_biguint().trailing_zeros().unwrap_or(0) as u32;
                if (c.clone() >> tz)?.is_one() {
                    return b.shl(tz);
                }
            }
        }
        let tz = (self.trailing_known_zeros() + other.trailing_known_zeros()).min(w);
        Self::new(low_mask(w, tz), BitVec::zeros(w))
    }

    /// Smallest unsigned value consistent with the known bits.
    pub(super) fn umin(&self) -> BigUint {
        self.ones().to_biguint()
    }

    /// Largest unsigned value consistent with the known bits.
    pub(super) fn umax(&self) -> BigUint {
        (!self.zeros().expect("zeros")).expect("not").to_biguint()
    }

    /// Signed bounds: the sign bit is 1 for the minimum and 0 for the maximum unless known.
    pub(super) fn smin_smax(&self) -> (BigInt, BigInt) {
        let w = self.width();
        let sign = high_mask(w, 1);
        let lo = match self.sign_known() {
            Some(_) => self.ones(),
            None => (self.ones() | sign.clone()).expect("or"),
        };
        let hi = (!self.zeros().expect("zeros")).expect("not");
        let hi = match self.sign_known() {
            Some(_) => hi,
            None => (hi & (!sign).expect("not")).expect("and"),
        };
        (lo.to_bigint(), hi.to_bigint())
    }

    /// Every value is at most `bound`: the bits above its highest set bit are 0.
    fn at_most(width: u32, bound: &BigUint) -> Result<Self, ClarirsError> {
        let bits = (bound.bits() as u32).min(width);
        Self::new(high_mask(width, width - bits), BitVec::zeros(width))
    }

    /// Bits known in either; both must be sound for the same value.
    fn merge(&self, other: &Self) -> Result<Self, ClarirsError> {
        Self::new(
            (self.known.clone() | other.known.clone())?,
            (self.value.clone() | other.value.clone())?,
        )
    }

    /// `a % b` with `a % 0 = a`: at most `a`, and below `b` when `b` is nonzero. A constant
    /// `b = m * 2^k` keeps `a`'s low `k` bits, since `a = q * b + r`.
    pub(super) fn urem(&self, other: &Self) -> Result<Self, ClarirsError> {
        let w = self.width();
        let mut bound = self.umax();
        if other.umin() != BigUint::ZERO {
            bound = bound.min(other.umax() - 1u32);
        }
        let r = Self::at_most(w, &bound)?;
        match other.all_known() {
            Some(c) if !c.is_zero() => {
                let tz = c.to_biguint().trailing_zeros().unwrap_or(0) as u32;
                let low = low_mask(w, tz);
                r.merge(&Self::new(
                    (self.known.clone() & low.clone())?,
                    (self.value.clone() & low)?,
                )?)
            }
            _ => Ok(r),
        }
    }

    /// `a / b` for `b` known nonzero (`a / 0` is all ones): at most `max(a) / min(b)`; a
    /// power-of-two constant is a shift.
    pub(super) fn udiv(&self, other: &Self) -> Result<Self, ClarirsError> {
        let w = self.width();
        let bmin = other.umin();
        if bmin == BigUint::ZERO {
            return Ok(Self::unknown(w));
        }
        if let Some(c) = other.all_known() {
            let tz = c.to_biguint().trailing_zeros().unwrap_or(0) as u32;
            if (c.clone() >> tz)?.is_one() {
                return self.lshr(tz);
            }
        }
        Self::at_most(w, &(self.umax() / bmin))
    }
}

/// Whether `node`'s bits must not be reasoned about: a pinned annotation, a VSA set, or a
/// concrete subtree the driver leaves alone.
fn opaque(node: &AstRef<'_>) -> bool {
    !node.simplifiable()
        || node.op().is_inherently_symbolic()
        || node
            .annotations()
            .iter()
            .any(|a| !a.eliminatable() && !a.relocatable())
}

fn shift_amount(node: &AstRef<'_>, width: u32) -> Option<u32> {
    match node.op() {
        AstOp::BVV(v) => Some(
            v.to_biguint()
                .min(num_bigint::BigUint::from(width))
                .try_into()
                .unwrap_or(width),
        ),
        _ => None,
    }
}

fn rotate_amount(node: &AstRef<'_>, width: u32) -> Option<u32> {
    match node.op() {
        AstOp::BVV(v) => (v.to_biguint() % width).try_into().ok(),
        _ => None,
    }
}

/// The bitvector operands whose known bits `transfer` reads.
fn operands<'c>(node: &AstRef<'c>) -> Vec<AstRef<'c>> {
    match node.op() {
        AstOp::Not(a)
        | AstOp::Neg(a)
        | AstOp::ZeroExt(a, _)
        | AstOp::SignExt(a, _)
        | AstOp::Extract(a, _, _)
        | AstOp::ByteReverse(a) => vec![a.clone()],
        AstOp::And(args)
        | AstOp::Or(args)
        | AstOp::Xor(args)
        | AstOp::Add(args)
        | AstOp::Mul(args)
        | AstOp::Concat(args) => args.clone(),
        AstOp::Sub(a, b) | AstOp::URem(a, b) | AstOp::UDiv(a, b) => vec![a.clone(), b.clone()],
        AstOp::ShL(a, k)
        | AstOp::LShR(a, k)
        | AstOp::AShR(a, k)
        | AstOp::RotateLeft(a, k)
        | AstOp::RotateRight(a, k) => {
            if matches!(k.op(), AstOp::BVV(_)) {
                vec![a.clone()]
            } else {
                vec![]
            }
        }
        AstOp::ITE(_, t, e) => vec![t.clone(), e.clone()],
        _ => vec![],
    }
}

fn fold_args<'c>(
    args: &[AstRef<'c>],
    memo: &KnownMemo,
    f: impl Fn(&KnownBits, &KnownBits) -> Result<KnownBits, ClarirsError>,
) -> Result<KnownBits, ClarirsError> {
    let mut acc = memo[&args[0].hash()].clone();
    for a in &args[1..] {
        acc = f(&acc, &memo[&a.hash()])?;
    }
    Ok(acc)
}

/// Known bits of `node` from its operands' memoised known bits.
fn transfer<'c>(node: &AstRef<'c>, memo: &KnownMemo) -> Result<KnownBits, ClarirsError> {
    let width = node.size();
    let get = |a: &AstRef<'c>| memo[&a.hash()].clone();
    Ok(match node.op() {
        AstOp::BVV(v) => KnownBits::constant(v.clone()),
        AstOp::Not(a) => get(a).not()?,
        AstOp::And(args) => fold_args(args, memo, |a, b| a.and(b))?,
        AstOp::Or(args) => fold_args(args, memo, |a, b| a.or(b))?,
        AstOp::Xor(args) => fold_args(args, memo, |a, b| a.xor(b))?,
        AstOp::Add(args) => fold_args(args, memo, |a, b| a.add(b))?,
        AstOp::Mul(args) => fold_args(args, memo, |a, b| a.mul(b))?,
        AstOp::Sub(a, b) => get(a).sub(&get(b))?,
        AstOp::Neg(a) => get(a).neg()?,
        AstOp::URem(a, b) => get(a).urem(&get(b))?,
        AstOp::UDiv(a, b) => get(a).udiv(&get(b))?,
        AstOp::ShL(a, k) => match shift_amount(k, width) {
            Some(k) => get(a).shl(k)?,
            None => KnownBits::unknown(width),
        },
        AstOp::LShR(a, k) => match shift_amount(k, width) {
            Some(k) => get(a).lshr(k)?,
            None => KnownBits::unknown(width),
        },
        AstOp::AShR(a, k) => match shift_amount(k, width) {
            Some(k) => get(a).ashr(k)?,
            None => KnownBits::unknown(width),
        },
        AstOp::RotateLeft(a, k) => match rotate_amount(k, width) {
            Some(k) => get(a).rotate_left(k)?,
            None => KnownBits::unknown(width),
        },
        AstOp::RotateRight(a, k) => match rotate_amount(k, width) {
            Some(k) => get(a).rotate_right(k)?,
            None => KnownBits::unknown(width),
        },
        AstOp::ZeroExt(a, n) => get(a).zero_ext(*n)?,
        AstOp::SignExt(a, n) => get(a).sign_ext(*n)?,
        AstOp::Extract(a, high, low) => get(a).extract(*high, *low)?,
        AstOp::Concat(args) => fold_args(args, memo, |a, b| a.concat(b))?,
        AstOp::ByteReverse(a) => match get(a).byte_reverse() {
            Ok(k) => k,
            Err(_) => KnownBits::unknown(width),
        },
        AstOp::ITE(_, t, e) => get(t).select(&get(e))?,
        _ => KnownBits::unknown(width),
    })
}

/// Known bits of `root`, memoised. Gives up (all unknown) past `MAX_NEW_NODES` fresh nodes.
pub(super) fn known_bits<'c>(
    root: &AstRef<'c>,
    memo: &mut KnownMemo,
) -> Result<KnownBits, ClarirsError> {
    if let Some(k) = memo.get(&root.hash()) {
        return Ok(k.clone());
    }
    let mut budget = MAX_NEW_NODES;
    // (node, operands pushed)
    let mut stack: Vec<(AstRef<'c>, bool)> = vec![(root.clone(), false)];
    while let Some((node, expanded)) = stack.pop() {
        let hash = node.hash();
        if memo.contains_key(&hash) {
            continue;
        }
        if expanded {
            let k = transfer(&node, memo)?;
            memo.insert(hash, k);
            continue;
        }
        if opaque(&node) {
            memo.insert(hash, KnownBits::unknown(node.size()));
            continue;
        }
        if budget == 0 {
            let k = KnownBits::unknown(root.size());
            memo.insert(root.hash(), k.clone());
            return Ok(k);
        }
        budget -= 1;
        stack.push((node.clone(), true));
        for a in operands(&node) {
            if !memo.contains_key(&a.hash()) {
                stack.push((a, false));
            }
        }
    }
    Ok(memo[&root.hash()].clone())
}

/// The constant `ast` equals when all of its bits are known.
pub(super) fn fold<'c>(
    ast: &AstRef<'c>,
    memo: &mut KnownMemo,
) -> Result<Option<BitVec>, ClarirsError> {
    if !matches!(ast.ast_type(), AstType::BitVec(_)) || matches!(ast.op(), AstOp::BVV(_)) {
        return Ok(None);
    }
    Ok(known_bits(ast, memo)?.all_known().cloned())
}

/// `big = small + d` with no wrap-around, as the range of `d`: `big` is an Add with `small`
/// among its operands, or `small * k` for a constant `k >= 1`, and the operands' largest
/// values sum below `2^w`.
fn offset<'c>(
    big: &AstRef<'c>,
    small: &AstRef<'c>,
    memo: &mut KnownMemo,
) -> Result<Option<(BigUint, BigUint)>, ClarirsError> {
    let limit = BigUint::from(1u32) << big.size();
    match big.op() {
        AstOp::Add(args) => {
            let Some(pos) = args.iter().position(|a| a == small) else {
                return Ok(None);
            };
            let mut total_max = BigUint::ZERO;
            let (mut dmin, mut dmax) = (BigUint::ZERO, BigUint::ZERO);
            for (i, a) in args.iter().enumerate() {
                let k = known_bits(a, memo)?;
                total_max += k.umax();
                if i != pos {
                    dmin += k.umin();
                    dmax += k.umax();
                }
            }
            Ok((total_max < limit).then_some((dmin, dmax)))
        }
        AstOp::Mul(args) => match args.as_slice() {
            [x, k] | [k, x] if x == small => {
                let AstOp::BVV(k) = k.op() else {
                    return Ok(None);
                };
                let k = k.to_biguint();
                if k == BigUint::ZERO {
                    return Ok(None);
                }
                let kx = known_bits(x, memo)?;
                if kx.umax() * &k >= limit {
                    return Ok(None);
                }
                let k1 = k - 1u32;
                Ok(Some((kx.umin() * &k1, kx.umax() * k1)))
            }
            _ => Ok(None),
        },
        _ => Ok(None),
    }
}

/// The value of a bitvector comparison when the operands' known bits decide it: disjoint
/// unsigned or signed ranges, conflicting known bits (for Eq/Neq), or one operand equal to
/// the other plus a non-wrapping offset (the carry flag of an add that cannot overflow).
/// Tautologies against an extreme constant are not folded.
pub(super) fn decide<'c>(
    ast: &AstRef<'c>,
    memo: &mut KnownMemo,
) -> Result<Option<bool>, ClarirsError> {
    let (a, b) = match ast.op() {
        AstOp::Eq(a, b)
        | AstOp::Neq(a, b)
        | AstOp::ULT(a, b)
        | AstOp::ULE(a, b)
        | AstOp::UGT(a, b)
        | AstOp::UGE(a, b)
        | AstOp::SLT(a, b)
        | AstOp::SLE(a, b)
        | AstOp::SGT(a, b)
        | AstOp::SGE(a, b) => (a, b),
        _ => return Ok(None),
    };
    if !matches!(a.ast_type(), AstType::BitVec(_))
        || (matches!(a.op(), AstOp::BVV(_)) && matches!(b.op(), AstOp::BVV(_)))
    {
        return Ok(None);
    }
    let ka = known_bits(a, memo)?;
    let kb = known_bits(b, memo)?;
    let decided = match by_ranges(ast.op(), &ka, &kb)? {
        // A tautology against an extreme constant (0 <= x, x <= max, x >=s min) holds for any
        // x; callers inspect such bound constraints, so they stay.
        Some(_) if extreme_tautology(ast.op(), a, b, &ka, &kb)? => return Ok(None),
        Some(v) => Some(v),
        None => relational(ast, a, b, memo)?,
    };
    // Eq/Neq share the Eq analysis.
    Ok(match ast.op() {
        AstOp::Neq(..) => decided.map(|v| !v),
        _ => decided,
    })
}

/// Whether one operand is a constant and the comparison is decided for any other operand.
fn extreme_tautology<'c>(
    op: &AstOp<'c>,
    a: &AstRef<'c>,
    b: &AstRef<'c>,
    ka: &KnownBits,
    kb: &KnownBits,
) -> Result<bool, ClarirsError> {
    let free = |k: &KnownBits| KnownBits::unknown(k.width());
    Ok(match (a.op(), b.op()) {
        (AstOp::BVV(_), _) => by_ranges(op, ka, &free(kb))?.is_some(),
        (_, AstOp::BVV(_)) => by_ranges(op, &free(ka), kb)?.is_some(),
        _ => false,
    })
}

/// The comparison's value from the operands' ranges, Eq/Neq as Eq.
fn by_ranges(op: &AstOp<'_>, ka: &KnownBits, kb: &KnownBits) -> Result<Option<bool>, ClarirsError> {
    let (amin, amax, bmin, bmax) = (ka.umin(), ka.umax(), kb.umin(), kb.umax());
    Ok(match op {
        AstOp::Eq(..) | AstOp::Neq(..) => {
            let conflict = !((ka.known.clone() & kb.known.clone())?
                & (ka.value.clone() ^ kb.value.clone())?)?
            .is_zero();
            (conflict || amax < bmin || bmax < amin).then_some(false)
        }
        AstOp::ULT(..) if amax < bmin => Some(true),
        AstOp::ULT(..) if amin >= bmax => Some(false),
        AstOp::ULE(..) if amax <= bmin => Some(true),
        AstOp::ULE(..) if amin > bmax => Some(false),
        AstOp::UGT(..) if amin > bmax => Some(true),
        AstOp::UGT(..) if amax <= bmin => Some(false),
        AstOp::UGE(..) if amin >= bmax => Some(true),
        AstOp::UGE(..) if amax < bmin => Some(false),
        AstOp::SLT(..) | AstOp::SLE(..) | AstOp::SGT(..) | AstOp::SGE(..) => {
            let ((smin_a, smax_a), (smin_b, smax_b)) = (ka.smin_smax(), kb.smin_smax());
            match op {
                AstOp::SLT(..) if smax_a < smin_b => Some(true),
                AstOp::SLT(..) if smin_a >= smax_b => Some(false),
                AstOp::SLE(..) if smax_a <= smin_b => Some(true),
                AstOp::SLE(..) if smin_a > smax_b => Some(false),
                AstOp::SGT(..) if smin_a > smax_b => Some(true),
                AstOp::SGT(..) if smax_a <= smin_b => Some(false),
                AstOp::SGE(..) if smin_a >= smax_b => Some(true),
                AstOp::SGE(..) if smax_a < smin_b => Some(false),
                _ => None,
            }
        }
        _ => None,
    })
}

/// Unsigned comparisons and Eq/Neq of `x + d` against `x`, `d` not wrapping (see `offset`).
fn relational<'c>(
    ast: &AstRef<'c>,
    a: &AstRef<'c>,
    b: &AstRef<'c>,
    memo: &mut KnownMemo,
) -> Result<Option<bool>, ClarirsError> {
    if matches!(
        ast.op(),
        AstOp::SLT(..) | AstOp::SLE(..) | AstOp::SGT(..) | AstOp::SGE(..)
    ) {
        return Ok(None);
    }
    // The larger side minus the smaller ranges over [lo, hi] as integers; `a_big`: a is larger.
    let (a_big, (lo, hi)) = if let Some(d) = offset(a, b, memo)? {
        (true, d)
    } else if let Some(d) = offset(b, a, memo)? {
        (false, d)
    } else {
        return Ok(None);
    };
    // Whether d == 0: always (hi == 0), never (lo > 0), or unknown.
    let equal = if hi == BigUint::ZERO {
        Some(true)
    } else if lo > BigUint::ZERO {
        Some(false)
    } else {
        None
    };
    // (a < b, a <= b) with a = b + d or b = a + d
    let (lt, le) = if a_big {
        (Some(false), equal)
    } else {
        (equal.map(|v| !v), Some(true))
    };
    Ok(match ast.op() {
        AstOp::Eq(..) | AstOp::Neq(..) => equal,
        AstOp::ULT(..) => lt,
        AstOp::ULE(..) => le,
        AstOp::UGT(..) => le.map(|v| !v),
        AstOp::UGE(..) => lt.map(|v| !v),
        _ => None,
    })
}
