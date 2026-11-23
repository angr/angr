//! A 256-bit unsigned integer: the Python ints of the constant propagations (VEX values are at most V256 wide).

use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: U256 = U256([0; 4]);

    pub fn from_u64(v: u64) -> Self {
        U256([v, 0, 0, 0])
    }

    /// Little-endian bytes, at most 32.
    pub fn from_le_bytes(b: &[u8]) -> Option<Self> {
        if b.len() > 32 {
            return None;
        }
        let mut w = [0u64; 4];
        for (i, &x) in b.iter().enumerate() {
            w[i / 8] |= (x as u64) << ((i % 8) * 8);
        }
        Some(U256(w))
    }

    pub fn to_u64(self) -> Option<u64> {
        (self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0).then_some(self.0[0])
    }

    pub fn low_u64(self) -> u64 {
        self.0[0]
    }

    /// `self & ((1 << bits) - 1)`.
    pub fn masked(self, bits: u32) -> Self {
        let mut w = self.0;
        for (i, x) in w.iter_mut().enumerate() {
            let lo = i as u32 * 64;
            if bits <= lo {
                *x = 0;
            } else if bits < lo + 64 {
                *x &= (1u64 << (bits - lo)) - 1;
            }
        }
        U256(w)
    }

    pub fn wrapping_add(self, o: Self) -> Self {
        let mut w = [0u64; 4];
        let mut carry = false;
        for (i, x) in w.iter_mut().enumerate() {
            let (s1, c1) = self.0[i].overflowing_add(o.0[i]);
            let (s2, c2) = s1.overflowing_add(carry as u64);
            *x = s2;
            carry = c1 || c2;
        }
        U256(w)
    }

    pub fn wrapping_sub(self, o: Self) -> Self {
        let mut w = [0u64; 4];
        let mut borrow = false;
        for (i, x) in w.iter_mut().enumerate() {
            let (d1, b1) = self.0[i].overflowing_sub(o.0[i]);
            let (d2, b2) = d1.overflowing_sub(borrow as u64);
            *x = d2;
            borrow = b1 || b2;
        }
        U256(w)
    }

    pub fn and(self, o: Self) -> Self {
        U256([
            self.0[0] & o.0[0],
            self.0[1] & o.0[1],
            self.0[2] & o.0[2],
            self.0[3] & o.0[3],
        ])
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 4]
    }

    pub fn to_le_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.0[i].to_le_bytes());
        }
        out
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_u64() {
            Some(v) => write!(f, "{v:#x}"),
            None => write!(
                f,
                "0x{:x}{:016x}{:016x}{:016x}",
                self.0[3], self.0[2], self.0[1], self.0[0]
            ),
        }
    }
}

impl<'py> pyo3::IntoPyObject<'py> for U256 {
    type Target = pyo3::PyAny;
    type Output = pyo3::Bound<'py, pyo3::PyAny>;
    type Error = pyo3::PyErr;

    fn into_pyobject(self, py: pyo3::Python<'py>) -> Result<Self::Output, Self::Error> {
        use pyo3::prelude::*;
        if let Some(v) = self.to_u64() {
            return Ok(v.into_pyobject(py)?.into_any());
        }
        py.get_type::<pyo3::types::PyInt>().call_method1(
            "from_bytes",
            (pyo3::types::PyBytes::new(py, &self.to_le_bytes()), "little"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arith() {
        let a = U256([u64::MAX, u64::MAX, 0, 0]);
        let b = U256::from_u64(1);
        assert_eq!(a.wrapping_add(b), U256([0, 0, 1, 0]));
        assert_eq!(
            U256::ZERO.wrapping_sub(b).masked(64),
            U256::from_u64(u64::MAX)
        );
        assert_eq!(a.masked(70), U256([u64::MAX, 63, 0, 0]));
        assert_eq!(a.masked(256), a);
    }
}
