use std::hash::{BuildHasher, Hasher};

/// This is a shim that allows us to use a precomputed hash value in place of a real hasher.
/// It expects the hash implementation of the type to only set a u64 value.
#[derive(Default, Clone)]
pub struct PrecomputedHasher(u64);

impl PrecomputedHasher {
    pub fn new() -> Self {
        Self(0)
    }
}

impl Hasher for PrecomputedHasher {
    fn write(&mut self, _: &[u8]) {}

    fn write_u64(&mut self, i: u64) {
        self.0 = i;
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

#[derive(Default, Copy, Clone)]
pub struct PrecomputedHasherBuilder;

impl BuildHasher for PrecomputedHasherBuilder {
    type Hasher = PrecomputedHasher;

    fn build_hasher(&self) -> Self::Hasher {
        PrecomputedHasher::new()
    }
}
