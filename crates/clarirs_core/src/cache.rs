use ahash::HashMap;
use std::{
    hash::Hash,
    sync::{Arc, RwLock, Weak},
};

use crate::prelude::*;

/// A trait for caching values based on a key. In the context of clarirs, this
/// is used to cache ASTs, as well as the results of various algorithms.
///
/// Implementations provide `get` and `insert`; `get_or_insert` is derived from
/// them, and need only be overridden when that default is insufficient.
pub trait Cache<K, V> {
    /// Probe the cache without computing a value on miss.
    fn get(&self, key: &K) -> Option<V>;

    fn insert(&self, key: K, value: &V);

    fn drop(&self, key: K);

    fn get_or_insert<E>(&self, key: K, value_cv: impl FnOnce() -> Result<V, E>) -> Result<V, E> {
        if let Some(value) = self.get(&key) {
            return Ok(value);
        }
        let value = value_cv()?;
        self.insert(key, &value);
        Ok(value)
    }
}

impl<K, V> Cache<K, V> for () {
    fn get(&self, _key: &K) -> Option<V> {
        None
    }

    fn insert(&self, _key: K, _value: &V) {
        // No-op
    }

    fn drop(&self, _key: K) {
        // No-op
    }
}

/// A generic cache implementation that uses a `HashMap` to store key-value pairs.
#[derive(Debug)]
pub struct GenericCache<K, V>(RwLock<HashMap<K, V>>);

impl<K, V> Default for GenericCache<K, V> {
    fn default() -> Self {
        Self(RwLock::new(HashMap::default()))
    }
}

impl<K: Hash + Eq, V: Clone> Cache<K, V> for GenericCache<K, V> {
    fn get(&self, key: &K) -> Option<V> {
        self.0.read().unwrap().get(key).cloned()
    }

    fn insert(&self, key: K, value: &V) {
        self.0.write().unwrap().insert(key, value.clone());
    }

    fn drop(&self, key: K) {
        self.0.write().unwrap().remove(&key);
    }
}

/// A special cache for when the result type is an AST. Unlike the generic cache,
/// this cache stores weak references to the AST nodes; the value is a
/// `Weak<AstNode>`.
#[derive(Debug, Default)]
pub struct AstCache<'c>(RwLock<HashMap<u64, Weak<AstNode<'c>>>>);

impl<'c> Cache<u64, AstRef<'c>> for AstCache<'c> {
    fn get(&self, key: &u64) -> Option<AstRef<'c>> {
        self.0.read().unwrap().get(key).and_then(Weak::upgrade)
    }

    fn insert(&self, key: u64, value: &AstRef<'c>) {
        let mut inner = self.0.write().unwrap();

        // A different live value under this hash means two distinct ASTs collide.
        #[cfg(feature = "panic-on-hash-collision")]
        if let Some(existing) = inner.get(&key).and_then(Weak::upgrade)
            && existing != *value
        {
            panic!("Hash collision detected! Hash: {key}, Existing: {existing:?}, New: {value:?}");
        }

        inner.insert(key, Arc::downgrade(value));
    }

    fn drop(&self, key: u64) {
        self.0.write().unwrap().remove(&key);
    }

    // Collision detection must recompute and compare on every call, even a cache
    // hit, which the derived get-then-insert cannot express.
    #[cfg(feature = "panic-on-hash-collision")]
    fn get_or_insert<E>(
        &self,
        key: u64,
        value_cv: impl FnOnce() -> Result<AstRef<'c>, E>,
    ) -> Result<AstRef<'c>, E> {
        let arc = value_cv()?;
        self.insert(key, &arc);
        Ok(arc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(feature = "panic-on-hash-collision"))]
    fn test_ast_cache_basic() -> Result<(), ClarirsError> {
        let ctx = crate::context::Context::new();
        let cache = AstCache::default();

        // Create a simple AST
        let ast1 = ctx.bvv(BitVec::from((42, 64)))?;
        let hash1 = 12345u64; // Arbitrary hash for testing

        // Insert into cache
        let result1 = cache.get_or_insert::<ClarirsError>(hash1, || Ok(ast1.clone()))?;

        // Verify we can retrieve it without recomputing
        let result2 = cache.get_or_insert::<ClarirsError>(hash1, || {
            panic!("Should not compute new value when cached")
        })?;
        assert_eq!(result1, result2);
        Ok(())
    }

    #[test]
    #[cfg(feature = "panic-on-hash-collision")]
    fn test_ast_cache_basic_collision_mode() -> Result<(), ClarirsError> {
        let ctx = crate::context::Context::new();
        let cache = AstCache::default();

        // Create a simple AST
        let ast1 = ctx.bvv(BitVec::from((42, 64)))?;
        let hash1 = 12345u64; // Arbitrary hash for testing

        // Insert into cache
        let result1 = cache.get_or_insert::<ClarirsError>(hash1, || Ok(ast1.clone()))?;

        // In collision mode, it will always recompute, so provide a valid computation
        let ast2 = ctx.bvv(BitVec::from((42, 64)))?;
        let result2 = cache.get_or_insert::<ClarirsError>(hash1, || Ok(ast2.clone()))?;
        assert_eq!(result1, result2);
        Ok(())
    }

    #[test]
    fn test_ast_cache_different_hashes() -> Result<(), ClarirsError> {
        let ctx = crate::context::Context::new();
        let cache = AstCache::default();

        let ast1 = ctx.bvv(BitVec::from((42, 64)))?;
        let ast2 = ctx.bvv(BitVec::from((99, 64)))?;

        let result1 = cache.get_or_insert::<ClarirsError>(1, || Ok(ast1.clone()))?;
        let result2 = cache.get_or_insert::<ClarirsError>(2, || Ok(ast2.clone()))?;

        // Different hashes should cache different values
        assert_ne!(result1, result2);
        Ok(())
    }

    #[test]
    #[cfg(not(feature = "panic-on-hash-collision"))]
    fn test_ast_cache_weak_reference_cleanup() -> Result<(), ClarirsError> {
        let ctx = crate::context::Context::new();
        let cache = AstCache::default();
        let hash = 999u64;

        {
            // Create and cache an AST
            let ast = ctx.bvv(BitVec::from((42, 64)))?;
            let _result = cache.get_or_insert::<ClarirsError>(hash, || Ok(ast.clone()))?;
            // ast and _result go out of scope here
        }

        // The weak reference should be expired now, so this should compute a new value
        let mut computed = false;
        let ast2 = ctx.bvv(BitVec::from((42, 64)))?;
        let _result = cache.get_or_insert::<ClarirsError>(hash, || {
            computed = true;
            Ok(ast2.clone())
        })?;

        assert!(
            computed,
            "Should have computed new value after weak ref expired"
        );
        Ok(())
    }

    // Test for collision detection mode
    #[test]
    #[cfg(feature = "panic-on-hash-collision")]
    #[should_panic(expected = "Hash collision detected")]
    fn test_hash_collision_detection_panics() {
        let ctx = crate::context::Context::new();
        let cache = AstCache::default();
        let hash = 777u64;

        // Insert first value
        let ast1 = ctx.bvv(BitVec::from((42, 64))).unwrap();
        let _ = cache
            .get_or_insert::<ClarirsError>(hash, || Ok(ast1.clone()))
            .unwrap();

        // Try to insert different value with same hash - should panic
        let ast2 = ctx.bvv(BitVec::from((99, 64))).unwrap();
        let _ = cache
            .get_or_insert::<ClarirsError>(hash, || Ok(ast2.clone()))
            .unwrap();
    }

    #[test]
    #[cfg(feature = "panic-on-hash-collision")]
    fn test_hash_collision_same_value_ok() -> Result<(), ClarirsError> {
        let ctx = crate::context::Context::new();
        let cache = AstCache::default();
        let hash = 888u64;

        // Insert first value
        let ast1 = ctx.bvv(BitVec::from((42, 64)))?;
        let result1 = cache.get_or_insert::<ClarirsError>(hash, || Ok(ast1.clone()))?;

        // Insert same value with same hash - should be fine
        let ast2 = ctx.bvv(BitVec::from((42, 64)))?;
        let result2 = cache.get_or_insert::<ClarirsError>(hash, || Ok(ast2.clone()))?;

        assert_eq!(result1, result2);
        Ok(())
    }

    #[test]
    #[cfg(feature = "panic-on-hash-collision")]
    fn test_always_computes_in_collision_mode() {
        let ctx = crate::context::Context::new();
        let cache = AstCache::default();
        let hash = 999u64;

        // Insert first value
        let ast1 = ctx.bvv(BitVec::from((42, 64))).unwrap();
        let _ = cache
            .get_or_insert::<ClarirsError>(hash, || Ok(ast1.clone()))
            .unwrap();

        // This should always compute, even though the value is in cache
        let mut computed = false;
        let ast2 = ctx.bvv(BitVec::from((42, 64))).unwrap();
        let _ = cache
            .get_or_insert::<ClarirsError>(hash, || {
                computed = true;
                Ok(ast2.clone())
            })
            .unwrap();

        assert!(
            computed,
            "Should always compute in collision detection mode"
        );
    }

    #[test]
    fn test_generic_cache_basic() {
        let cache = GenericCache::<u64, String>::default();

        let result1 = cache
            .get_or_insert::<ClarirsError>(1, || Ok("hello".to_string()))
            .unwrap();
        let result2 = cache
            .get_or_insert::<ClarirsError>(1, || panic!("Should not compute when cached"))
            .unwrap();

        assert_eq!(result1, result2);
    }
}
