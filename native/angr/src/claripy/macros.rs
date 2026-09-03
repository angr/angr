#[macro_export]
macro_rules! add_pyfunctions {
    ($m:ident, $($fn_name:path),*,) => {
        $(
            $m.add_function(wrap_pyfunction!($fn_name, $m)?)?;
        )*
    };
}

/// The per-class wrapper plumbing: a weakref cache keyed by AST hash, `new`/`new_with_name`
/// reusing a live wrapper before building one with `$init(base, inner)`, and `Drop` eviction.
#[macro_export]
macro_rules! ast_wrapper {
    ($ty:ident, $cache:ident, $init:expr) => {
        static $cache: ::std::sync::LazyLock<
            ::dashmap::DashMap<u64, Py<::pyo3::types::PyWeakrefReference>>,
        > = ::std::sync::LazyLock::new(::dashmap::DashMap::new);

        impl $ty {
            pub fn new<'py>(
                py: Python<'py>,
                inner: &AstRef<'static>,
            ) -> Result<Bound<'py, $ty>, ClaripyError> {
                Self::new_with_name(py, inner, None)
            }

            /// Wrap an AST without simplifying it, keeping its annotation set exactly as
            /// given.
            pub fn new_with_name<'py>(
                py: Python<'py>,
                inner: &AstRef<'static>,
                name: Option<String>,
            ) -> Result<Bound<'py, $ty>, ClaripyError> {
                if let Some(cache_hit) = $cache.get(&inner.hash()).and_then(|cache_hit| {
                    cache_hit
                        .bind(py)
                        .upgrade_as::<$ty>()
                        .expect(concat!(stringify!($ty), " cache poisoned"))
                }) {
                    Ok(cache_hit)
                } else {
                    let this = Bound::new(
                        py,
                        $init(Base::new_with_name(py, inner, name)?, inner.clone()),
                    )?;
                    let weakref = ::pyo3::types::PyWeakrefReference::new(&this)?;
                    $cache.insert(inner.hash(), weakref.unbind());

                    Ok(this)
                }
            }
        }

        impl Drop for $ty {
            fn drop(&mut self) {
                // Evict this wrapper's cache entry so dead hashes don't accumulate.
                // Our own weakref is already cleared by the time Drop runs, so a dead
                // upgrade means the entry is stale; a live upgrade means the entry was
                // re-populated with a new wrapper and must stay.
                Python::attach(|py| {
                    $cache.remove_if(&self.inner.hash(), |_, weakref| {
                        weakref.bind(py).upgrade().is_none()
                    });
                });
            }
        }
    };
}
