#[macro_export]
macro_rules! add_pyfunctions {
    ($m:ident, $($fn_name:path),*,) => {
        $(
            $m.add_function(wrap_pyfunction!($fn_name, $m)?)?;
        )*
    };
}
