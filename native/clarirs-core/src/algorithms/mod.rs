pub mod canonicalize;
pub mod collect_vars;
pub mod excavate_ite;
pub mod find_variable;
pub mod reconstruct;
pub mod replace;
pub mod simplify;
pub mod walk;

pub use canonicalize::{canonicalize, structurally_match};
pub use walk::walk;
