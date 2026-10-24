//! `SyscallResolver`: the filter in Rust; resolving a syscall needs symbolic execution, so it declines to the twin.

use pyo3::prelude::*;

use super::{Decision, Effects, JumpSite, Outcome, ResolveCx, Resolver};
use crate::vexlift::jumpkind_name;

pub struct SyscallResolver {
    /// `SyscallResolver._os_resolves_syscalls`
    pub os_resolves_syscalls: bool,
}

impl Resolver for SyscallResolver {
    fn kind(&self) -> &'static str {
        "SyscallResolver"
    }

    fn timeless(&self) -> bool {
        true
    }

    fn filter(
        &mut self,
        _py: Python<'_>,
        _cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
    ) -> PyResult<Decision<bool>> {
        Ok(Decision::Done(self.os_resolves_syscalls && jumpkind_name(j.jumpkind).starts_with("Ijk_Sys")))
    }

    fn resolve(
        &mut self,
        _py: Python<'_>,
        _cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        _j: &JumpSite,
        _fx: &mut Effects,
    ) -> PyResult<Decision<Outcome>> {
        Ok(Decision::Python("symbolic"))
    }
}
