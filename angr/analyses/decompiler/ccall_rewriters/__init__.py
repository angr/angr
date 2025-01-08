from __future__ import annotations
from .amd64_ccalls import AMD64CCallRewriter
from .x86_ccalls import X86CCallRewriter


CCALL_REWRITERS = {
    "X86": X86CCallRewriter,
    "AMD64": AMD64CCallRewriter,
}
