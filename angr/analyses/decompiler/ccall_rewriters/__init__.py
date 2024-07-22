from .amd64_ccalls import AMD64CCallRewriter
from .arm_ccalls import ARMCCallRewriter


CCALL_REWRITERS = {
    "AMD64": AMD64CCallRewriter,
    "ARMEL": ARMCCallRewriter,
}
