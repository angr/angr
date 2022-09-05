from .amd64_ccalls import AMD64CCallRewriter


CCALL_REWRITERS = {
    'AMD64': AMD64CCallRewriter,
}
