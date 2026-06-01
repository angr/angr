; amd64 functions that spill an FP value to a stack slot then overwrite it
; with fisttp (integer).  The decompiler must NOT unify the FP and int
; variables at the same stack offset.
;
; int slot_reuse_dbl(double x)   -- double -> fisttp -> return int
; int slot_reuse_flt(float x)    -- float  -> fisttp -> return int

bits 64

section .text
global slot_reuse_dbl
global slot_reuse_flt

slot_reuse_dbl:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 16
    movsd   [rbp-16], xmm0     ; spill double param
    fld     qword [rbp-16]      ; load as x87 double
    fisttp  dword [rbp-16]      ; overwrite slot with truncated int
    mov     eax, [rbp-16]       ; return the int
    leave
    ret

slot_reuse_flt:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 16
    movss   [rbp-16], xmm0     ; spill float param
    fld     dword [rbp-16]      ; load as x87 float
    fisttp  dword [rbp-16]      ; overwrite slot with truncated int
    mov     eax, [rbp-16]       ; return the int
    leave
    ret
