; i386 functions that spill an FP value to a stack slot then overwrite it
; with fisttp (integer).  The decompiler must NOT unify the FP and int
; variables at the same stack offset.
;
; int slot_reuse_dbl(double x)   -- double -> fisttp -> return int
; int slot_reuse_flt(float x)    -- float  -> fisttp -> return int

bits 32

section .text
global slot_reuse_dbl
global slot_reuse_flt

slot_reuse_dbl:
    push    ebp
    mov     ebp, esp
    sub     esp, 16
    fld     qword [ebp+8]       ; load double param from stack
    fstp    qword [ebp-8]       ; spill to local slot
    fld     qword [ebp-8]       ; reload
    fisttp  dword [ebp-8]       ; overwrite slot with truncated int
    mov     eax, [ebp-8]        ; return the int
    leave
    ret

slot_reuse_flt:
    push    ebp
    mov     ebp, esp
    sub     esp, 16
    fld     dword [ebp+8]       ; load float param from stack
    fstp    dword [ebp-4]       ; spill to local slot
    fld     dword [ebp-4]       ; reload
    fisttp  dword [ebp-4]       ; overwrite slot with truncated int
    mov     eax, [ebp-4]        ; return the int
    leave
    ret
