; i386 function with conditional FP stack usage creating an ftop conflict.
; Exercises IRegReplacer safety net and ftop ambiguity handling.
;
; double ftop_conflict(int flag, double val)
;   if flag > 0: return val + 1.0
;   else:        return 0.0
;
; The two paths leave different values on the x87 stack but both
; converge at the same return point.  The ftop at the merge point
; is constant (-1 from both paths) but intermediate x87 accesses
; may create IRegisters that need resolution.
;
; Assemble: nasm -f elf32 -o ftop_conflict_i386.o ftop_conflict_i386.s

    section .text
    global ftop_conflict

ftop_conflict:
    push ebp
    mov ebp, esp
    sub esp, 8
    cmp dword [ebp+8], 0
    jle .zero_path

.add_path:
    fld qword [ebp+12]     ; ST0 = val
    fld1                    ; ST0 = 1.0, ST1 = val
    faddp st1, st0          ; ST0 = val + 1.0
    jmp .merge

.zero_path:
    fldz                    ; ST0 = 0.0

.merge:
    fstp qword [ebp-8]     ; pop result to stack
    fld qword [ebp-8]      ; reload (to normalize x87 state)
    leave
    ret
