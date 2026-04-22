; i386 function with 4 double params on the stack.
; Exercises double arg pair merging in CC analysis.
;
; double four_doubles(double a, double b, double c, double d)
;   returns a*b + c*d
;
; Assemble: nasm -f elf32 -o four_doubles_i386.o four_doubles_i386.s

    section .text
    global four_doubles

four_doubles:
    push ebp
    mov ebp, esp
    fld qword [ebp+8]      ; ST0 = a
    fmul qword [ebp+16]    ; ST0 = a*b
    fld qword [ebp+24]     ; ST0 = c, ST1 = a*b
    fmul qword [ebp+32]    ; ST0 = c*d, ST1 = a*b
    faddp st1, st0          ; ST0 = a*b + c*d
    leave
    ret
