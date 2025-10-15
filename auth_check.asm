; auth_check.asm — Database Password Authentication
; Updated to store first 8 bytes of password as XOR key
; Contrat:
;   authenticate() -> RAX = 0 if success, 1 if failure
;   Stores first 8 bytes of password in db_key for encryption

global authenticate
extern master_prompt
extern master_password
extern db_key              ; NEW: 8-byte key for XOR ECB

section .data
    ok_msg      db "Password accepted", 10
    ok_len      equ $-ok_msg

    wrong_msg   db "Invalid password (must be 8+ characters)", 10
    wrong_len   equ $-wrong_msg

    final_msg   db "Too many attempts. Exiting.", 10
    final_len   equ $-final_msg

    MAX_KEYLEN  equ 32
    MIN_KEYLEN  equ 8             ; Minimum 8 characters required
    PROMPT_LEN  equ 23

section .text

authenticate:
    push r12
    push rbx
    push rbp

    mov  r12, 3                   ; 3 attempts

.try_loop:
    ; Prompt for database password
    mov  rax, 1
    mov  rdi, 1
    lea  rsi, [rel master_prompt]
    mov  rdx, PROMPT_LEN
    syscall

    ; Read password
    mov  rax, 0
    mov  rdi, 0
    lea  rsi, [rel master_password]
    mov  rdx, MAX_KEYLEN
    syscall
    cmp  rax, 0
    jle  .fail_all

    ; Remove newline/carriage return
    mov  r8, rax
    dec  r8
    js   .calc_len

    mov  al, [master_password + r8]
    cmp  al, 10                   ; '\n'
    jne  .maybe_cr
    mov  byte [master_password + r8], 0
    cmp  r8, 0
    je   .calc_len
    mov  al, [master_password + r8 - 1]
    cmp  al, 13                   ; '\r'
    jne  .calc_len
    mov  byte [master_password + r8 - 1], 0
    jmp  .calc_len

.maybe_cr:
    mov  al, [master_password + r8]
    cmp  al, 13
    jne  .calc_len
    mov  byte [master_password + r8], 0

.calc_len:
    ; Calculate actual length
    xor  rdx, rdx
.len_loop:
    cmp  rdx, MAX_KEYLEN
    jae  .len_done
    mov  al, [master_password + rdx]
    cmp  al, 0
    je   .len_done
    inc  rdx
    jmp  .len_loop
.len_done:

    ; Check minimum length (8 bytes required)
    cmp  rdx, MIN_KEYLEN
    jge  .valid_length

    ; Password too short
    mov  rax, 1
    mov  rdi, 1
    lea  rsi, [rel wrong_msg]
    mov  rdx, wrong_len
    syscall

    dec  r12
    cmp  r12, 0
    jg   .try_loop
    jmp  .too_many_attempts

.valid_length:
    ; Extract first 8 bytes as encryption key
    lea  rsi, [rel master_password]
    lea  rdi, [rel db_key]
    mov  rcx, 8
    cld
    rep  movsb

    ; Success message
    mov  rax, 1
    mov  rdi, 1
    lea  rsi, [rel ok_msg]
    mov  rdx, ok_len
    syscall

    xor  rax, rax                 ; Return 0 (success)
    pop  rbp
    pop rbx
    pop  r12
    ret

.too_many_attempts:
    mov  rax, 1
    mov  rdi, 1
    lea  rsi, [rel final_msg]
    mov  rdx, final_len
    syscall

.fail_all:
    mov  rax, 1                   ; Return 1 (failure)
    pop  rbp
    pop  rbx
    pop  r12
    ret