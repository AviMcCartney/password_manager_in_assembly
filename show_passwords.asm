; =====================================================================
; show_passwords.asm — Display decrypted (login, password) pairs
; Updated to use 8-byte db_key for XOR ECB decryption
; =====================================================================

global show_passwords
extern filename
extern buffer
extern db_key              ; CHANGED: use db_key instead of master_password
extern newline
extern xor_encrypt_decrypt
extern open_fail_msg

section .data
space db ' '

section .text

show_passwords:
    push rbx
    push rbp

    ; --- OPEN FILE (read-only) ---
    mov rax, 2
    lea rdi, [rel filename]
    mov rsi, 0                    ; O_RDONLY
    syscall
    cmp rax, -1
    je  .open_err
    mov rbx, rax                  ; fd in RBX

.read_loop:
    ; --- READ 64-BYTE BLOCK ---
    mov rax, 0
    mov rdi, rbx
    lea rsi, [rel buffer]
    mov rdx, 64
    syscall
    cmp rax, 0
    je  .close_and_done           ; EOF
    cmp rax, 64
    jne .close_and_done           ; Partial block - stop

    ; --- XOR DECRYPTION using db_key ---
    lea rsi, [rel db_key]         ; CHANGED: use 8-byte db_key
    lea rdi, [rel buffer]
    call xor_encrypt_decrypt

    ; --- PRINT LOGIN (buffer[0..31]) ---
    lea rsi, [rel buffer]
    xor rcx, rcx
.find_login:
    cmp rcx, 32
    je  .print_login
    mov al, [buffer + rcx]
    cmp al, 0
    je  .print_login
    inc rcx
    jmp .find_login

.print_login:
    cmp rcx, 0
    je  .skip_login_write
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel buffer]
    mov rdx, rcx
    syscall
.skip_login_write:

    ; --- PRINT SPACE ---
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel space]
    mov rdx, 1
    syscall

    ; --- PRINT PASSWORD (buffer[32..63]) ---
    lea rsi, [rel buffer + 32]
    xor rcx, rcx
.find_pass:
    cmp rcx, 32
    je  .print_pass
    mov al, [buffer + 32 + rcx]
    cmp al, 0
    je  .print_pass
    inc rcx
    jmp .find_pass

.print_pass:
    cmp rcx, 0
    je  .skip_pass_write
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel buffer + 32]
    mov rdx, rcx
    syscall
.skip_pass_write:

    ; --- PRINT NEWLINE ---
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel newline]
    mov rdx, 1
    syscall

    jmp .read_loop

.close_and_done:
    mov rax, 3
    mov rdi, rbx
    syscall
    jmp .finish

.open_err:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel open_fail_msg]
    mov rdx, 21
    syscall

.finish:
    pop rbp
    pop rbx
    ret