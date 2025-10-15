; add_password.asm — Add encrypted (login, password) entry
; Updated to use 8-byte db_key for XOR ECB encryption

global add_password

extern login_prompt
extern password_prompt
extern login
extern password
extern entry
extern db_key              ; CHANGED: use db_key instead of master_password
extern filename
extern success_msg
extern fail_msg
extern open_fail_msg
extern xor_encrypt_decrypt

section .text

add_password:
    push rbx
    push rbp

    ; --- LOGIN PROMPT ---
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel login_prompt]
    mov rdx, 13
    syscall

    ; --- READ LOGIN ---
    mov rax, 0
    mov rdi, 0
    lea rsi, [rel login]
    mov rdx, 32
    syscall
    mov r8, rax
    cmp r8, 0
    je .read_pw
    dec r8
    mov al, [login + r8]
    cmp al, 10
    jne .read_pw
    mov byte [login + r8], 0

.read_pw:
    ; --- PASSWORD PROMPT ---
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel password_prompt]
    mov rdx, 17
    syscall

    ; --- READ PASSWORD ---
    mov rax, 0
    mov rdi, 0
    lea rsi, [rel password]
    mov rdx, 32
    syscall
    mov r8, rax
    cmp r8, 0
    je .build_entry
    dec r8
    mov al, [password + r8]
    cmp al, 10
    jne .build_entry
    mov byte [password + r8], 0

.build_entry:
    ; --- BUILD 64-BYTE ENTRY (login[32] || password[32]) ---
    lea rdi, [rel entry]
    lea rsi, [rel login]
    mov rcx, 32
    cld
    rep movsb

    lea rdi, [rel entry + 32]
    lea rsi, [rel password]
    mov rcx, 32
    cld
    rep movsb

    ; --- XOR ENCRYPTION using db_key ---
    lea rsi, [rel db_key]         ; CHANGED: use 8-byte db_key
    lea rdi, [rel entry]
    call xor_encrypt_decrypt

    ; --- OPEN FILE (append mode) ---
    mov rax, 2
    lea rdi, [rel filename]
    mov rsi, 1089                 ; O_WRONLY|O_CREAT|O_APPEND
    mov rdx, 420                  ; 0644 permissions
    syscall
    cmp rax, -1
    je .open_error
    mov rbx, rax

    ; --- WRITE ENCRYPTED ENTRY ---
    mov rax, 1
    mov rdi, rbx
    lea rsi, [rel entry]
    mov rdx, 64
    syscall
    cmp rax, -1
    je .write_error

    ; --- CLOSE FILE ---
    mov rax, 3
    mov rdi, rbx
    syscall

    ; --- SUCCESS MESSAGE ---
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel success_msg]
    mov rdx, 39
    syscall
    jmp .done

.open_error:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel open_fail_msg]
    mov rdx, 21
    syscall
    jmp .done

.write_error:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel fail_msg]
    mov rdx, 22
    syscall
    cmp rbx, 0
    jle .done
    mov rax, 3
    mov rdi, rbx
    syscall

.done:
    pop rbp
    pop rbx
    ret