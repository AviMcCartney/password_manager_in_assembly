; add_password.asm
global add_password

extern login_prompt
extern password_prompt
extern login
extern password
extern entry
extern master_password
extern filename
extern success_msg
extern fail_msg
extern open_fail_msg
extern xor_encrypt_decrypt

section .text

add_password:
    push rbx
    push rbp

    ; --- ZERO login & password buffers (32 bytes each) ---
    lea rdi, [rel login]
    mov rcx, 32
    xor al, al
    rep stosb

    lea rdi, [rel password]
    mov rcx, 32
    xor al, al
    rep stosb

    ; --- Prompt + read login ---
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel login_prompt]
    mov rdx, 13
    syscall

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
    ; --- Prompt + read password ---
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel password_prompt]
    mov rdx, 17
    syscall

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
    ; copy login -> entry[0..31]
    lea rdi, [rel entry]
    lea rsi, [rel login]
    mov rcx, 32
    cld
    rep movsb

    ; copy password -> entry[32..63]
    lea rdi, [rel entry + 32]
    lea rsi, [rel password]
    mov rcx, 32
    cld
    rep movsb

    ; Encrypt using the canonical routine (first 8 bytes of master_password)
    lea rdi, [rel entry]
    lea rsi, [rel master_password]
    call xor_encrypt_decrypt

    ; open file (append)
    mov rax, 2
    lea rdi, [rel filename]
    mov rsi, 1089
    mov rdx, 420
    syscall
    cmp rax, -1
    je .open_error
    mov rbx, rax

    ; write 64 bytes
    mov rax, 1
    mov rdi, rbx
    lea rsi, [rel entry]
    mov rdx, 64
    syscall
    cmp rax, -1
    je .write_error

    ; close fd
    mov rax, 3
    mov rdi, rbx
    syscall

    ; success
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
