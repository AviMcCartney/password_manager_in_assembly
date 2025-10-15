; common_data.asm
; Données partagées + routine xor_encrypt_decrypt (répète la clé master)
; API: xor_encrypt_decrypt(rdi = addr buffer(64), rsi = addr key ASCIIZ)

global login_prompt
global password_prompt
global master_prompt
global choice_prompt
global newline
global success_msg
global fail_msg
global open_fail_msg
global filename

global master_password
global login
global password
global choice
global entry
global buffer
global encrypted_entry

global xor_encrypt_decrypt

section .data
login_prompt     db "Enter login: ", 0
password_prompt  db "Enter password: ", 0
master_prompt    db "Enter master password: ", 0
choice_prompt    db "Choose an option (0 to add, 1 to display): ", 0
newline          db 0xA, 0

success_msg      db "Login and password stored successfully!", 0
fail_msg         db "Error writing to file!", 0
open_fail_msg    db "Error opening file!", 0
filename         db 'databs.txt', 0

section .bss
master_password  resb 32
login            resb 32
password         resb 32
choice           resb 1
entry            resb 64
buffer           resb 256
encrypted_entry  resb 64

section .text
; ------------------------------------------------------------
; xor_encrypt_decrypt: répète la clé (ASCIIZ) sur 64 octets
; rdi = addr buffer (64 bytes)
; rsi = addr key (ASCIIZ), keylen <= 32
; inplace XOR
; ------------------------------------------------------------
xor_encrypt_decrypt:
    push rbx
    push rcx
    push rdx
    push r8
    push r9

    xor r8, r8
.xlen_loop:
    mov al, [rsi + r8]
    cmp al, 0
    je .xlen_done
    inc r8
    cmp r8, 32
    jb .xlen_loop
.xlen_done:
    cmp r8, 0
    jne .have_key
    ; keylen == 0 -> nothing
    jmp .xret

.have_key:
    xor rcx, rcx           ; index 0..63
.xloop:
    cmp rcx, 64
    je .xret
    mov rdx, rcx
.mod_loop:
    cmp rdx, r8
    jb .mod_done
    sub rdx, r8
    jmp .mod_loop
.mod_done:
    mov al, [rdi + rcx]
    mov bl, [rsi + rdx]
    xor al, bl
    mov [rdi + rcx], al
    inc rcx
    jmp .xloop

.xret:
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret
