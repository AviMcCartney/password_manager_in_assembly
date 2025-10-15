; ====================================================================
; common_data.asm — Shared data + XOR ECB encryption
; Updated to use 8-byte key for XOR ECB cipher
; ====================================================================

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
global master_password_const    ; <-- exporte la constante du mot de passe maître
global login
global password
global choice
global entry
global buffer
global encrypted_entry
global db_key

global xor_encrypt_decrypt


section .data
; -------------------- String constants --------------------
login_prompt     db "Enter login: ", 0
password_prompt  db "Enter password: ", 0
master_prompt    db "Enter master password: ", 0
choice_prompt    db "Choose an option (0 to add, 1 to display): ", 0
newline          db 0xA, 0

success_msg      db "Login and password stored successfully!", 0
fail_msg         db "Error writing to file!", 0
open_fail_msg    db "Error opening file!", 0
filename         db 'databs.txt', 0

; -------------------- Master password constant (set your real master here) -----------
; IMPORTANT: replace "supersecret" with your desired master password (NUL-terminated)
master_password_const db "x0r1nG_4_StR1nG_w1Th_4_k3y", 0

section .bss
; -------------------- Mutable buffers --------------------
master_password  resb 32     ; Full master password
db_key           resb 8      ; First 8 bytes used for XOR ECB
login            resb 32
password         resb 32
choice           resb 1
entry            resb 64
buffer           resb 256
encrypted_entry  resb 64

section .text
; --------------------------------------------------------------------
; xor_encrypt_decrypt - XOR ECB cipher with 8-byte key
;   Applies XOR with repeating 8-byte key (ECB mode)
;   Inputs:
;     RDI = address of 64-byte buffer (modified in-place)
;     RSI = address of 8-byte key (db_key)
;   Outputs:
;     Buffer XORed in-place
;   Algorithm:
;     For i = 0 to 63:
;       buffer[i] = buffer[i] XOR key[i mod 8]
; --------------------------------------------------------------------
xor_encrypt_decrypt:
    push rbx
    push rcx
    push rdx
    push r8

    ; RDI = buffer (64 bytes)
    ; RSI = key (8 bytes)
    
    xor rcx, rcx                  ; rcx = index (0..63)

.xor_loop:
    cmp rcx, 64
    je  .done

    ; Calculate key index: rdx = rcx mod 8
    mov rdx, rcx
    and rdx, 7                    ; Fast modulo 8 using AND

    ; Load buffer[i] and key[i mod 8], XOR them
    mov al, [rdi + rcx]           ; al = buffer[i]
    mov bl, [rsi + rdx]           ; bl = key[i mod 8]
    xor al, bl                    ; al = buffer[i] XOR key[i mod 8]
    mov [rdi + rcx], al           ; store result

    inc rcx
    jmp .xor_loop

.done:
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret