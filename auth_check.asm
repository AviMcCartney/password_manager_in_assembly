; auth_check.asm
; Module d'authentification : lit le master password DIRECTEMENT dans
; common_data.master_password, vérifie via XOR (key/needed) et gère 3 essais.
;
; API:
;   authenticate() -> rax = 0 si OK, 1 si échec
;
; Dépendances (externes):
;   master_prompt (optionnel, défini dans common_data)
;   master_password (buffer partagé dans common_data)
; Le module contient sa propre sortie messages.

global authenticate
extern master_prompt
extern master_password

section .data
    ok_msg    db "Mot de passe correct", 10
    ok_len    equ $-ok_msg

    wrong_msg db "Mot de passe incorrect", 10
    wrong_len equ $-wrong_msg

    final_msg db "Trop d'essais. Fin.", 10
    final_len equ $-final_msg

    ; clé / needed (extraits de ton crackme)
    key:    db 215,12,59,49,231,63,30,91,51,198,129,13,90,170,150,2,184,181,183,243,186,54,10,125,140,90,0
    needed: db 175,60,73,0,137,120,65,111,108,149,245,95,107,196,209,93,207,132,227,155,229,2,85,22,191,35

    CHECK_LEN equ 26
    MAX_KEYLEN equ 32

section .text

; authenticate: effectue prompt/read directement dans common_data.master_password,
; supprime CR/LF, exige longueur CHECK_LEN, effectue vérif XOR (master ^ key == needed)
; rax = 0 -> succès, rax = 1 -> échec
authenticate:
    push r12            ; sauvegarde r12 (callee-saved)
    push rbx
    push rbp

    mov r12, 3          ; tentatives restantes (r12 est préservé par les syscalls)

.try_loop:
    ; afficher prompt si désiré (master_prompt est dans common_data)
    ; si tu n'as pas master_prompt défini, tu peux commenter ce bloc.
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel master_prompt]
    mov rdx, 23         ; taille approximative du prompt (ajuste si tu veux)
    syscall

    ; lire DIRECTEMENT dans common_data.master_password (32 octets)
    mov rax, 0
    mov rdi, 0
    lea rsi, [rel master_password]
    mov rdx, MAX_KEYLEN
    syscall
    cmp rax, 0
    jle .fail_all       ; lecture échoue -> échec

    ; rax = nb lus ; supprimer LF/CR si présent
    mov r8, rax
    dec r8
    js .calc_len        ; si rax == 0 saute

    mov al, [master_password + r8]
    cmp al, 10          ; '\n' ?
    jne .maybe_cr
    mov byte [master_password + r8], 0
    cmp r8, 0
    je .calc_len
    mov al, [master_password + r8 - 1]
    cmp al, 13
    jne .calc_len
    mov byte [master_password + r8 - 1], 0
    jmp .calc_len

.maybe_cr:
    mov al, [master_password + r8]
    cmp al, 13
    jne .calc_len
    mov byte [master_password + r8], 0

.calc_len:
    ; calcule longueur dans rdx (0..MAX_KEYLEN)
    xor rdx, rdx
.len_loop:
    cmp rdx, MAX_KEYLEN
    jae .len_done
    mov al, [master_password + rdx]
    cmp al, 0
    je .len_done
    inc rdx
    jmp .len_loop
.len_done:
    ; si longueur différente de CHECK_LEN => message incorrect
    cmp rdx, CHECK_LEN
    je .do_check

    ; longueur incorrecte -> afficher message et décrémenter
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel wrong_msg]
    mov rdx, wrong_len
    syscall

    dec r12
    cmp r12, 0
    jg .try_loop

    ; épuisé -> message final
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel final_msg]
    mov rdx, final_len
    syscall
    jmp .fail_all

.do_check:
    ; vérification XOR: pour i in 0..CHECK_LEN-1: (master[i] XOR key[i]) == needed[i]
    xor rcx, rcx
.check_loop:
    cmp rcx, CHECK_LEN
    je .success
    mov al, [master_password + rcx]
    mov bl, [rel key + rcx]
    xor al, bl
    cmp al, [rel needed + rcx]
    jne .incorrect
    inc rcx
    jmp .check_loop

.incorrect:
    ; message incorrect
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel wrong_msg]
    mov rdx, wrong_len
    syscall

    dec r12
    cmp r12, 0
    jg .try_loop

    ; trop d'essais -> final
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel final_msg]
    mov rdx, final_len
    syscall
    jmp .fail_all

.success:
    ; afficher OK et return 0
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel ok_msg]
    mov rdx, ok_len
    syscall

    xor rax, rax    ; rax = 0
    pop rbp
    pop rbx
    pop r12
    ret

.fail_all:
    mov rax, 1
    pop rbp
    pop rbx
    pop r12
    ret
