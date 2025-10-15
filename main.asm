; main.asm — boucle persistante + option 3 pour quitter

global _start
extern authenticate
extern add_password
extern show_passwords
extern newline

section .data
    menu_msg    db "Choisissez: 1) Ajouter (F1)  2) Afficher (F2)  3) Quitter",10,"> ",0
    menu_len    equ $-menu_msg
    invalid_msg db "Choix invalide.",10
    invalid_len equ $-invalid_msg

    MAX_READ    equ 8

section .bss
    choice_buf  resb MAX_READ

section .text
_start:
    ; Authentification initiale
    call authenticate
    cmp  rax, 0
    jne  .auth_failed

.menu_loop:
    ; saut de ligne avant le menu
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel newline]
    mov rdx, 1
    syscall

    ; Afficher le menu
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel menu_msg]
    mov rdx, menu_len
    syscall

    ; Lire l’entrée utilisateur
    mov rax, 0
    mov rdi, 0
    lea rsi, [rel choice_buf]
    mov rdx, MAX_READ
    syscall
    cmp rax, 0
    jle .exit_fail

    ; Dispatch sur le premier caractère
    mov al, [choice_buf]
    cmp al, '1'
    je  .do_add
    cmp al, '2'
    je  .do_show
    cmp al, '3'
    je  .exit_ok

    ; Choix invalide -> message puis reboucler
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel invalid_msg]
    mov rdx, invalid_len
    syscall
    jmp .menu_loop

.do_add:
    call add_password
    jmp  .menu_loop

.do_show:
    call show_passwords
    jmp  .menu_loop

.auth_failed:
    mov rax, 60
    mov rdi, 1
    syscall

.exit_ok:
    mov rax, 60
    xor rdi, rdi
    syscall

.exit_fail:
    mov rax, 60
    mov rdi, 1
    syscall
