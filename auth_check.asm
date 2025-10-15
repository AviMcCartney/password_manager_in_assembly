; auth_check.asm — Authentification par mot de passe maître
; Contrat:
;   authenticate() -> RAX = 0 si succès, 1 si échec (trop d’essais / lecture KO / longueur invalide / XOR invalide)
; Contexte technique:
;   Linux x86_64 SysV ABI. Syscalls: read(0,buf,len)=RAX=0, write(1,buf,len)=RAX=1.
;   Registres callee-saved préservés: RBX, RBP, R12.
; Principe:
;   1) Afficher un prompt (optionnel).
;   2) Lire le mot de passe dans common_data.master_password (max 32).
;   3) Retirer LF/CR fin de ligne, calculer la longueur.
;   4) Exiger CHECK_LEN octets.
;   5) Vérifier: master[i] XOR key[i] == needed[i] pour i=0..CHECK_LEN-1.
;   6) 3 tentatives max, messages associés.

global authenticate
extern master_prompt           ; chaîne définie dans common_data (facultatif)
extern master_password         ; buffer 32 octets partagé (destination de lecture)

section .data
    ok_msg      db "Mot de passe correct", 10
    ok_len      equ $-ok_msg

    wrong_msg   db "Mot de passe incorrect", 10
    wrong_len   equ $-wrong_msg

    final_msg   db "Trop d'essais. Fin.", 10
    final_len   equ $-final_msg

    ; Matériel de vérification XOR (longueurs bornées par CHECK_LEN).
    key:        db 215,12,59,49,231,63,30,91,51,198,129,13,90,170,150,2,184,181,183,243,186,54,10,125,140,90,0
    needed:     db 175,60,73,0,137,120,65,111,108,149,245,95,107,196,209,93,207,132,227,155,229,2,85,22,191,35

    CHECK_LEN   equ 26            ; longueur attendue du mot de passe
    MAX_KEYLEN  equ 32            ; taille max lue dans master_password
    PROMPT_LEN  equ 23            ; longueur affichée pour master_prompt (adapter si besoin)

section .text

; authenticate:
;   Entrées:  —
;   Sorties:  RAX=0 si succès, RAX=1 sinon.
;   Effets:   Écrit sur STDOUT, lit sur STDIN, remplit master_password.
authenticate:
    ; Prologue — préserver les callee-saved utilisés
    push r12
    push rbx
    push rbp

    mov  r12, 3                   ; compteur d’essais restants

.try_loop:
    ; --- Prompt (optionnel) ---------------------------------------------------
    ; write(1, master_prompt, PROMPT_LEN)
    mov  rax, 1                   ; SYS_write
    mov  rdi, 1                   ; fd = STDOUT
    lea  rsi, [rel master_prompt]
    mov  rdx, PROMPT_LEN
    syscall

    ; --- Lecture du mot de passe ---------------------------------------------
    ; read(0, master_password, MAX_KEYLEN)
    mov  rax, 0                   ; SYS_read
    mov  rdi, 0                   ; fd = STDIN
    lea  rsi, [rel master_password]
    mov  rdx, MAX_KEYLEN
    syscall
    cmp  rax, 0
    jle  .fail_all                ; erreur ou EOF immédiat

    ; rax = nb d’octets lus. Retirer LF/CR éventuels en fin de ligne.
    mov  r8, rax                  ; r8 = n
    dec  r8
    js   .calc_len                ; si n == 0 (cas limite), passer au calcul

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
    cmp  al, 13                   ; '\r'
    jne  .calc_len
    mov  byte [master_password + r8], 0

.calc_len:
    ; --- Longueur réelle (jusqu’au premier '\0'), max MAX_KEYLEN --------------
    xor  rdx, rdx                 ; rdx = len
.len_loop:
    cmp  rdx, MAX_KEYLEN
    jae  .len_done
    mov  al, [master_password + rdx]
    cmp  al, 0
    je   .len_done
    inc  rdx
    jmp  .len_loop
.len_done:

    ; Vérifier la longueur attendue
    cmp  rdx, CHECK_LEN
    je   .do_check

    ; Longueur invalide -> message, décrément essais
    mov  rax, 1                   ; SYS_write
    mov  rdi, 1
    lea  rsi, [rel wrong_msg]
    mov  rdx, wrong_len
    syscall

    dec  r12
    cmp  r12, 0
    jg   .try_loop

    ; Plus d’essais -> message final
    mov  rax, 1
    mov  rdi, 1
    lea  rsi, [rel final_msg]
    mov  rdx, final_len
    syscall
    jmp  .fail_all

.do_check:
    ; --- Vérification XOR -----------------------------------------------------
    ; Pour i = 0..CHECK_LEN-1:
    ;   (master_password[i] XOR key[i]) doit égaler needed[i]
    xor  rcx, rcx
.check_loop:
    cmp  rcx, CHECK_LEN
    je   .success
    mov  al, [master_password + rcx]
    mov  bl, [rel key + rcx]
    xor  al, bl
    cmp  al, [rel needed + rcx]
    jne  .incorrect
    inc  rcx
    jmp  .check_loop

.incorrect:
    ; Mauvais mot de passe -> message, décrément essais
    mov  rax, 1
    mov  rdi, 1
    lea  rsi, [rel wrong_msg]
    mov  rdx, wrong_len
    syscall

    dec  r12
    cmp  r12, 0
    jg   .try_loop

    ; Plus d’essais -> message final
    mov  rax, 1
    mov  rdi, 1
    lea  rsi, [rel final_msg]
    mov  rdx, final_len
    syscall
    jmp  .fail_all

.success:
    ; Succès -> message + RAX=0
    mov  rax, 1
    mov  rdi, 1
    lea  rsi, [rel ok_msg]
    mov  rdx, ok_len
    syscall

    xor  rax, rax                 ; code retour 0
    pop  rbp
    pop  rbx
    pop  r12
    ret

.fail_all:
    ; Échec -> RAX=1
    mov  rax, 1
    pop  rbp
    pop  rbx
    pop  r12
    ret
