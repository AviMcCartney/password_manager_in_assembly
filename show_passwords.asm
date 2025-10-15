; =====================================================================
; show_passwords.asm — Lecture/affichage des paires (login, password)
; Rôle:
;   - Ouvre le fichier des entrées chiffrées.
;   - Lit par blocs fixes de 64 octets.
;   - Déchiffre in-place via xor_encrypt_decrypt(master_password).
;   - Affiche: "<login_trimmed> <password_trimmed>\n" pour chaque bloc.
; Contrat:
;   - Exporte: show_passwords()
;   - Callee-saved préservés: RBX, RBP.
;   - Retour: via RET. Aucune valeur spécifiée dans RAX.
; Hypothèses:
;   - Chaque entrée occupe exactement 64 octets:
;       login[32] || password[32], null-terminés ou remplis.
;   - master_password contient la clé courante (ASCIIZ, ≤ 32).
;   - filename pointe vers le fichier de stockage.
; Limites:
;   - Ignore les blocs partiels (<64 octets), stops à EOF.
;   - Affiche rien si champ vide (longueur 0).
; =====================================================================

global show_passwords
extern filename
extern buffer
extern master_password
extern newline
extern xor_encrypt_decrypt
extern open_fail_msg

section .data
space db ' '                     ; séparateur entre login et password

section .text

show_passwords:
    ; Prologue — préserver les registres callee-saved utilisés
    push rbx
    push rbp

    ; ---------------- Ouverture du fichier (lecture seule) --------------------
    ; rax=2 (SYS_open), rdi=pathname, rsi=flags=0 (O_RDONLY)
    mov rax, 2
    lea rdi, [rel filename]
    mov rsi, 0
    syscall
    cmp rax, -1
    je  .open_err
    mov rbx, rax                  ; fd dans RBX

.read_loop:
    ; ---------------- Lecture d’un bloc de 64 octets --------------------------
    ; rax=0 (SYS_read), rdi=fd, rsi=buffer, rdx=64
    mov rax, 0
    mov rdi, rbx
    lea rsi, [rel buffer]
    mov rdx, 64
    syscall
    cmp rax, 0
    je  .close_and_done           ; EOF
    cmp rax, 64
    jne .close_and_done           ; bloc partiel -> stop (intégrité rompue)

    ; ---------------- Déchiffrement XOR in-place ------------------------------
    ; Convention: RDI=dest (buffer), RSI=key (master_password)
    lea rsi, [rel master_password]
    lea rdi, [rel buffer]
    call xor_encrypt_decrypt

    ; ---------------- Impression du login (buffer[0..31]) ---------------------
    ; Cherche la longueur effective jusqu’à '\0' ou 32.
    lea rsi, [rel buffer]         ; rsi base login
    xor rcx, rcx                  ; rcx = len
.find_login:
    cmp rcx, 32
    je  .print_login              ; plein champ
    mov al, [buffer + rcx]
    cmp al, 0
    je  .print_login              ; trouvé NUL
    inc rcx
    jmp .find_login

.print_login:
    ; write(1, buffer, rcx) si rcx>0
    cmp rcx, 0
    je  .skip_login_write
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel buffer]
    mov rdx, rcx
    syscall
.skip_login_write:

    ; ---------------- Espace séparateur ---------------------------------------
    ; write(1, " ", 1)
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel space]
    mov rdx, 1
    syscall

    ; ---------------- Impression du password (buffer[32..63]) -----------------
    lea rsi, [rel buffer + 32]    ; rsi base password
    xor rcx, rcx                  ; rcx = len
.find_pass:
    cmp rcx, 32
    je  .print_pass
    mov al, [buffer + 32 + rcx]
    cmp al, 0
    je  .print_pass
    inc rcx
    jmp .find_pass

.print_pass:
    ; write(1, buffer+32, rcx) si rcx>0
    cmp rcx, 0
    je  .skip_pass_write
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel buffer + 32]
    mov rdx, rcx
    syscall
.skip_pass_write:

    ; ---------------- Nouvelle ligne -----------------------------------------
    ; write(1, "\n", 1)
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel newline]
    mov rdx, 1
    syscall

    jmp .read_loop                ; prochain enregistrement

.close_and_done:
    ; ---------------- Fermeture du fichier ------------------------------------
    mov rax, 3                    ; SYS_close
    mov rdi, rbx
    syscall
    jmp .finish

.open_err:
    ; ---------------- Message d’erreur d’ouverture ----------------------------
    ; write(1, open_fail_msg, 21)  ; longueur fixée dans l’appelant
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel open_fail_msg]
    mov rdx, 21
    syscall

.finish:
    ; Épilogue — restaurer et retourner
    pop rbp
    pop rbx
    ret
