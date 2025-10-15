; add_password.asm — ajoute une entrée (login, password) chiffrée et l’écrit en append
; Contrat: add_password() ne détruit pas RBX/RBP (sauvegarde/restaure), retourne via RET.
; I/O: utilise read(0, …), write(1|fd, …), openat (num 2 ici = open), close(3).
; Format d’une entrée: 64 octets = 32 pour login + 32 pour password, puis XOR en place.
; Dépendances de données/chaines définies dans common_data.asm.
;
; Syscalls Linux x86_64:
;   rax = numéro, rdi/rsi/rdx/r10/r8/r9 = arguments, retour dans rax.
; Codes d’ouverture: O_WRONLY|O_CREAT|O_APPEND = 0x441 = 1089 décimal.
; Droits de création: 0644 octal = 420 décimal.

global add_password

; Symboles externes (données + fonctions utilitaires)
extern login_prompt          ; "Login: "… (taille attendue 13)
extern password_prompt       ; "Password: "… (taille attendue 17)
extern login                 ; tampon 32 octets
extern password              ; tampon 32 octets
extern entry                 ; tampon 64 octets (login||password)
extern master_password       ; clé XOR (octets, taille gérée par xor_encrypt_decrypt)
extern filename              ; chemin du fichier de stockage
extern success_msg           ; "Entrée enregistrée."… (taille attendue 39)
extern fail_msg              ; "Erreur d'écriture."… (taille attendue 22)
extern open_fail_msg         ; "Erreur d'ouverture."… (taille attendue 21)
extern xor_encrypt_decrypt   ; void xor_encrypt_decrypt(dest=RDI, key=RSI) — opère in-place

section .text

add_password:
    ; Prologue: préserver registres appelés-preservés utilisés (RBX,RBP)
    push rbx
    push rbp

    ; --- Prompt LOGIN ---------------------------------------------------------
    ; write(1, login_prompt, 13)
    mov rax, 1                      ; SYS_write
    mov rdi, 1                      ; STDOUT
    lea rsi, [rel login_prompt]
    mov rdx, 13                     ; longueur littérale du prompt
    syscall

    ; --- Lecture LOGIN --------------------------------------------------------
    ; read(0, login, 32)
    mov rax, 0                      ; SYS_read
    mov rdi, 0                      ; STDIN
    lea rsi, [rel login]
    mov rdx, 32                     ; lit au plus 32 octets
    syscall
    ; rax = nombre d’octets lus. On retire un éventuel '\n' final.
    mov r8, rax                     ; r8 = n
    cmp r8, 0
    je .read_pw                     ; rien lu -> passe au password
    dec r8                           ; index du dernier octet lu - 1
    mov al, [login + r8]
    cmp al, 10                      ; '\n' ?
    jne .read_pw
    mov byte [login + r8], 0        ; remplace '\n' par '\0' (sécurise la concaténation)

.read_pw:
    ; --- Prompt PASSWORD ------------------------------------------------------
    ; write(1, password_prompt, 17)
    mov rax, 1                      ; SYS_write
    mov rdi, 1                      ; STDOUT
    lea rsi, [rel password_prompt]
    mov rdx, 17
    syscall

    ; --- Lecture PASSWORD -----------------------------------------------------
    ; read(0, password, 32)
    mov rax, 0                      ; SYS_read
    mov rdi, 0                      ; STDIN
    lea rsi, [rel password]
    mov rdx, 32
    syscall
    ; Nettoyage du '\n' éventuel comme pour login
    mov r8, rax
    cmp r8, 0
    je .build_entry
    dec r8
    mov al, [password + r8]
    cmp al, 10
    jne .build_entry
    mov byte [password + r8], 0

.build_entry:
    ; --- Construction du bloc 64 octets --------------------------------------
    ; entry[0..31]  = login (copie brute, 32 octets)
    ; entry[32..63] = password (copie brute, 32 octets)
    lea rdi, [rel entry]            ; dest
    lea rsi, [rel login]            ; src
    mov rcx, 32
    cld
    rep movsb

    lea rdi, [rel entry + 32]       ; dest = fin de login
    lea rsi, [rel password]         ; src = password
    mov rcx, 32
    cld
    rep movsb

    ; --- Chiffrement XOR in-place --------------------------------------------
    ; Convention: RDI=dest (entry), RSI=key (master_password)
    lea rsi, [rel master_password]
    lea rdi, [rel entry]
    call xor_encrypt_decrypt

    ; --- Ouverture du fichier en append --------------------------------------
    ; fd = open(filename, O_WRONLY|O_CREAT|O_APPEND, 0644)
    mov rax, 2                      ; SYS_open (ABI historique; sur kernels récents openat est 257)
    lea rdi, [rel filename]         ; const char *pathname
    mov rsi, 1089                   ; flags: 0x441 (WRONLY|CREAT|APPEND)
    mov rdx, 420                    ; mode: 0644 (si CREAT)
    syscall
    cmp rax, -1
    je .open_error
    mov rbx, rax                    ; sauvegarde fd dans RBX

    ; --- Écriture de l’entrée chiffrée ---------------------------------------
    ; write(fd, entry, 64)
    mov rax, 1                      ; SYS_write
    mov rdi, rbx                    ; fd
    lea rsi, [rel entry]
    mov rdx, 64
    syscall
    cmp rax, -1
    je .write_error

    ; --- Fermeture fd ---------------------------------------------------------
    mov rax, 3                      ; SYS_close
    mov rdi, rbx
    syscall

    ; --- Message de succès ----------------------------------------------------
    ; write(1, success_msg, 39)
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel success_msg]
    mov rdx, 39
    syscall
    jmp .done

.open_error:
    ; write(1, open_fail_msg, 21)
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel open_fail_msg]
    mov rdx, 21
    syscall
    jmp .done

.write_error:
    ; write(1, fail_msg, 22)
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel fail_msg]
    mov rdx, 22
    syscall
    ; si un fd valide a été ouvert, on tente de le fermer
    cmp rbx, 0
    jle .done
    mov rax, 3                      ; SYS_close
    mov rdi, rbx
    syscall

.done:
    ; Épilogue: restaurer RBP/RBX et retourner
    pop rbp
    pop rbx
    ret
