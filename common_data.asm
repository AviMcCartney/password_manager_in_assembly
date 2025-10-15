; ====================================================================
; common_data.asm — Données partagées + primitive XOR
; Rôle:
;   - Expose via 'global' toutes les chaînes, tampons et symboles
;     utilisés par les autres modules (prompts, messages, fichier).
;   - Fournit xor_encrypt_decrypt: XOR en place de 64 octets avec
;     une clé ASCIIZ (longueur <= 32), clé répétée périodiquement.
; Conventions:
;   - SysV x86_64. Les segments .data/.bss exportent des symboles.
;   - Aucune allocation dynamique. Tailles fixes (voir commentaires).
;   - La fonction XOR préserve l’état appelant (sauvegarde registres).
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
global login
global password
global choice
global entry
global buffer
global encrypted_entry

global xor_encrypt_decrypt

section .data
; -------------------- Chaînes constantes (ASCIIZ) --------------------
login_prompt     db "Enter login: ", 0                 ; prompt login
password_prompt  db "Enter password: ", 0              ; prompt mot de passe
master_prompt    db "Enter master password: ", 0       ; prompt maître
choice_prompt    db "Choose an option (0 to add, 1 to display): ", 0 ; menu
newline          db 0xA, 0                              ; "\n" + NUL

success_msg      db "Login and password stored successfully!", 0 ; succès
fail_msg         db "Error writing to file!", 0                   ; erreur write()
open_fail_msg    db "Error opening file!", 0                      ; erreur open()
filename         db 'databs.txt', 0                               ; fichier cible

section .bss
; -------------------- Tampons mutables -------------------------------
master_password  resb 32     ; clé maîtresse saisie (max 32, ASCIIZ possible)
login            resb 32     ; champ login brut (max 32)
password         resb 32     ; champ password brut (max 32)
choice           resb 1      ; choix utilisateur (1 octet)
entry            resb 64     ; bloc 64 = login(32) || password(32)
buffer           resb 256    ; buffer I/O générique (lecture fichier, etc.)
encrypted_entry  resb 64     ; bloc 64 chiffré/déchiffré (si besoin distinct)

section .text
; --------------------------------------------------------------------
; xor_encrypt_decrypt
;   Répète la clé ASCIIZ (longueur L, 1<=L<=32) sur 64 octets et
;   applique XOR en place sur le buffer de 64 octets.
;   Entrées:
;     RDI = adresse du buffer 64 octets (dest, modifié en place)
;     RSI = adresse de la clé ASCIIZ (longueur <= 32). Si longueur 0,
;           la fonction ne modifie rien.
;   Sorties:
;     Rien (buffer modifié en place). Registres appelant préservés.
;   Complexité:
;     O(L + 64) — calcul de la longueur puis balayage des 64 octets.
;   Remarques:
;     - Le "modulo" de l’index est implémenté par soustractions successives
;       (compatibilité sans DIV/MOD, coût négligeable à 64 octets).
; --------------------------------------------------------------------
xor_encrypt_decrypt:
    ; Sauvegarde des registres potentiellement clobber
    push rbx
    push rcx
    push rdx
    push r8
    push r9

    ; ---- Mesure de la longueur de clé (r8 = L, bornée à 32) ----
    xor r8, r8
.xlen_loop:
    mov al, [rsi + r8]    ; lire clé[r8]
    cmp al, 0             ; fin ASCIIZ ?
    je  .xlen_done
    inc r8
    cmp r8, 32            ; borne max de sécurité
    jb  .xlen_loop
.xlen_done:
    cmp r8, 0             ; L == 0 ?
    jne .have_key
    jmp .xret             ; clé vide => no-op

.have_key:
    ; ---- XOR des 64 octets avec clé périodique ----
    xor rcx, rcx          ; rcx = i (0..63)
.xloop:
    cmp rcx, 64
    je  .xret

    ; rdx = i mod L (par soustractions, L <= 32 => peu d’itérations)
    mov rdx, rcx
.mod_loop:
    cmp rdx, r8
    jb  .mod_done
    sub rdx, r8
    jmp .mod_loop
.mod_done:
    ; al = buffer[i] XOR key[rdx]
    mov al, [rdi + rcx]
    mov bl, [rsi + rdx]
    xor al, bl
    mov [rdi + rcx], al

    inc rcx
    jmp .xloop

.xret:
    ; Restauration registres et retour
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret
