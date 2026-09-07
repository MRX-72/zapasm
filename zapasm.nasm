; zapasm.nasm - single-port connect scanner, raw syscalls only
; A minimal recreation of the zapscan connect-scan core.
; usage: zapasm <ipv4> <port>

section .data
    open_msg:   db "open", 10
    open_len:   equ $-open_msg
    closed_msg: db "closed", 10
    closed_len: equ $-closed_msg
    usage_msg:  db "usage: zapasm <ip> <port>", 10
    usage_len:  equ $-usage_msg

section .bss
    sockaddr: resb 16                  ; struct sockaddr_in

section .text
    global _start

_start:
    mov rax, [rsp]                     ; argc
    cmp rax, 3
    jne .usage

    mov rdi, [rsp+16]                  ; argv[1] = "1.2.3.4"
    call parse_ip                      ; -> bytes at sockaddr+4

    mov rdi, [rsp+24]                  ; argv[2] = "80"
    call parse_port                    ; -> big-endian at sockaddr+2

    mov word [sockaddr], 2             ; AF_INET

    mov rax, 41                        ; socket(AF_INET, SOCK_STREAM, 0)
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    syscall
    test rax, rax
    js .closed                         ; socket failed
    mov r13, rax                       ; keep fd

    mov rax, 42                        ; connect(fd, sockaddr, 16)
    mov rdi, r13
    lea rsi, [sockaddr]
    mov rdx, 16
    syscall
    test rax, rax
    jnz .closed                        ; refused / filtered

    mov rax, 1                         ; write(1, "open")
    mov rdi, 1
    lea rsi, [open_msg]
    mov rdx, open_len
    syscall
    mov rax, 60
    xor rdi, rdi
    syscall

.closed:
    mov rax, 1                         ; write(1, "closed")
    mov rdi, 1
    lea rsi, [closed_msg]
    mov rdx, closed_len
    syscall
    mov rax, 60
    xor rdi, rdi
    syscall

.usage:
    mov rax, 1
    mov rdi, 1
    lea rsi, [usage_msg]
    mov rdx, usage_len
    syscall
    mov rax, 60
    mov rdi, 2
    syscall

; rdi = dotted-quad string -> writes 4 octets at sockaddr+4
parse_ip:
    lea rsi, [sockaddr+4]
    mov r12, 3               ; remaining dots
.loop:
    xor r8, r8               ; current octet
.byte:
    movzx r9, byte [rdi]
    test r9, r9
    jz .done
    cmp r9, '.'
    je .next
    sub r9, '0'
    imul r8, r8, 10
    add r8, r9
    inc rdi
    jmp .byte
.next:
    mov byte [rsi], r8b
    inc rsi
    inc rdi
    dec r12
    test r12, r12
    jge .loop
.done:
    mov byte [rsi], r8b
    ret

; rdi = decimal port string -> writes 2 bytes big-endian at sockaddr+2
parse_port:
    xor r8, r8
.loop:
    movzx r9, byte [rdi]
    test r9, r9
    jz .done
    sub r9, '0'
    imul r8, r8, 10
    add r8, r9
    inc rdi
    jmp .loop
.done:
    cmp r8, 65535
    ja .usage                 ; reject > 65535
    shl r8, 8                 ; network order: high byte first
    mov byte [sockaddr+2], r8b    ; port >> 8
    mov byte [sockaddr+3], r8h    ; port & 0xff
    ret