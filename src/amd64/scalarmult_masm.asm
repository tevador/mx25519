; Copyright (c) 2022 tevador <tevador@gmail.com>
;
; This file is part of mx25519, which is released under LGPLv3.
; See LICENSE for full license details.

IFDEF RAX

REG_REL EQU 0

MX25519_SCALARMULT SEGMENT PAGE READ EXECUTE

PUBLIC mx25519_scalarmult_amd64x
PUBLIC mx25519_scalarmult_amd64

include constants.inc

mx25519_scalarmult_amd64x PROC
  mov qword ptr [rsp+8], rdi
  mov qword ptr [rsp+16], rsi
  mov rdi, rcx
  mov rsi, rdx
  mov rdx, r8

include scalarmult_mulx_adx.inc

  mov rdi, qword ptr [rsp+8]
  mov rsi, qword ptr [rsp+16]
  ret
mx25519_scalarmult_amd64x ENDP

mx25519_scalarmult_amd64 PROC
  mov qword ptr [rsp+8], rdi
  mov qword ptr [rsp+16], rsi
  mov rdi, rcx
  mov rsi, rdx
  mov rdx, r8

include scalarmult_compat.inc

  mov rdi, qword ptr [rsp+8]
  mov rsi, qword ptr [rsp+16]
  ret
mx25519_scalarmult_amd64 ENDP

MX25519_SCALARMULT ENDS

ENDIF

END
