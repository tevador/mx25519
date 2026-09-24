# Copyright (c) 2022-2026 tevador <tevador@gmail.com>
#
# This file is part of mx25519, which is released under LGPLv3.
# See LICENSE for full license details.

.intel_syntax noprefix
#if defined(__APPLE__)
.text
#define DECL(x) _##x
#else
.section .text
#define DECL(x) x
#endif

#if defined(__WIN32__) || defined(__CYGWIN__)
#define WINABI
#endif

#define REG_REL rip
#define db .byte
#define ALIGN .balign

#if defined(__CET__) && (__CET__ & 1)
#define CET_ENDBR endbr64
#else
#define CET_ENDBR
#endif

#if defined(__ELF__)
#define FUNC_TYPE(x) .type DECL(x), @function
#define FUNC_SIZE(x) .size DECL(x), . - DECL(x)
#else
#define FUNC_TYPE(x)
#define FUNC_SIZE(x)
#endif

.global DECL(mx25519_scalarmult_amd64x)
.global DECL(mx25519_scalarmult_amd64)

#include "constants.inc"

ALIGN 32
#include "gcd_table.inc"

ALIGN 32
FUNC_TYPE(mx25519_scalarmult_amd64x)
DECL(mx25519_scalarmult_amd64x):
  CET_ENDBR
#ifdef WINABI
  mov   qword ptr [rsp+8], rdi
  mov   qword ptr [rsp+16], rsi
  mov   rdi, rcx
  mov   rsi, rdx
  mov   rdx, r8
  sub   rsp, 160
  vmovdqu xmmword ptr [rsp+144], xmm6
  vmovdqu xmmword ptr [rsp+128], xmm7
  vmovdqu xmmword ptr [rsp+112], xmm8
  vmovdqu xmmword ptr [rsp+96], xmm9
  vmovdqu xmmword ptr [rsp+80], xmm10
  vmovdqu xmmword ptr [rsp+64], xmm11
  vmovdqu xmmword ptr [rsp+48], xmm12
  vmovdqu xmmword ptr [rsp+32], xmm13
  vmovdqu xmmword ptr [rsp+16], xmm14
  vmovdqu xmmword ptr [rsp], xmm15
#endif

#include "scalarmult_mulx_adx.inc"

#ifdef WINABI
  vmovdqu xmm15, xmmword ptr [rsp]
  vmovdqu xmm14, xmmword ptr [rsp+16]
  vmovdqu xmm13, xmmword ptr [rsp+32]
  vmovdqu xmm12, xmmword ptr [rsp+48]
  vmovdqu xmm11, xmmword ptr [rsp+64]
  vmovdqu xmm10, xmmword ptr [rsp+80]
  vmovdqu xmm9, xmmword ptr [rsp+96]
  vmovdqu xmm8, xmmword ptr [rsp+112]
  vmovdqu xmm7, xmmword ptr [rsp+128]
  vmovdqu xmm6, xmmword ptr [rsp+144]
  add   rsp, 160
  mov   rdi, qword ptr [rsp+8]
  mov   rsi, qword ptr [rsp+16]
#endif

  ret
FUNC_SIZE(mx25519_scalarmult_amd64x)

ALIGN 32
FUNC_TYPE(mx25519_scalarmult_amd64)
DECL(mx25519_scalarmult_amd64):
  CET_ENDBR
#ifdef WINABI
  mov   qword ptr [rsp+8], rdi
  mov   qword ptr [rsp+16], rsi
  mov   rdi, rcx
  mov   rsi, rdx
  mov   rdx, r8
#endif

#include "scalarmult_compat.inc"

#ifdef WINABI
  mov   rdi, qword ptr [rsp+8]
  mov   rsi, qword ptr [rsp+16]
#endif

  ret
FUNC_SIZE(mx25519_scalarmult_amd64)

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#if defined(__CET__)
.section .note.gnu.property,"a"
ALIGN 8
.long 1f - 0f
.long 4f - 1f
.long 5
0: .asciz "GNU"
1: ALIGN 8
.long 0xc0000002
.long 3f - 2f
2: .long __CET__
3: ALIGN 8
4:
#endif
#endif
