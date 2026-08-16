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

.global DECL(mx25519_scalarmult_amd64x)
.global DECL(mx25519_scalarmult_amd64)

#include "constants.inc"

ALIGN 32
#include "gcd_table.inc"

ALIGN 32
DECL(mx25519_scalarmult_amd64x):
#ifdef WINABI
  mov   qword ptr [rsp+8], rdi
  mov   qword ptr [rsp+16], rsi
  mov   rdi, rcx
  mov   rsi, rdx
  mov   rdx, r8
  mov   rcx, r9
  movzx r8, byte ptr [rsp+40]
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

ALIGN 32
DECL(mx25519_scalarmult_amd64):
#ifdef WINABI
  mov   qword ptr [rsp+8], rdi
  mov   qword ptr [rsp+16], rsi
  mov   rdi, rcx
  mov   rsi, rdx
  mov   rdx, r8
  mov   rcx, r9
  movzx r8, byte ptr [rsp+40]
#endif

#include "scalarmult_compat.inc"

#ifdef WINABI
  mov   rdi, qword ptr [rsp+8]
  mov   rsi, qword ptr [rsp+16]
#endif

  ret
