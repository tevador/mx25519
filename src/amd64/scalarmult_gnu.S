# Copyright (c) 2022 tevador <tevador@gmail.com>
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
DECL(mx25519_scalarmult_amd64x):
#ifdef WINABI
  mov qword ptr [rsp+8], rdi
  mov qword ptr [rsp+16], rsi
  mov rdi, rcx
  mov rsi, rdx
  mov rdx, r8
#endif

#include "scalarmult_mulx_adx.inc"

#ifdef WINABI
  mov rdi, qword ptr [rsp+8]
  mov rsi, qword ptr [rsp+16]
#endif

  ret

ALIGN 32
DECL(mx25519_scalarmult_amd64):
#ifdef WINABI
  mov qword ptr [rsp+8], rdi
  mov qword ptr [rsp+16], rsi
  mov rdi, rcx
  mov rsi, rdx
  mov rdx, r8
#endif

#include "scalarmult_compat.inc"

#ifdef WINABI
  mov rdi, qword ptr [rsp+8]
  mov rsi, qword ptr [rsp+16]
#endif

  ret
