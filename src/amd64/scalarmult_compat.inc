;# Copyright (c) 2022 tevador <tevador@gmail.com>
;#
;# This file is part of mx25519, which is released under LGPLv3.
;# See LICENSE for full license details.
;#
;#
;# Parts of this file are derived from a work with the following license:
;#
;# Copyright (c) 2020, Kaushik Nath and Palash Sarkar.
;#
;# Permission to use this code is granted.
;#
;# Redistribution and use in source and binary forms, with or without
;# modification, are permitted provided that the following conditions are
;# met:
;#
;# * Redistributions of source code must retain the above copyright notice,
;#   this list of conditions and the following disclaimer.
;#
;# * Redistributions in binary form must reproduce the above copyright
;#   notice, this list of conditions and the following disclaimer in the
;#   documentation and/or other materials provided with the distribution.
;#
;# * The names of the contributors may not be used to endorse or promote
;#   products derived from this software without specific prior written
;#   permission.
;#
;# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ""AS IS"" AND ANY EXPRESS OR
;# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
;# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
;# IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
;# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
;# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
;# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
;# THEORY LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
;# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

;# arguments:
;#     rdi -> public key address (out)
;#     rsi -> private key address (in)
;#     rdx -> base point address (in)

sub rsp, 392

;# stack layout (offsets from rsp):
;# 0 T1
;# 32 T2
;# 64 T3
;# 96 T4
;# 128 X1
;# 160 X2
;# 192 X3
;# 224 Z2
;# 256 Z3
;# 288 saved registers: rbx, rbp, rdi, rsi, r12, r13, r14, r15
;# 352 key bit index (1 byte)
;# 353 swap flag (1 byte)
;# 354 current key byte value (1 byte)
;# 356 key byte index (4 bytes)
;# 360 private key

mov    qword ptr [rsp+288], rbx
mov    qword ptr [rsp+296], rbp
mov    qword ptr [rsp+304], rdi
;# mov    qword ptr [rsp+312], rsi
mov    qword ptr [rsp+320], r12
mov    qword ptr [rsp+328], r13
mov    qword ptr [rsp+336], r14
mov    qword ptr [rsp+344], r15

;# copy the private key and clamp it
mov    r8, qword ptr [rsi]
and    r8, -8
mov    qword ptr [rsp+360], r8
mov    r8, qword ptr [rsi+8]
mov    qword ptr [rsp+368], r8
mov    r8, qword ptr [rsi+16]
mov    qword ptr [rsp+376], r8
mov    r8, qword ptr [rsi+24]
mov    qword ptr [rsp+384], r8

;# starting from bit 6 of the 31st byte
mov    eax, 31
mov    byte ptr [rsp+352], 6
mov    byte ptr [rsp+353], 0
mov    dword ptr [rsp+356], eax

;# load XP
mov    r8, qword ptr [rdx]
mov    r9, qword ptr [rdx+8]
mov    r10, qword ptr [rdx+16]
mov    r11, qword ptr [rdx+24]

;# reduce XP mod 2^255-19
btr    r11, 63
mov    rbx, r8
mov    rcx, r9
mov    rdx, r10
mov    rdi, r11
sub    r8, qword ptr [p0+REG_REL]
sbb    r9, qword ptr [p12+REG_REL]
sbb    r10, qword ptr [p12+REG_REL]
sbb    r11, qword ptr [p3+REG_REL]
bt     r11, 63
cmovb  r8, rbx
cmovb  r9, rcx
cmovb  r10, rdx
cmovb  r11, rdi

;# X1 ← XP, X3 ← XP
mov    qword ptr [rsp+128], r8
mov    qword ptr [rsp+192], r8
mov    qword ptr [rsp+136], r9
mov    qword ptr [rsp+200], r9
mov    qword ptr [rsp+144], r10
mov    qword ptr [rsp+208], r10
mov    qword ptr [rsp+152], r11
mov    qword ptr [rsp+216], r11

;# X2 ← 1
mov    qword ptr [rsp+160], 1
mov    qword ptr [rsp+168], 0
mov    qword ptr [rsp+176], 0
mov    qword ptr [rsp+184], 0

;# Z2 ← 0
mov    qword ptr [rsp+224], 0
mov    qword ptr [rsp+232], 0
mov    qword ptr [rsp+240], 0
mov    qword ptr [rsp+248], 0

;# Z3 ← 1
mov    qword ptr [rsp+256], 1
mov    qword ptr [rsp+264], 0
mov    qword ptr [rsp+272], 0
mov    qword ptr [rsp+280], 0

;# Montgomery ladder loop

loop_byte:

;# rsi = private key address
;# eax = key byte index
movzx  ecx, byte ptr [rsi+rax]
mov    byte ptr [rsp+354], cl

;#
;# Montgomery ladder step
;#
;# Reduction ideas for addition and subtraction are taken from the 64-bit implementation
;# "amd64-64" of the work "https://link.springer.com/article/10.1007/s13389-012-0027-1"
;#
;# T1 ← X2 + Z2
;# T2 ← X2 - Z2
;# T3 ← X3 + Z3
;# T4 ← X3 - Z3
;# Z3 ← T2 · T3
;# X3 ← T1 · T4
;#
;# bit ← n[i]
;# select ← bit ⊕ prevbit
;# prevbit ← bit
;# CSelect(T1,T3,select): if (select == 1) {T1 = T3}
;# CSelect(T2,T4,select): if (select == 1) {T2 = T4}
;#
;# T2 ← T2^2
;# T1 ← T1^2
;# X3 ← X3 + Z3
;# Z3 ← X3 - Z3
;# Z3 ← Z3^2
;# X3 ← X3^2
;# T3 ← T1 - T2
;# T4 ← ((A + 2)/4) · T3
;# T4 ← T4 + T2
;# X2 ← T1 · T2
;# Z2 ← T3 · T4
;# Z3 ← Z3 · X1
;#

loop_bit:

;# X2
mov    r8, qword ptr [rsp+160]
mov    r9, qword ptr [rsp+168]
mov    r10, qword ptr [rsp+176]
mov    r11, qword ptr [rsp+184]

;# copy X2
mov    rax, r8
mov    rbx, r9
mov    rbp, r10
mov    rsi, r11

;# T1 ← X2 + Z2
add    r8, qword ptr [rsp+224]
adc    r9, qword ptr [rsp+232]
adc    r10, qword ptr [rsp+240]
adc    r11, qword ptr [rsp+248]

mov    rdi, 0
mov    rcx, 38
cmovae rcx, rdi

add    r8, rcx
adc    r9, rdi
adc    r10, rdi
adc    r11, rdi

cmovb  rdi, rcx
add    r8, rdi

mov    qword ptr [rsp+0], r8
mov    qword ptr [rsp+8], r9
mov    qword ptr [rsp+16], r10
mov    qword ptr [rsp+24], r11

;# T2 ← X2 - Z2
sub    rax, qword ptr [rsp+224]
sbb    rbx, qword ptr [rsp+232]
sbb    rbp, qword ptr [rsp+240]
sbb    rsi, qword ptr [rsp+248]
mov    rdi, 0
mov    rcx, 38
cmovae rcx, rdi
sub    rax, rcx
sbb    rbx, rdi
sbb    rbp, rdi
sbb    rsi, rdi
cmovb  rdi, rcx
sub    rax, rdi
mov    qword ptr [rsp+32], rax
mov    qword ptr [rsp+40], rbx
mov    qword ptr [rsp+48], rbp
mov    qword ptr [rsp+56], rsi

;# X3
mov    r8, qword ptr [rsp+192]
mov    r9, qword ptr [rsp+200]
mov    r10, qword ptr [rsp+208]
mov    r11, qword ptr [rsp+216]

;# copy X3
mov    rax, r8
mov    rbx, r9
mov    rbp, r10
mov    rsi, r11

;# T3 ← X3 + Z3
add    r8, qword ptr [rsp+256]
adc    r9, qword ptr [rsp+264]
adc    r10, qword ptr [rsp+272]
adc    r11, qword ptr [rsp+280]
mov    rdi, 0
mov    rcx, 38
cmovae rcx, rdi
add    r8, rcx
adc    r9, rdi
adc    r10, rdi
adc    r11, rdi
cmovb  rdi, rcx
add    r8, rdi
mov    qword ptr [rsp+64], r8
mov    qword ptr [rsp+72], r9
mov    qword ptr [rsp+80], r10
mov    qword ptr [rsp+88], r11

;# T4 ← X3 - Z3
sub    rax, qword ptr [rsp+256]
sbb    rbx, qword ptr [rsp+264]
sbb    rbp, qword ptr [rsp+272]
sbb    rsi, qword ptr [rsp+280]
mov    rdi, 0
mov    rcx, 38
cmovae rcx, rdi
sub    rax, rcx
sbb    rbx, rdi
sbb    rbp, rdi
sbb    rsi, rdi
cmovb  rdi, rcx
sub    rax, rdi
mov    qword ptr [rsp+96], rax
mov    qword ptr [rsp+104], rbx
mov    qword ptr [rsp+112], rbp
mov    qword ptr [rsp+120], rsi

;# Z3 ← T2 · T3
mov    rax, qword ptr [rsp+40]
mul    qword ptr [rsp+88]
mov    r8, rax
xor    r9, r9
mov    r10, rdx
xor    r11, r11
mov    rax, qword ptr [rsp+48]
mul    qword ptr [rsp+80]
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, qword ptr [rsp+56]
mul    qword ptr [rsp+72]
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, qword ptr [rsp+48]
mul    qword ptr [rsp+88]
add    r10, rax
adc    r11, 0
mov    r12, rdx
xor    r13, r13
mov    rax, qword ptr [rsp+56]
mul    qword ptr [rsp+80]
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, 38
mul    r10
imul   r11, r11, 38
mov    r10, rax
add    r11, rdx
mov    rax, qword ptr [rsp+56]
mul    qword ptr [rsp+88]
add    r12, rax
adc    r13, 0
mov    rax, 38
mul    rdx
mov    r14, rax
mov    r15, rdx
mov    rax, 38
mul    r12
imul   r13, r13, 38
mov    r12, rax
add    r13, rdx
mov    rax, qword ptr [rsp+32]
mul    qword ptr [rsp+88]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, qword ptr [rsp+40]
mul    qword ptr [rsp+80]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, qword ptr [rsp+48]
mul    qword ptr [rsp+72]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, qword ptr [rsp+56]
mul    qword ptr [rsp+64]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, 38
mul    r8
imul   r9, r9, 38
mov    r8, rax
add    r9, rdx
mov    rax, qword ptr [rsp+32]
mul    qword ptr [rsp+64]
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, qword ptr [rsp+32]
mul    qword ptr [rsp+72]
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, qword ptr [rsp+40]
mul    qword ptr [rsp+64]
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, qword ptr [rsp+32]
mul    qword ptr [rsp+80]
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
mov    rax, qword ptr [rsp+40]
mul    qword ptr [rsp+72]
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
mov    rax, qword ptr [rsp+48]
mul    qword ptr [rsp+64]
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
add    r10, r9
adc    r11, 0
add    r12, r11
adc    r13, 0
add    r14, r13
adc    r15, 0
shld   r15, r14, 1
btr    r14, 63
imul   r15, r15, 19
add    r8, r15
adc    r10, 0
adc    r12, 0
adc    r14, 0
mov    qword ptr [rsp+256], r8
mov    qword ptr [rsp+264], r10
mov    qword ptr [rsp+272], r12
mov    qword ptr [rsp+280], r14

;# X3 ← T1 · T4
mov    rax, qword ptr [rsp+8]
mul    qword ptr [rsp+120]
mov    r8, rax
xor    r9, r9
mov    r10, rdx
xor    r11, r11
mov    rax, qword ptr [rsp+16]
mul    qword ptr [rsp+112]
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, qword ptr [rsp+24]
mul    qword ptr [rsp+104]
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, qword ptr [rsp+16]
mul    qword ptr [rsp+120]
add    r10, rax
adc    r11, 0
mov    r12, rdx
xor    r13, r13
mov    rax, qword ptr [rsp+24]
mul    qword ptr [rsp+112]
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, 38
mul    r10
imul   r11, r11, 38
mov    r10, rax
add    r11, rdx
mov    rax, qword ptr [rsp+24]
mul    qword ptr [rsp+120]
add    r12, rax
adc    r13, 0
mov    rax, 38
mul    rdx
mov    r14, rax
mov    r15, rdx
mov    rax, 38
mul    r12
imul   r13, r13, 38
mov    r12, rax
add    r13, rdx
mov    rax, qword ptr [rsp+0]
mul    qword ptr [rsp+120]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, qword ptr [rsp+8]
mul    qword ptr [rsp+112]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, qword ptr [rsp+16]
mul    qword ptr [rsp+104]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, qword ptr [rsp+24]
mul    qword ptr [rsp+96]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, 38
mul    r8
imul   r9, r9, 38
mov    r8, rax
add    r9, rdx
mov    rax, qword ptr [rsp+0]
mul    qword ptr [rsp+96]
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, qword ptr [rsp+0]
mul    qword ptr [rsp+104]
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, qword ptr [rsp+8]
mul    qword ptr [rsp+96]
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, qword ptr [rsp+0]
mul    qword ptr [rsp+112]
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
mov    rax, qword ptr [rsp+8]
mul    qword ptr [rsp+104]
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
mov    rax, qword ptr [rsp+16]
mul    qword ptr [rsp+96]
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
add    r10, r9
adc    r11, 0
add    r12, r11
adc    r13, 0
add    r14, r13
adc    r15, 0
shld   r15, r14, 1
btr    r14, 63
imul   r15, r15, 19
add    r8, r15
adc    r10, 0
adc    r12, 0
adc    r14, 0
mov    qword ptr [rsp+192], r8
mov    qword ptr [rsp+200], r10
mov    qword ptr [rsp+208], r12
mov    qword ptr [rsp+216], r14

movzx  ecx, byte ptr [rsp+352]
movzx  ebx, byte ptr [rsp+354]
shr    bl, cl
and    bl, 1
mov    cl, bl
xor    bl, byte ptr [rsp+353]
mov    byte ptr [rsp+353], cl
cmp    bl, 1

;# CSelect(T1,T3,select)
mov    r8, qword ptr [rsp+0]
mov    r9, qword ptr [rsp+8]
mov    r10, qword ptr [rsp+16]
mov    r11, qword ptr [rsp+24]
mov    r12, qword ptr [rsp+64]
mov    r13, qword ptr [rsp+72]
mov    r14, qword ptr [rsp+80]
mov    r15, qword ptr [rsp+88]
cmove  r8, r12
cmove  r9, r13
cmove  r10, r14
cmove  r11, r15
mov    qword ptr [rsp+0], r8
mov    qword ptr [rsp+8], r9
mov    qword ptr [rsp+16], r10
mov    qword ptr [rsp+24], r11

;# CSelect(T2,T4,select)
mov    rbx, qword ptr [rsp+32]
mov    rbp, qword ptr [rsp+40]
mov    rcx, qword ptr [rsp+48]
mov    rsi, qword ptr [rsp+56]
mov    r12, qword ptr [rsp+96]
mov    r13, qword ptr [rsp+104]
mov    r14, qword ptr [rsp+112]
mov    r15, qword ptr [rsp+120]
cmove  rbx, r12
cmove  rbp, r13
cmove  rcx, r14
cmove  rsi, r15

;# T2 ← T2^2
mov    rax, rsi
mul    rsi
mov    r12, rax
xor    r13, r13
mov    rax, 38
mul    rdx
mov    r14, rax
mov    r15, rdx
mov    rax, rbp
mul    rsi
mov    r8, rax
xor    r9, r9
mov    r10, rdx
xor    r11, r11
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, rcx
mul    rcx
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, rcx
mul    rsi
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, 38
mul    r10
imul   r11, r11, 38
mov    r10, rax
add    r11, rdx
mov    rax, 38
mul    r12
imul   r13, r13, 38
mov    r12, rax
add    r13, rdx
mov    rax, rbx
mul    rsi
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, rbp
mul    rcx
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, 38
mul    r8
imul   r9, r9, 38
mov    r8, rax
add    r9, rdx
mov    rax, rbx
mul    rbx
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, rbx
mul    rbp
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, rbx
mul    rcx
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
mov    rax, rbp
mul    rbp
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
add    r10, r9
adc    r11, 0
add    r12, r11
adc    r13, 0
add    r14, r13
adc    r15, 0
shld   r15, r14, 1
imul   r15, r15, 19
btr    r14, 63
add    r8, r15
adc    r10, 0
adc    r12, 0
adc    r14, 0
mov    qword ptr [rsp+32], r8
mov    qword ptr [rsp+40], r10
mov    qword ptr [rsp+48], r12
mov    qword ptr [rsp+56], r14

;# T1 ← T1^2
mov    rbx, qword ptr [rsp+0]
mov    rbp, qword ptr [rsp+8]
mov    rcx, qword ptr [rsp+16]
mov    rsi, qword ptr [rsp+24]
mov    rax, rsi
mul    rsi
mov    r12, rax
xor    r13, r13
mov    rax, 38
mul    rdx
mov    r14, rax
mov    r15, rdx
mov    rax, rbp
mul    rsi
mov    r8, rax
xor    r9, r9
mov    r10, rdx
xor    r11, r11
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, rcx
mul    rcx
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, rcx
mul    rsi
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, 38
mul    r10
imul   r11, r11, 38
mov    r10, rax
add    r11, rdx
mov    rax, 38
mul    r12
imul   r13, r13, 38
mov    r12, rax
add    r13, rdx
mov    rax, rbx
mul    rsi
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, rbp
mul    rcx
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, 38
mul    r8
imul   r9, r9, 38
mov    r8, rax
add    r9, rdx
mov    rax, rbx
mul    rbx
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, rbx
mul    rbp
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, rbx
mul    rcx
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
mov    rax, rbp
mul    rbp
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
add    r10, r9
adc    r11, 0
add    r12, r11
adc    r13, 0
add    r14, r13
adc    r15, 0
shld   r15, r14, 1
imul   r15, r15, 19
btr    r14, 63
add    r8, r15
adc    r10, 0
adc    r12, 0
adc    r14, 0
mov    qword ptr [rsp+0], r8
mov    qword ptr [rsp+8], r10
mov    qword ptr [rsp+16], r12
mov    qword ptr [rsp+24], r14

;# X3
mov    r8, qword ptr [rsp+192]
mov    r9, qword ptr [rsp+200]
mov    r10, qword ptr [rsp+208]
mov    r11, qword ptr [rsp+216]

;# copy X3
mov    rbx, r8
mov    rbp, r9
mov    rcx, r10
mov    rsi, r11

;# X3 ← X3 + Z3
add    r8, qword ptr [rsp+256]
adc    r9, qword ptr [rsp+264]
adc    r10, qword ptr [rsp+272]
adc    r11, qword ptr [rsp+280]
mov    rax, 0
mov    rdx, 38
cmovae rdx, rax
add    r8, rdx
adc    r9, rax
adc    r10, rax
adc    r11, rax
cmovb  rax, rdx
add    r8, rax
mov    qword ptr [rsp+192], r8
mov    qword ptr [rsp+200], r9
mov    qword ptr [rsp+208], r10
mov    qword ptr [rsp+216], r11

;# Z3 ← X3 - Z3
sub    rbx, qword ptr [rsp+256]
sbb    rbp, qword ptr [rsp+264]
sbb    rcx, qword ptr [rsp+272]
sbb    rsi, qword ptr [rsp+280]
mov    rax, 0
mov    rdx, 38
cmovae rdx, rax
sub    rbx, rdx
sbb    rbp, rax
sbb    rcx, rax
sbb    rsi, rax
cmovb  rax, rdx
sub    rbx, rax

;# Z3 ← Z3^2
mov    rax, rsi
mul    rsi
mov    r12, rax
xor    r13, r13
mov    rax, 38
mul    rdx
mov    r14, rax
mov    r15, rdx
mov    rax, rbp
mul    rsi
mov    r8, rax
xor    r9, r9
mov    r10, rdx
xor    r11, r11
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, rcx
mul    rcx
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, rcx
mul    rsi
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, 38
mul    r10
imul   r11, r11, 38
mov    r10, rax
add    r11, rdx
mov    rax, 38
mul    r12
imul   r13, r13, 38
mov    r12, rax
add    r13, rdx
mov    rax, rbx
mul    rsi
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, rbp
mul    rcx
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, 38
mul    r8
imul   r9, r9, 38
mov    r8, rax
add    r9, rdx
mov    rax, rbx
mul    rbx
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, rbx
mul    rbp
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, rbx
mul    rcx
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
mov    rax, rbp
mul    rbp
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
add    r10, r9
adc    r11, 0
add    r12, r11
adc    r13, 0
add    r14, r13
adc    r15, 0
shld   r15, r14, 1
imul   r15, r15, 19
btr    r14, 63
add    r8, r15
adc    r10, 0
adc    r12, 0
adc    r14, 0
mov    qword ptr [rsp+256], r8
mov    qword ptr [rsp+264], r10
mov    qword ptr [rsp+272], r12
mov    qword ptr [rsp+280], r14

;# X3 ← X3^2
mov    rbx, qword ptr [rsp+192]
mov    rbp, qword ptr [rsp+200]
mov    rcx, qword ptr [rsp+208]
mov    rsi, qword ptr [rsp+216]
mov    rax, rsi
mul    rsi
mov    r12, rax
xor    r13, r13
mov    rax, 38
mul    rdx
mov    r14, rax
mov    r15, rdx
mov    rax, rbp
mul    rsi
mov    r8, rax
xor    r9, r9
mov    r10, rdx
xor    r11, r11
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, rcx
mul    rcx
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, rcx
mul    rsi
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, 38
mul    r10
imul   r11, r11, 38
mov    r10, rax
add    r11, rdx
mov    rax, 38
mul    r12
imul   r13, r13, 38
mov    r12, rax
add    r13, rdx
mov    rax, rbx
mul    rsi
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, rbp
mul    rcx
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, 38
mul    r8
imul   r9, r9, 38
mov    r8, rax
add    r9, rdx
mov    rax, rbx
mul    rbx
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, rbx
mul    rbp
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, rbx
mul    rcx
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
mov    rax, rbp
mul    rbp
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
add    r10, r9
adc    r11, 0
add    r12, r11
adc    r13, 0
add    r14, r13
adc    r15, 0
shld   r15, r14, 1
imul   r15, r15, 19
btr    r14, 63
add    r8, r15
adc    r10, 0
adc    r12, 0
adc    r14, 0

;# update X3
mov    qword ptr [rsp+192], r8
mov    qword ptr [rsp+200], r10
mov    qword ptr [rsp+208], r12
mov    qword ptr [rsp+216], r14

;# T3 ← T1 - T2
mov    rbx, qword ptr [rsp+0]
mov    rbp, qword ptr [rsp+8]
mov    rcx, qword ptr [rsp+16]
mov    rsi, qword ptr [rsp+24]
sub    rbx, qword ptr [rsp+32]
sbb    rbp, qword ptr [rsp+40]
sbb    rcx, qword ptr [rsp+48]
sbb    rsi, qword ptr [rsp+56]
mov    rax, 0
mov    rdx, 38
cmovae rdx, rax
sub    rbx, rdx
sbb    rbp, rax
sbb    rcx, rax
sbb    rsi, rax
cmovb  rax, rdx
sub    rbx, rax
mov    qword ptr [rsp+64], rbx
mov    qword ptr [rsp+72], rbp
mov    qword ptr [rsp+80], rcx
mov    qword ptr [rsp+88], rsi

;# T4 ← ((A + 2)/4) · T3
mov    rax, 121666
mov    rdi, rax
mul    rbx
mov    rbx, rax
mov    r8, rdx
mov    rax, rdi
mul    rbp
mov    rbp, rax
mov    r9, rdx
mov    rax, rdi
mul    rcx
mov    rcx, rax
mov    r10, rdx
xor    r11, r11
mov    rax, rdi
mul    rsi
mov    rsi, rax
add    rbp, r8
adc    rcx, r9
adc    rsi, r10
adc    r11, rdx
shld   r11, rsi, 1
btr    rsi, 63
imul   r11, r11, 19
add    rbx, r11
adc    rbp, 0
adc    rcx, 0
adc    rsi, 0

;# T4 ← T4 + T2
add    rbx, qword ptr [rsp+32]
adc    rbp, qword ptr [rsp+40]
adc    rcx, qword ptr [rsp+48]
adc    rsi, qword ptr [rsp+56]
mov    rax, 0
mov    rdx, 38
cmovae rdx, rax
add    rbx, rdx
adc    rbp, rax
adc    rcx, rax
adc    rsi, rax
cmovb  rax, rdx
add    rbx, rax
mov    qword ptr [rsp+96], rbx
mov    qword ptr [rsp+104], rbp
mov    qword ptr [rsp+112], rcx
mov    qword ptr [rsp+120], rsi

;# X2 ← T1 · T2
mov    rax, qword ptr [rsp+8]
mul    qword ptr [rsp+56]
mov    r8, rax
xor    r9, r9
mov    r10, rdx
xor    r11, r11
mov    rax, qword ptr [rsp+16]
mul    qword ptr [rsp+48]
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, qword ptr [rsp+24]
mul    qword ptr [rsp+40]
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, qword ptr [rsp+16]
mul    qword ptr [rsp+56]
add    r10, rax
adc    r11, 0
mov    r12, rdx
xor    r13, r13
mov    rax, qword ptr [rsp+24]
mul    qword ptr [rsp+48]
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, 38
mul    r10
imul   r11, r11, 38
mov    r10, rax
add    r11, rdx
mov    rax, qword ptr [rsp+24]
mul    qword ptr [rsp+56]
add    r12, rax
adc    r13, 0
mov    rax, 38
mul    rdx
mov    r14, rax
mov    r15, rdx
mov    rax, 38
mul    r12
imul   r13, r13, 38
mov    r12, rax
add    r13, rdx
mov    rax, qword ptr [rsp+0]
mul    qword ptr [rsp+56]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, qword ptr [rsp+8]
mul    qword ptr [rsp+48]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, qword ptr [rsp+16]
mul    qword ptr [rsp+40]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, qword ptr [rsp+24]
mul    qword ptr [rsp+32]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, 38
mul    r8
imul   r9, r9, 38
mov    r8, rax
add    r9, rdx
mov    rax, qword ptr [rsp+0]
mul    qword ptr [rsp+32]
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, qword ptr [rsp+0]
mul    qword ptr [rsp+40]
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, qword ptr [rsp+8]
mul    qword ptr [rsp+32]
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, qword ptr [rsp+0]
mul    qword ptr [rsp+48]
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
mov    rax, qword ptr [rsp+8]
mul    qword ptr [rsp+40]
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
mov    rax, qword ptr [rsp+16]
mul    qword ptr [rsp+32]
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
add    r10, r9
adc    r11, 0
add    r12, r11
adc    r13, 0
add    r14, r13
adc    r15, 0
shld   r15, r14, 1
btr    r14, 63
imul   r15, r15, 19
add    r8, r15
adc    r10, 0
adc    r12, 0
adc    r14, 0

;# update X2
mov    qword ptr [rsp+160], r8
mov    qword ptr [rsp+168], r10
mov    qword ptr [rsp+176], r12
mov    qword ptr [rsp+184], r14

;# Z2 ← T3 · T4
mov    rax, qword ptr [rsp+72]
mul    qword ptr [rsp+120]
mov    r8, rax
xor    r9, r9
mov    r10, rdx
xor    r11, r11
mov    rax, qword ptr [rsp+80]
mul    qword ptr [rsp+112]
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, qword ptr [rsp+88]
mul    qword ptr [rsp+104]
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, qword ptr [rsp+80]
mul    qword ptr [rsp+120]
add    r10, rax
adc    r11, 0
mov    r12, rdx
xor    r13, r13
mov    rax, qword ptr [rsp+88]
mul    qword ptr [rsp+112]
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, 38
mul    r10
imul   r11, r11, 38
mov    r10, rax
add    r11, rdx
mov    rax, qword ptr [rsp+88]
mul    qword ptr [rsp+120]
add    r12, rax
adc    r13, 0
mov    rax, 38
mul    rdx
mov    r14, rax
mov    r15, rdx
mov    rax, 38
mul    r12
imul   r13, r13, 38
mov    r12, rax
add    r13, rdx
mov    rax, qword ptr [rsp+64]
mul    qword ptr [rsp+120]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, qword ptr [rsp+72]
mul    qword ptr [rsp+112]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, qword ptr [rsp+80]
mul    qword ptr [rsp+104]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, qword ptr [rsp+88]
mul    qword ptr [rsp+96]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, 38
mul    r8
imul   r9, r9, 38
mov    r8, rax
add    r9, rdx
mov    rax, qword ptr [rsp+64]
mul    qword ptr [rsp+96]
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, qword ptr [rsp+64]
mul    qword ptr [rsp+104]
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, qword ptr [rsp+72]
mul    qword ptr [rsp+96]
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, qword ptr [rsp+64]
mul    qword ptr [rsp+112]
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
mov    rax, qword ptr [rsp+72]
mul    qword ptr [rsp+104]
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
mov    rax, qword ptr [rsp+80]
mul    qword ptr [rsp+96]
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
add    r10, r9
adc    r11, 0
add    r12, r11
adc    r13, 0
add    r14, r13
adc    r15, 0
shld   r15, r14, 1
btr    r14, 63
imul   r15, r15, 19
add    r8, r15
adc    r10, 0
adc    r12, 0
adc    r14, 0

;# update Z2
mov    qword ptr [rsp+224], r8
mov    qword ptr [rsp+232], r10
mov    qword ptr [rsp+240], r12
mov    qword ptr [rsp+248], r14

;# Z3 ← Z3 · X1
mov    rax, qword ptr [rsp+136]
mul    qword ptr [rsp+280]
mov    r8, rax
xor    r9, r9
mov    r10, rdx
xor    r11, r11
mov    rax, qword ptr [rsp+144]
mul    qword ptr [rsp+272]
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, qword ptr [rsp+152]
mul    qword ptr [rsp+264]
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, qword ptr [rsp+144]
mul    qword ptr [rsp+280]
add    r10, rax
adc    r11, 0
mov    r12, rdx
xor    r13, r13
mov    rax, qword ptr [rsp+152]
mul    qword ptr [rsp+272]
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, 38
mul    r10
imul   r11, r11, 38
mov    r10, rax
add    r11, rdx
mov    rax, qword ptr [rsp+152]
mul    qword ptr [rsp+280]
add    r12, rax
adc    r13, 0
mov    rax, 38
mul    rdx
mov    r14, rax
mov    r15, rdx
mov    rax, 38
mul    r12
imul   r13, r13, 38
mov    r12, rax
add    r13, rdx
mov    rax, qword ptr [rsp+128]
mul    qword ptr [rsp+280]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, qword ptr [rsp+136]
mul    qword ptr [rsp+272]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, qword ptr [rsp+144]
mul    qword ptr [rsp+264]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, qword ptr [rsp+152]
mul    qword ptr [rsp+256]
add    r14, rax
adc    r15, 0
add    r8, rdx
adc    r9, 0
mov    rax, 38
mul    r8
imul   r9, r9, 38
mov    r8, rax
add    r9, rdx
mov    rax, qword ptr [rsp+128]
mul    qword ptr [rsp+256]
add    r8, rax
adc    r9, 0
add    r10, rdx
adc    r11, 0
mov    rax, qword ptr [rsp+128]
mul    qword ptr [rsp+264]
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, qword ptr [rsp+136]
mul    qword ptr [rsp+256]
add    r10, rax
adc    r11, 0
add    r12, rdx
adc    r13, 0
mov    rax, qword ptr [rsp+128]
mul    qword ptr [rsp+272]
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
mov    rax, qword ptr [rsp+136]
mul    qword ptr [rsp+264]
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
mov    rax, qword ptr [rsp+144]
mul    qword ptr [rsp+256]
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
add    r10, r9
adc    r11, 0
add    r12, r11
adc    r13, 0
add    r14, r13
adc    r15, 0
shld   r15, r14, 1
btr    r14, 63
imul   r15, r15, 19
add    r8, r15
adc    r10, 0
adc    r12, 0
adc    r14, 0

;# update Z3
mov    qword ptr [rsp+256], r8
mov    qword ptr [rsp+264], r10
mov    qword ptr [rsp+272], r12
mov    qword ptr [rsp+280], r14

movzx  ecx, byte ptr [rsp+352]
sub    ecx, 1
mov    byte ptr [rsp+352], cl
;cmp    cl, 0
jge    loop_bit

mov    byte ptr [rsp+352], 7
lea    rsi, [rsp+360]
mov    eax, dword ptr [rsp+356]
sub    eax, 1
mov    dword ptr [rsp+356], eax
;cmp    eax, 0
jge    loop_byte

;# remove the private key from the stack
mov    qword ptr [rsi], 0
mov    qword ptr [rsi+8], 0
mov    qword ptr [rsi+16], 0
mov    qword ptr [rsi+24], 0

;# result ← X2 · Z2^(-1)

;# result in: r8, r9, r10, r11
;# Stack variables:
;# 0   T0
;# 32  T1
;# 64  T2
;# 96  T3
;# 128 T4
;# 352 invtable position (4 bytes)

;# load result ← Z2
mov    r8, qword ptr [rsp+224]
mov    r9, qword ptr [rsp+232]
mov    r10, qword ptr [rsp+240]
mov    r11, qword ptr [rsp+248]

;# T0 ← X2
mov    r12, qword ptr [rsp+160]
mov    qword ptr [rsp+0], r12
mov    r12, qword ptr [rsp+168]
mov    qword ptr [rsp+8], r12
mov    r12, qword ptr [rsp+176]
mov    qword ptr [rsp+16], r12
mov    r12, qword ptr [rsp+184]
mov    qword ptr [rsp+24], r12

;# T2 ← Z2
mov    qword ptr [rsp+64], r8
mov    qword ptr [rsp+72], r9
mov    qword ptr [rsp+80], r10
mov    qword ptr [rsp+88], r11

mov    dword ptr [rsp+352], 0
lea    r12, [invtable+REG_REL]

inv_loop:
;# ecx = current instruction
mov    ecx, dword ptr [r12]
test   cl, cl
jz     skip_square

square_loop:
mov    rax, r11
mul    r11
mov    r12, rax
xor    r13, r13
mov    rax, 38
mul    rdx
mov    r14, rax
mov    r15, rdx
shl    r11, 1
mov    rax, r9
mul    r11
mov    rbx, rax
xor    rbp, rbp
mov    rdi, rdx
xor    rsi, rsi
mov    rax, r10
mul    r10
add    rbx, rax
adc    rbp, 0
add    rdi, rdx
adc    rsi, 0
mov    rax, r10
mul    r11
add    rdi, rax
adc    rsi, 0
add    r12, rdx
adc    r13, 0
mov    rax, 38
mul    rdi
imul   rsi, rsi, 38
mov    rdi, rax
add    rsi, rdx
mov    rax, 38
mul    r12
imul   r13, r13, 38
mov    r12, rax
add    r13, rdx
mov    rax, r8
mul    r11
add    r14, rax
adc    r15, 0
add    rbx, rdx
adc    rbp, 0
mov    rax, r9
mul    r10
add    r14, rax
adc    r15, 0
add    rbx, rdx
adc    rbp, 0
add    r14, rax
adc    r15, 0
add    rbx, rdx
adc    rbp, 0
mov    rax, 38
mul    rbx
imul   rbp, rbp, 38
mov    rbx, rax
add    rbp, rdx
mov    rax, r8
mul    r8
add    rbx, rax
adc    rbp, 0
add    rdi, rdx
adc    rsi, 0
mov    rax, r8
mul    r9
add    rdi, rax
adc    rsi, 0
add    r12, rdx
adc    r13, 0
add    rdi, rax
adc    rsi, 0
add    r12, rdx
adc    r13, 0
mov    rax, r8
mul    r10
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
mov    rax, r9
mul    r9
add    r12, rax
adc    r13, 0
add    r14, rdx
adc    r15, 0
mov    r9, rdi
add    r9, rbp
adc    rsi, 0
mov    r10, r12
add    r10, rsi
adc    r13, 0
mov    r11, r14
add    r11, r13
adc    r15, 0
shld   r15, r11, 1
imul   r15, r15, 19
btr    r11, 63
add    rbx, r15
adc    r9, 0
adc    r10, 0
adc    r11, 0
mov    r8, 0
adc    r8, 0
shld   r8, r11, 1
btr    r11, 63
imul   r8, r8, 19
add    r8, rbx
sub    cl, 1
jnz    square_loop

skip_square:
shr    ecx, 8
test   cl, cl
jnz    skip_mul

;# T4 ← result
lea    rbx, [rsp+128]
mov    qword ptr [rbx], r8
mov    qword ptr [rbx+8], r9
mov    qword ptr [rbx+16], r10
mov    qword ptr [rbx+24], r11

movzx  edi, ch ;# mul_source
shl    edi, 5
add    rdi, rsp

;# result ← T4 · mul_source
mov    rax, qword ptr [rbx+8]
mul    qword ptr [rdi+24]
mov    r8, rax
xor    esi, esi
mov    r9, rdx
xor    ebp, ebp
mov    rax, qword ptr [rbx+16]
mul    qword ptr [rdi+16]
add    r8, rax
adc    rsi, 0
add    r9, rdx
adc    rbp, 0
mov    rax, qword ptr [rbx+24]
mul    qword ptr [rdi+8]
add    r8, rax
adc    rsi, 0
add    r9, rdx
adc    rbp, 0
mov    rax, qword ptr [rbx+16]
mul    qword ptr [rdi+24]
add    r9, rax
adc    rbp, 0
mov    r10, rdx
xor    r13, r13
mov    rax, qword ptr [rbx+24]
mul    qword ptr [rdi+16]
add    r9, rax
adc    rbp, 0
add    r10, rdx
adc    r13, 0
mov    rax, 38
mul    r9
imul   rbp, rbp, 38
mov    r9, rax
add    rbp, rdx
mov    rax, qword ptr [rbx+24]
mul    qword ptr [rdi+24]
add    r10, rax
adc    r13, 0
mov    rax, 38
mul    rdx
mov    r11, rax
mov    r15, rdx
mov    rax, 38
mul    r10
imul   r13, r13, 38
mov    r10, rax
add    r13, rdx
mov    rax, qword ptr [rbx]
mul    qword ptr [rdi+24]
add    r11, rax
adc    r15, 0
add    r8, rdx
adc    rsi, 0
mov    rax, qword ptr [rbx+8]
mul    qword ptr [rdi+16]
add    r11, rax
adc    r15, 0
add    r8, rdx
adc    rsi, 0
mov    rax, qword ptr [rbx+16]
mul    qword ptr [rdi+8]
add    r11, rax
adc    r15, 0
add    r8, rdx
adc    rsi, 0
mov    rax, qword ptr [rbx+24]
mul    qword ptr [rdi]
add    r11, rax
adc    r15, 0
add    r8, rdx
adc    rsi, 0
mov    rax, 38
mul    r8
imul   rsi, rsi, 38
mov    r8, rax
add    rsi, rdx
mov    rax, qword ptr [rbx]
mul    qword ptr [rdi]
add    r8, rax
adc    rsi, 0
add    r9, rdx
adc    rbp, 0
mov    rax, qword ptr [rbx]
mul    qword ptr [rdi+8]
add    r9, rax
adc    rbp, 0
add    r10, rdx
adc    r13, 0
mov    rax, qword ptr [rbx+8]
mul    qword ptr [rdi]
add    r9, rax
adc    rbp, 0
add    r10, rdx
adc    r13, 0
mov    rax, qword ptr [rbx]
mul    qword ptr [rdi+16]
add    r10, rax
adc    r13, 0
add    r11, rdx
adc    r15, 0
mov    rax, qword ptr [rbx+8]
mul    qword ptr [rdi+8]
add    r10, rax
adc    r13, 0
add    r11, rdx
adc    r15, 0
mov    rax, qword ptr [rbx+16]
mul    qword ptr [rdi]
add    r10, rax
adc    r13, 0
add    r11, rdx
adc    r15, 0
add    r9, rsi
adc    rbp, 0
add    r10, rbp
adc    r13, 0
add    r11, r13
adc    r15, 0
shld   r15, r11, 1
btr    r11, 63
imul   r15, r15, 19
add    r8, r15
adc    r9, 0
adc    r10, 0
adc    r11, 0

skip_mul:
shr    ecx, 11
jz     skip_store

add    rcx, rsp

;# store temp T[1-3]
mov    qword ptr [rcx], r8
mov    qword ptr [rcx+8], r9
mov    qword ptr [rcx+16], r10
mov    qword ptr [rcx+24], r11

skip_store:
mov    eax, dword ptr [rsp+352]
add    eax, 4
lea    r12, [invtable+REG_REL]
add    r12, rax
mov    dword ptr [rsp+352], eax

cmp   eax, 52
jb    inv_loop

;# final reduction

xor    r12, r12
btr    r11, 63
adc    r12, 0
imul   r12, r12, 19
add    r8, r12
adc    r9, 0

mov    rax, r8
mov    rcx, r9
mov    rdx, r10
mov    rsi, r11
sub    r8, qword ptr [p0+REG_REL]
sbb    r9, qword ptr [p12+REG_REL]
sbb    r10, qword ptr [p12+REG_REL]
sbb    r11, qword ptr [p3+REG_REL]
bt     r11, 63
cmovb  r8, rax
cmovb  r9, rcx
cmovb  r10, rdx
cmovb  r11, rsi

mov    rdi, qword ptr [rsp+304]

;# output the result
mov    qword ptr [rdi], r8
mov    qword ptr [rdi+8], r9
mov    qword ptr [rdi+16], r10
mov    qword ptr [rdi+24], r11

;# restore registers
mov    rbx, qword ptr [rsp+288]
mov    rbp, qword ptr [rsp+296]
;# mov    rdi, qword ptr [rsp+304]
;# mov    rsi, qword ptr [rsp+312]
mov    r12, qword ptr [rsp+320]
mov    r13, qword ptr [rsp+328]
mov    r14, qword ptr [rsp+336]
mov    r15, qword ptr [rsp+344]

add    rsp, 392
