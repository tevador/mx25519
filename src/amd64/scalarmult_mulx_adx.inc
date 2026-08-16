;# Copyright (c) 2022-2026 tevador <tevador@gmail.com>
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
;#     rcx -> lo byte clamping mask
;#     r8  -> hi byte clamping mask

;# 32-byte align rsp
mov r11, rsp
and r11, 31
add r11, 416
sub rsp, r11
add r11, 384 ;# the secondary stack frame size is stored in r11

;# [primary stack frame]
;# (offsets from rsp)
;# 416 alignment
;# 352 saved registers: rbx, rbp, rdi, r11, r12, r13, r14, r15
;# 320 private key
;# 312 key byte index (4 bytes)
;# 306 current key byte value (1 byte)
;# 305 swap flag (1 byte)
;# 304 key bit index (1 byte)
;# 256 Z3
;# 224 Z2
;# 192 X3
;# 160 X2
;# 128 X1
;# 96 T4
;# 64 T3
;# 32 T2
;# 0 T1

mov    qword ptr [rsp+352], rbx
mov    qword ptr [rsp+360], rbp
mov    qword ptr [rsp+368], rdi
mov    qword ptr [rsp+376], r11
mov    qword ptr [rsp+384], r12
mov    qword ptr [rsp+392], r13
mov    qword ptr [rsp+400], r14
mov    qword ptr [rsp+408], r15

;# copy the private key and clamp it
shl    r8, 56
or     rcx, -8
mov    r9, qword ptr [rsi+24]
or     r9, r8
mov    qword ptr [rsp+344], r9
mov    r8, qword ptr [rsi]
and    r8, rcx
mov    qword ptr [rsp+320], r8
mov    r8, qword ptr [rsi+8]
mov    qword ptr [rsp+328], r8
mov    r8, qword ptr [rsi+16]
mov    qword ptr [rsp+336], r8

;# starting from bit 6 of the 31st byte
mov    eax, 31
mov    byte ptr [rsp+304], 6
mov    byte ptr [rsp+305], 0
mov    dword ptr [rsp+312], eax
lea    rsi, [rsp+320]

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

ALIGN 16
loop_byte_x:

;# rsi = private key address
;# eax = key byte index
movzx  ecx, byte ptr [rsi+rax]
mov    byte ptr [rsp+306], cl

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

ALIGN 16
loop_bit_x:

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
mov    edi, 0
mov    rcx, 38
cmovae rcx, rdi
sub    rax, rcx
sbb    rbx, 0
sbb    rbp, 0
sbb    rsi, 0
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
mov    edi, 0
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
mov    edi, 0
mov    rcx, 38
cmovae rcx, rdi
sub    rax, rcx
sbb    rbx, 0
sbb    rbp, 0
sbb    rsi, 0
cmovb  rdi, rcx
sub    rax, rdi
mov    qword ptr [rsp+96], rax
mov    qword ptr [rsp+104], rbx
mov    qword ptr [rsp+112], rbp
mov    qword ptr [rsp+120], rsi

;# Z3 ← T2 · T3
xor    r13d, r13d
mov    rdx, qword ptr [rsp+32]
mulx   r9, r8, qword ptr [rsp+64]
mulx   r10, rcx, qword ptr [rsp+72]
adcx   r9, rcx
mulx   r11, rcx, qword ptr [rsp+80]
adcx   r10, rcx
mulx   r12, rcx, qword ptr [rsp+88]
adcx   r11, rcx
adcx   r12, r13
xor    r14d, r14d
mov    rdx, qword ptr [rsp+40]
mulx   rbp, rcx, qword ptr [rsp+64]
adcx   r9, rcx
adox   r10, rbp
mulx   rbp, rcx, qword ptr [rsp+72]
adcx   r10, rcx
adox   r11, rbp
mulx   rbp, rcx, qword ptr [rsp+80]
adcx   r11, rcx
adox   r12, rbp
mulx   rbp, rcx, qword ptr [rsp+88]
adcx   r12, rcx
adox   r13, rbp
adcx   r13, r14
xor    r15d, r15d
mov    rdx, qword ptr [rsp+48]
mulx   rbp, rcx, qword ptr [rsp+64]
adcx   r10, rcx
adox   r11, rbp
mulx   rbp, rcx, qword ptr [rsp+72]
adcx   r11, rcx
adox   r12, rbp
mulx   rbp, rcx, qword ptr [rsp+80]
adcx   r12, rcx
adox   r13, rbp
mulx   rbp, rcx, qword ptr [rsp+88]
adcx   r13, rcx
adox   r14, rbp
adcx   r14, r15
xor    eax, eax
mov    rdx, qword ptr [rsp+56]
mulx   rbp, rcx, qword ptr [rsp+64]
adcx   r11, rcx
adox   r12, rbp
mulx   rbp, rcx, qword ptr [rsp+72]
adcx   r12, rcx
adox   r13, rbp
mulx   rbp, rcx, qword ptr [rsp+80]
adcx   r13, rcx
adox   r14, rbp
mulx   rbp, rcx, qword ptr [rsp+88]
adcx   r14, rcx
adox   r15, rbp
adcx   r15, rax
xor    ebp, ebp
mov    rdx, 38
mulx   r12, rax, r12
adcx   r8, rax
adox   r9, r12
mulx   r13, rcx, r13
adcx   r9, rcx
adox   r10, r13
mulx   r14, rcx, r14
adcx   r10, rcx
adox   r11, r14
mulx   r15, rcx, r15
adcx   r11, rcx
adox   r15, rbp ;# zero
adcx   r15, rbp ;# zero
shld   r15, r11, 1
btr    r11, 63
imul   r15, r15, 19
add    r8, r15
adc    r9, 0
adc    r10, 0
adc    r11, 0
mov    qword ptr [rsp+256], r8
mov    qword ptr [rsp+264], r9
mov    qword ptr [rsp+272], r10
mov    qword ptr [rsp+280], r11

;# X3 ← T1 · T4
xor    r13d, r13d
mov    rdx, qword ptr [rsp+0]
mulx   r9, r8, qword ptr [rsp+96]
mulx   r10, rcx, qword ptr [rsp+104]
adcx   r9, rcx
mulx   r11, rcx, qword ptr [rsp+112]
adcx   r10, rcx
mulx   r12, rcx, qword ptr [rsp+120]
adcx   r11, rcx
adcx   r12, r13
xor    r14d, r14d
mov    rdx, qword ptr [rsp+8]
mulx   rbp, rcx, qword ptr [rsp+96]
adcx   r9, rcx
adox   r10, rbp
mulx   rbp, rcx, qword ptr [rsp+104]
adcx   r10, rcx
adox   r11, rbp
mulx   rbp, rcx, qword ptr [rsp+112]
adcx   r11, rcx
adox   r12, rbp
mulx   rbp, rcx, qword ptr [rsp+120]
adcx   r12, rcx
adox   r13, rbp
adcx   r13, r14
xor    r15d, r15d
mov    rdx, qword ptr [rsp+16]
mulx   rbp, rcx, qword ptr [rsp+96]
adcx   r10, rcx
adox   r11, rbp
mulx   rbp, rcx, qword ptr [rsp+104]
adcx   r11, rcx
adox   r12, rbp
mulx   rbp, rcx, qword ptr [rsp+112]
adcx   r12, rcx
adox   r13, rbp
mulx   rbp, rcx, qword ptr [rsp+120]
adcx   r13, rcx
adox   r14, rbp
adcx   r14, r15
xor    eax, eax
mov    rdx, qword ptr [rsp+24]
mulx   rbp, rcx, qword ptr [rsp+96]
adcx   r11, rcx
adox   r12, rbp
mulx   rbp, rcx, qword ptr [rsp+104]
adcx   r12, rcx
adox   r13, rbp
mulx   rbp, rcx, qword ptr [rsp+112]
adcx   r13, rcx
adox   r14, rbp
mulx   rbp, rcx, qword ptr [rsp+120]
adcx   r14, rcx
adox   r15, rbp
adcx   r15, rax
xor    ebp, ebp
mov    rdx, 38
mulx   r12, rax, r12
adcx   r8, rax
adox   r9, r12
mulx   r13, rcx, r13
adcx   r9, rcx
adox   r10, r13
mulx   r14, rcx, r14
adcx   r10, rcx
adox   r11, r14
mulx   r15, rcx, r15
adcx   r11, rcx
adox   r15, rbp ;# zero
adcx   r15, rbp ;# zero
shld   r15, r11, 1
btr    r11, 63
imul   r15, r15, 19
add    r8, r15
adc    r9, 0
adc    r10, 0
adc    r11, 0
mov    qword ptr [rsp+192], r8
mov    qword ptr [rsp+200], r9
mov    qword ptr [rsp+208], r10
mov    qword ptr [rsp+216], r11

movzx  ecx, byte ptr [rsp+304]
movzx  ebx, byte ptr [rsp+306]
shr    bl, cl
and    bl, 1
mov    cl, bl
xor    bl, byte ptr [rsp+305]
mov    byte ptr [rsp+305], cl
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
mov    rax, qword ptr [rsp+32]
mov    rbx, qword ptr [rsp+40]
mov    rbp, qword ptr [rsp+48]
mov    rsi, qword ptr [rsp+56]
mov    r12, qword ptr [rsp+96]
mov    r13, qword ptr [rsp+104]
mov    r14, qword ptr [rsp+112]
mov    r15, qword ptr [rsp+120]
cmove  rax, r12
cmove  rbx, r13
cmove  rbp, r14
cmove  rsi, r15

;# T2 ← T2^2
xor    r13d, r13d
mov    rdx, rax
mulx   r10, r9, rbx
mulx   r11, rcx, rbp
adcx   r10, rcx
mulx   r12, rcx, rsi
adcx   r11, rcx
adcx   r12, r13
xor    r14d, r14d
mov    rdx, rbx
mulx   rdi, rcx, rbp
adcx   r11, rcx
adox   r12, rdi
mulx   rdi, rcx, rsi
adcx   r12, rcx
adox   r13, rdi
adcx   r13, r14
xor    r15d, r15d
mov    rdx, rbp
mulx   r14, rcx, rsi
adcx   r13, rcx
adcx   r14, r15
shld   r15, r14, 1
shld   r14, r13, 1
shld   r13, r12, 1
shld   r12, r11, 1
shld   r11, r10, 1
shld   r10, r9, 1
shl    r9, 1
xor    edx, edx
mov    rdx, rax
mulx   rdx, r8, rdx
adcx   r9, rdx
mov    rdx, rbx
mulx   rdx, rcx, rdx
adcx   r10, rcx
adcx   r11, rdx
mov    rdx, rbp
mulx   rdx, rcx, rdx
adcx   r12, rcx
adcx   r13, rdx
mov    rdx, rsi
mulx   rdx, rcx, rdx
adcx   r14, rcx
adcx   r15, rdx
xor    edi, edi
mov    rdx, 38
mulx   rbp, rbx, r12
adcx   rbx, r8
adox   rbp, r9
mulx   rax, rcx, r13
adcx   rbp, rcx
adox   rax, r10
mulx   rsi, rcx, r14
adcx   rax, rcx
adox   rsi, r11
mulx   r15, rcx, r15
adcx   rsi, rcx
adox   r15, rdi ;# zero
adcx   r15, rdi ;# zero
shld   r15, rsi, 1
btr    rsi, 63
imul   r15, r15, 19
add    rbx, r15
adc    rbp, 0
adc    rax, 0
adc    rsi, 0
mov    qword ptr [rsp+32], rbx
mov    qword ptr [rsp+40], rbp
mov    qword ptr [rsp+48], rax
mov    qword ptr [rsp+56], rsi

;# T1 ← T1^2
xor    r13d, r13d
mov    rdx, qword ptr [rsp+0]
mulx   r10, r9, qword ptr [rsp+8]
mulx   r11, rcx, qword ptr [rsp+16]
adcx   r10, rcx
mulx   r12, rcx, qword ptr [rsp+24]
adcx   r11, rcx
adcx   r12, r13
xor    r14d, r14d
mov    rdx, qword ptr [rsp+8]
mulx   rdi, rcx, qword ptr [rsp+16]
adcx   r11, rcx
adox   r12, rdi
mulx   rdi, rcx, qword ptr [rsp+24]
adcx   r12, rcx
adox   r13, rdi
adcx   r13, r14
xor    r15d, r15d
mov    rdx, qword ptr [rsp+16]
mulx   r14, rcx, qword ptr [rsp+24]
adcx   r13, rcx
adcx   r14, r15
shld   r15, r14, 1
shld   r14, r13, 1
shld   r13, r12, 1
shld   r12, r11, 1
shld   r11, r10, 1
shld   r10, r9, 1
shl    r9, 1
xor    edx, edx
mov    rdx, qword ptr [rsp+0]
mulx   rdx, r8, rdx
adcx   r9, rdx
mov    rdx, qword ptr [rsp+8]
mulx   rdx, rcx, rdx
adcx   r10, rcx
adcx   r11, rdx
mov    rdx, qword ptr [rsp+16]
mulx   rdx, rcx, rdx
adcx   r12, rcx
adcx   r13, rdx
mov    rdx, qword ptr [rsp+24]
mulx   rdx, rcx, rdx
adcx   r14, rcx
adcx   r15, rdx
xor    edi, edi
mov    rdx, 38
mulx   rbp, rbx, r12
adcx   rbx, r8
adox   rbp, r9
mulx   rax, rcx, r13
adcx   rbp, rcx
adox   rax, r10
mulx   rsi, rcx, r14
adcx   rax, rcx
adox   rsi, r11
mulx   r15, rcx, r15
adcx   rsi, rcx
adox   r15, rdi ;# zero
adcx   r15, rdi ;# zero
shld   r15, rsi, 1
btr    rsi, 63
imul   r15, r15, 19
add    rbx, r15
adc    rbp, 0
adc    rax, 0
adc    rsi, 0
mov    qword ptr [rsp+0], rbx
mov    qword ptr [rsp+8], rbp
mov    qword ptr [rsp+16], rax
mov    qword ptr [rsp+24], rsi

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

;# X3 ← X3 + Z3
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
mov    qword ptr [rsp+192], r8
mov    qword ptr [rsp+200], r9
mov    qword ptr [rsp+208], r10
mov    qword ptr [rsp+216], r11

;# Z3 ← X3 - Z3
sub    rax, qword ptr [rsp+256]
sbb    rbx, qword ptr [rsp+264]
sbb    rbp, qword ptr [rsp+272]
sbb    rsi, qword ptr [rsp+280]
mov    edi, 0
mov    rcx, 38
cmovae rcx, rdi
sub    rax, rcx
sbb    rbx, 0
sbb    rbp, 0
sbb    rsi, 0
cmovb  rdi, rcx
sub    rax, rdi

;# Z3 ← Z3^2
xor    r13d, r13d
mov    rdx, rax
mulx   r10, r9, rbx
mulx   r11, rcx, rbp
adcx   r10, rcx
mulx   r12, rcx, rsi
adcx   r11, rcx
adcx   r12, r13
xor    r14d, r14d
mov    rdx, rbx
mulx   rdi, rcx, rbp
adcx   r11, rcx
adox   r12, rdi
mulx   rdi, rcx, rsi
adcx   r12, rcx
adox   r13, rdi
adcx   r13, r14
xor    r15d, r15d
mov    rdx, rbp
mulx   r14, rcx, rsi
adcx   r13, rcx
adcx   r14, r15
shld   r15, r14, 1
shld   r14, r13, 1
shld   r13, r12, 1
shld   r12, r11, 1
shld   r11, r10, 1
shld   r10, r9, 1
shl    r9, 1
xor    edx, edx
mov    rdx, rax
mulx   rdx, r8, rdx
adcx   r9, rdx
mov    rdx, rbx
mulx   rdx, rcx, rdx
adcx   r10, rcx
adcx   r11, rdx
mov    rdx, rbp
mulx   rdx, rcx, rdx
adcx   r12, rcx
adcx   r13, rdx
mov    rdx, rsi
mulx   rdx, rcx, rdx
adcx   r14, rcx
adcx   r15, rdx
xor    edi, edi
mov    rdx, 38
mulx   rbp, rbx, r12
adcx   rbx, r8
adox   rbp, r9
mulx   rax, rcx, r13
adcx   rbp, rcx
adox   rax, r10
mulx   rsi, rcx, r14
adcx   rax, rcx
adox   rsi, r11
mulx   r15, rcx, r15
adcx   rsi, rcx
adox   r15, rdi ;# zero
adcx   r15, rdi ;# zero
shld   r15, rsi, 1
btr    rsi, 63
imul   r15, r15, 19
add    rbx, r15
adc    rbp, 0
adc    rax, 0
adc    rsi, 0
mov    qword ptr [rsp+256], rbx
mov    qword ptr [rsp+264], rbp
mov    qword ptr [rsp+272], rax
mov    qword ptr [rsp+280], rsi

;# X3 ← X3^2
xor    r13d, r13d
mov    rdx, qword ptr [rsp+192]
mulx   r10, r9, qword ptr [rsp+200]
mulx   r11, rcx, qword ptr [rsp+208]
adcx   r10, rcx
mulx   r12, rcx, qword ptr [rsp+216]
adcx   r11, rcx
adcx   r12, r13
xor    r14d, r14d
mov    rdx, qword ptr [rsp+200]
mulx   rdi, rcx, qword ptr [rsp+208]
adcx   r11, rcx
adox   r12, rdi
mulx   rdi, rcx, qword ptr [rsp+216]
adcx   r12, rcx
adox   r13, rdi
adcx   r13, r14
xor    r15d, r15d
mov    rdx, qword ptr [rsp+208]
mulx   r14, rcx, qword ptr [rsp+216]
adcx   r13, rcx
adcx   r14, r15
shld   r15, r14, 1
shld   r14, r13, 1
shld   r13, r12, 1
shld   r12, r11, 1
shld   r11, r10, 1
shld   r10, r9, 1
shl    r9, 1
xor    edx, edx
mov    rdx, qword ptr [rsp+192]
mulx   rdx, r8, rdx
adcx   r9, rdx
mov    rdx, qword ptr [rsp+200]
mulx   rdx, rcx, rdx
adcx   r10, rcx
adcx   r11, rdx
mov    rdx, qword ptr [rsp+208]
mulx   rdx, rcx, rdx
adcx   r12, rcx
adcx   r13, rdx
mov    rdx, qword ptr [rsp+216]
mulx   rdx, rcx, rdx
adcx   r14, rcx
adcx   r15, rdx
xor    edi, edi
mov    rdx, 38
mulx   rbp, rbx, r12
adcx   rbx, r8
adox   rbp, r9
mulx   rax, rcx, r13
adcx   rbp, rcx
adox   rax, r10
mulx   rsi, rcx, r14
adcx   rax, rcx
adox   rsi, r11
mulx   r15, rcx, r15
adcx   rsi, rcx
adox   r15, rdi ;# zero
adcx   r15, rdi ;# zero
shld   r15, rsi, 1
btr    rsi, 63
imul   r15, r15, 19
add    rbx, r15
adc    rbp, 0
adc    rax, 0
adc    rsi, 0

;# update X3
mov    qword ptr [rsp+192], rbx
mov    qword ptr [rsp+200], rbp
mov    qword ptr [rsp+208], rax
mov    qword ptr [rsp+216], rsi

;# T3 ← T1 - T2
mov    rax, qword ptr [rsp+0]
mov    rbx, qword ptr [rsp+8]
mov    rsi, qword ptr [rsp+16]
mov    rdi, qword ptr [rsp+24]
sub    rax, qword ptr [rsp+32]
sbb    rbx, qword ptr [rsp+40]
sbb    rsi, qword ptr [rsp+48]
sbb    rdi, qword ptr [rsp+56]
mov    ebp, 0
mov    rcx, 38
cmovae rcx, rbp
sub    rax, rcx
sbb    rbx, rbp
sbb    rsi, rbp
sbb    rdi, rbp
cmovb  rbp, rcx
sub    rax, rbp
mov    qword ptr [rsp+64], rax
mov    qword ptr [rsp+72], rbx
mov    qword ptr [rsp+80], rsi
mov    qword ptr [rsp+88], rdi

;# T4 ← ((A + 2)/4) · T3
xor    r12d, r12d
mov    rdx, 121666
mulx   rbp, rax, rax
mulx   rcx, rbx, rbx
adcx   rbx, rbp
mulx   rbp, rsi, rsi
adcx   rsi, rcx
mulx   rcx, rdi, rdi
adcx   rdi, rbp
adcx   rcx, r12
shld   rcx, rdi, 1
btr    rdi, 63
imul   rcx, rcx, 19
add    rax, rcx
adc    rbx, 0
adc    rsi, 0
adc    rdi, 0

;# T4 ← T4 + T2
add    rax, qword ptr [rsp+32]
adc    rbx, qword ptr [rsp+40]
adc    rsi, qword ptr [rsp+48]
adc    rdi, qword ptr [rsp+56]
mov    ebp, 0
mov    rcx, 38
cmovae rcx, rbp
add    rax, rcx
adc    rbx, rbp
adc    rsi, rbp
adc    rdi, rbp
cmovb  rbp, rcx
add    rax, rbp
mov    qword ptr [rsp+96], rax
mov    qword ptr [rsp+104], rbx
mov    qword ptr [rsp+112], rsi
mov    qword ptr [rsp+120], rdi

;# X2 ← T1 · T2
xor    r13d, r13d
mov    rdx, qword ptr [rsp+0]
mulx   r9, r8, qword ptr [rsp+32]
mulx   r10, rcx, qword ptr [rsp+40]
adcx   r9, rcx
mulx   r11, rcx, qword ptr [rsp+48]
adcx   r10, rcx
mulx   r12, rcx, qword ptr [rsp+56]
adcx   r11, rcx
adcx   r12, r13
xor    r14d, r14d
mov    rdx, qword ptr [rsp+8]
mulx   rbp, rcx, qword ptr [rsp+32]
adcx   r9, rcx
adox   r10, rbp
mulx   rbp, rcx, qword ptr [rsp+40]
adcx   r10, rcx
adox   r11, rbp
mulx   rbp, rcx, qword ptr [rsp+48]
adcx   r11, rcx
adox   r12, rbp
mulx   rbp, rcx, qword ptr [rsp+56]
adcx   r12, rcx
adox   r13, rbp
adcx   r13, r14
xor    r15d, r15d
mov    rdx, qword ptr [rsp+16]
mulx   rbp, rcx, qword ptr [rsp+32]
adcx   r10, rcx
adox   r11, rbp
mulx   rbp, rcx, qword ptr [rsp+40]
adcx   r11, rcx
adox   r12, rbp
mulx   rbp, rcx, qword ptr [rsp+48]
adcx   r12, rcx
adox   r13, rbp
mulx   rbp, rcx, qword ptr [rsp+56]
adcx   r13, rcx
adox   r14, rbp
adcx   r14, r15
xor    eax, eax
mov    rdx, qword ptr [rsp+24]
mulx   rbp, rcx, qword ptr [rsp+32]
adcx   r11, rcx
adox   r12, rbp
mulx   rbp, rcx, qword ptr [rsp+40]
adcx   r12, rcx
adox   r13, rbp
mulx   rbp, rcx, qword ptr [rsp+48]
adcx   r13, rcx
adox   r14, rbp
mulx   rbp, rcx, qword ptr [rsp+56]
adcx   r14, rcx
adox   r15, rbp
adcx   r15, rax
xor    ebp, ebp
mov    rdx, 38
mulx   r12, rax, r12
adcx   r8, rax
adox   r9, r12
mulx   r13, rcx, r13
adcx   r9, rcx
adox   r10, r13
mulx   r14, rcx, r14
adcx   r10, rcx
adox   r11, r14
mulx   r15, rcx, r15
adcx   r11, rcx
adox   r15, rbp ;# zero
adcx   r15, rbp ;# zero
shld   r15, r11, 1
btr    r11, 63
imul   r15, r15, 19
add    r8, r15
adc    r9, 0
adc    r10, 0
adc    r11, 0

;# update X2
mov    qword ptr [rsp+160], r8
mov    qword ptr [rsp+168], r9
mov    qword ptr [rsp+176], r10
mov    qword ptr [rsp+184], r11

;# Z2 ← T3 · T4
xor    r13d, r13d
mov    rdx, qword ptr [rsp+96]
mulx   r9, r8, qword ptr [rsp+64]
mulx   r10, rcx, qword ptr [rsp+72]
adcx   r9, rcx
mulx   r11, rcx, qword ptr [rsp+80]
adcx   r10, rcx
mulx   r12, rcx, qword ptr [rsp+88]
adcx   r11, rcx
adcx   r12, r13
xor    r14d, r14d
mov    rdx, qword ptr [rsp+104]
mulx   rbp, rcx, qword ptr [rsp+64]
adcx   r9, rcx
adox   r10, rbp
mulx   rbp, rcx, qword ptr [rsp+72]
adcx   r10, rcx
adox   r11, rbp
mulx   rbp, rcx, qword ptr [rsp+80]
adcx   r11, rcx
adox   r12, rbp
mulx   rbp, rcx, qword ptr [rsp+88]
adcx   r12, rcx
adox   r13, rbp
adcx   r13, r14
xor    r15d, r15d
mov    rdx, qword ptr [rsp+112]
mulx   rbp, rcx, qword ptr [rsp+64]
adcx   r10, rcx
adox   r11, rbp
mulx   rbp, rcx, qword ptr [rsp+72]
adcx   r11, rcx
adox   r12, rbp
mulx   rbp, rcx, qword ptr [rsp+80]
adcx   r12, rcx
adox   r13, rbp
mulx   rbp, rcx, qword ptr [rsp+88]
adcx   r13, rcx
adox   r14, rbp
adcx   r14, r15
xor    eax, eax
mov    rdx, qword ptr [rsp+120]
mulx   rbp, rcx, qword ptr [rsp+64]
adcx   r11, rcx
adox   r12, rbp
mulx   rbp, rcx, qword ptr [rsp+72]
adcx   r12, rcx
adox   r13, rbp
mulx   rbp, rcx, qword ptr [rsp+80]
adcx   r13, rcx
adox   r14, rbp
mulx   rbp, rcx, qword ptr [rsp+88]
adcx   r14, rcx
adox   r15, rbp
adcx   r15, rax
xor    ebp, ebp
mov    rdx, 38
mulx   r12, rax, r12
adcx   r8, rax
adox   r9, r12
mulx   r13, rcx, r13
adcx   r9, rcx
adox   r10, r13
mulx   r14, rcx, r14
adcx   r10, rcx
adox   r11, r14
mulx   r15, rcx, r15
adcx   r11, rcx
adox   r15, rbp ;# zero
adcx   r15, rbp ;# zero
shld   r15, r11, 1
btr    r11, 63
imul   r15, r15, 19
add    r8, r15
adc    r9, 0
adc    r10, 0
adc    r11, 0

;# update Z2
mov    qword ptr [rsp+224], r8
mov    qword ptr [rsp+232], r9
mov    qword ptr [rsp+240], r10
mov    qword ptr [rsp+248], r11

;# Z3 ← Z3 · X1
xor    r13d, r13d
mov    rdx, qword ptr [rsp+256]
mulx   r9, r8, qword ptr [rsp+128]
mulx   r10, rcx, qword ptr [rsp+136]
adcx   r9, rcx
mulx   r11, rcx, qword ptr [rsp+144]
adcx   r10, rcx
mulx   r12, rcx, qword ptr [rsp+152]
adcx   r11, rcx
adcx   r12, r13
xor    r14d, r14d
mov    rdx, qword ptr [rsp+264]
mulx   rbp, rcx, qword ptr [rsp+128]
adcx   r9, rcx
adox   r10, rbp
mulx   rbp, rcx, qword ptr [rsp+136]
adcx   r10, rcx
adox   r11, rbp
mulx   rbp, rcx, qword ptr [rsp+144]
adcx   r11, rcx
adox   r12, rbp
mulx   rbp, rcx, qword ptr [rsp+152]
adcx   r12, rcx
adox   r13, rbp
adcx   r13, r14
xor    r15d, r15d
mov    rdx, qword ptr [rsp+272]
mulx   rbp, rcx, qword ptr [rsp+128]
adcx   r10, rcx
adox   r11, rbp
mulx   rbp, rcx, qword ptr [rsp+136]
adcx   r11, rcx
adox   r12, rbp
mulx   rbp, rcx, qword ptr [rsp+144]
adcx   r12, rcx
adox   r13, rbp
mulx   rbp, rcx, qword ptr [rsp+152]
adcx   r13, rcx
adox   r14, rbp
adcx   r14, r15
xor    eax, eax
mov    rdx, qword ptr [rsp+280]
mulx   rbp, rcx, qword ptr [rsp+128]
adcx   r11, rcx
adox   r12, rbp
mulx   rbp, rcx, qword ptr [rsp+136]
adcx   r12, rcx
adox   r13, rbp
mulx   rbp, rcx, qword ptr [rsp+144]
adcx   r13, rcx
adox   r14, rbp
mulx   rbp, rcx, qword ptr [rsp+152]
adcx   r14, rcx
adox   r15, rbp
adcx   r15, rax
xor    ebp, ebp
mov    rdx, 38
mulx   r12, rax, r12
adcx   r8, rax
adox   r9, r12
mulx   r13, rcx, r13
adcx   r9, rcx
adox   r10, r13
mulx   r14, rcx, r14
adcx   r10, rcx
adox   r11, r14
mulx   r15, rcx, r15
adcx   r11, rcx
adox   r15, rbp ;# zero
adcx   r15, rbp ;# zero
shld   r15, r11, 1
btr    r11, 63
imul   r15, r15, 19
add    r8, r15
adc    r9, 0
adc    r10, 0
adc    r11, 0

;# update Z3
mov    qword ptr [rsp+256], r8
mov    qword ptr [rsp+264], r9
mov    qword ptr [rsp+272], r10
mov    qword ptr [rsp+280], r11

movzx  ecx, byte ptr [rsp+304]
sub    ecx, 1
mov    byte ptr [rsp+304], cl
;# cmp    cl, 0
jge    loop_bit_x

mov    byte ptr [rsp+304], 7
lea    rsi, [rsp+320]
mov    eax, dword ptr [rsp+312]
sub    eax, 1
mov    dword ptr [rsp+312], eax
;# cmp    eax, 0
jge    loop_byte_x

;# load select, AKA the LSB, then remove
;# needed to support privkeys wth unclamped LSB
mov bl, byte ptr [rsp+305]
mov byte ptr [rsp+305], 0
cmp bl, 1

;# CSelect(X2,X3,select)
mov    rsi, qword ptr [rsp+160]
mov    rbp, qword ptr [rsp+168]
mov    rcx, qword ptr [rsp+176]
mov    rax, qword ptr [rsp+184]
mov    r12, qword ptr [rsp+192]
mov    r13, qword ptr [rsp+200]
mov    r14, qword ptr [rsp+208]
mov    r15, qword ptr [rsp+216]
cmove  rsi, r12
cmove  rbp, r13
cmove  rcx, r14
cmove  rax, r15

;# CSelect(Z2,Z3,select)
mov    r8, qword ptr [rsp+224]
mov    r9, qword ptr [rsp+232]
mov    r10, qword ptr [rsp+240]
mov    r11, qword ptr [rsp+248]
mov    r12, qword ptr [rsp+256]
mov    r13, qword ptr [rsp+264]
mov    r14, qword ptr [rsp+272]
mov    r15, qword ptr [rsp+280]
cmove  r8, r12
cmove  r9, r13
cmove  r10, r14
cmove  r11, r15

;# overwrite the private key on the stack with X2
mov    qword ptr [rsp+320], rsi
mov    qword ptr [rsp+328], rbp
mov    qword ptr [rsp+336], rcx
mov    qword ptr [rsp+344], rax

sub    rsp, 384

;# [secondary stack frame]
;# (offsets from rsp)
;# 800 alignment
;# 736 saved registers: rbx, rbp, rdi, r11, r12, r13, r14, r15
;# 704 X2
;# (0-703) scratch space

;# Z2 in: r8, r9, r10, r11
;# begin inversion

lea rdx, [gcd_table+REG_REL]
mov rsi, r11
sar rsi, 63
btr r11, 63
and rsi, 19
add rsi, 19
add r8, rsi
adc r9, 0
adc r10, 0
adc r11, 0
mov rsi, r11
sar rsi, 63
btr r11, 63
and rsi, 19
add r8, rsi
adc r9, 0
adc r10, 0
adc r11, 0
sub r8, 19
sbb r9, 0
sbb r10, 0
sbb r11, 0
mov rsi, -1152921504606846976
andn r14, rsi, r8
vmovupd ymm0, ymmword ptr [rdx+288]
vmovapd ymmword ptr [rsp+32], ymm0
mov rax, r8
and rax, 1073741823
mov qword ptr [rsp+48], rax
vmovupd ymm0, ymmword ptr [rdx+320]
vmovapd ymmword ptr [rsp+64], ymm0
mov rax, r8
shr rax, 30
and rax, 1073741823
mov qword ptr [rsp+80], rax
vmovupd ymm0, ymmword ptr [rdx+352]
vmovapd ymmword ptr [rsp+96], ymm0
shrd r8, r9, 60
and r8, 1073741823
mov qword ptr [rsp+112], r8
vmovupd ymm0, ymmword ptr [rdx+384]
vmovapd ymmword ptr [rsp+128], ymm0
mov rsi, r9
shr rsi, 26
and rsi, 1073741823
mov qword ptr [rsp+144], rsi
vmovupd ymm0, ymmword ptr [rdx+416]
vmovapd ymmword ptr [rsp+160], ymm0
shrd r9, r10, 56
and r9, 1073741823
mov qword ptr [rsp+176], r9
vmovupd ymm0, ymmword ptr [rdx+448]
vmovapd ymmword ptr [rsp+192], ymm0
mov rsi, r10
shr rsi, 22
and rsi, 1073741823
mov qword ptr [rsp+208], rsi
vmovupd ymm0, ymmword ptr [rdx+480]
vmovapd ymmword ptr [rsp+224], ymm0
shrd r10, r11, 52
and r10, 1073741823
mov qword ptr [rsp+240], r10
vmovupd ymm0, ymmword ptr [rdx+512]
vmovapd ymmword ptr [rsp+256], ymm0
mov rsi, r11
shr rsi, 18
and rsi, 1073741823
mov qword ptr [rsp+272], rsi
vmovupd ymm0, ymmword ptr [rdx+544]
vmovapd ymmword ptr [rsp+288], ymm0
shr r11, 48
mov qword ptr [rsp+304], r11
mov rdi, -19
xor rsi, rsi
mov rcx, -1
mov qword ptr [rsp], rsi
mov qword ptr [rsp+8], rcx
mov rcx, -1048576
vmovupd ymm0, ymmword ptr [rdx]
vmovapd ymmword ptr [rsp+320], ymm0
vmovupd ymm0, ymmword ptr [rdx+32]
vmovapd ymmword ptr [rsp+352], ymm0
vmovupd ymm0, ymmword ptr [rdx+64]
vmovapd ymmword ptr [rsp+384], ymm0
vmovupd ymm0, ymmword ptr [rdx+96]
vmovapd ymmword ptr [rsp+416], ymm0
vmovupd ymm0, ymmword ptr [rdx+128]
vmovapd ymmword ptr [rsp+448], ymm0
vmovupd ymm0, ymmword ptr [rdx+160]
vmovapd ymmword ptr [rsp+480], ymm0
vmovupd ymm0, ymmword ptr [rdx+192]
vmovapd ymmword ptr [rsp+512], ymm0
vmovupd ymm0, ymmword ptr [rdx+224]
vmovapd ymmword ptr [rsp+544], ymm0
vmovupd ymm0, ymmword ptr [rdx+256]
mov r8, 10
mov r10, 1152921504606846976
xor r11, r11
mov r12, r10
xor r13, r13

ALIGN 16
_bigloop:
mov rax, r14
imul r12
mov rbx, rax
mov rbp, rdx
mov rax, rdi
imul r13
add rbx, rax
adc rbp, rdx
shrd rbx, rbp, 60
mov rax, rdi
imul r10
mov rdi, rax
mov rbp, rdx
mov rax, r14
imul r11
add rdi, rax
adc rbp, rdx
shrd rdi, rbp, 60
vpinsrq xmm1, xmm1, r11, 0
vpinsrq xmm1, xmm1, r13, 1
imul r11, r15
imul r15, r12
imul r13, r9
imul r9, r10
add r9, r11
add r15, r13
add rdi, r9
lea rdx, [rbx+r15]
vmovapd ymm2, ymmword ptr [rsp+32]
andn r9, rcx, rdi

_loop20_init:
andn rax, rcx, rdx
vpinsrq xmm3, xmm3, r10, 0
add r9, qword ptr [inv_bias41+REG_REL]
add rax, qword ptr [inv_bias62+REG_REL]
vpinsrq xmm3, xmm3, r12, 1
mov r10, qword ptr [rsp+8]
mov r11, rax
vpermq ymm4, ymm2, 78
lea r12, [rax+r9]
test rax, 1
cmovne r10, rsi
vpermq ymm3, ymm3, 80
cmove r12, rax
lea r13, [rsi+1]
vpermq ymm1, ymm1, 80
sub rax, r9
sar rax, 1
vmovapd ymm5, ymmword ptr [rsp+448]
sar r12, 1
neg rsi
vpand ymm6, ymm5, ymm3
cmp r10, 0
cmovge r9, r11
vpand ymm7, ymm5, ymm1
cmovl rax, r12
cmovl rsi, r13
vpmuldq ymm8, ymm2, ymm6
mov r10, -1
mov r11, rax
vpmuldq ymm9, ymm4, ymm7
lea r12, [rax+r9]
test rax, 1
vpaddq ymm8, ymm9, ymm8
cmovne r10, rsi
cmove r12, rax
vmovapd ymm9, ymmword ptr [rsp+416]
lea r13, [rsi+1]
vmovapd ymm10, ymmword ptr [rsp+320]
sub rax, r9
sar rax, 1
sar r12, 1
vpmuldq ymm11, ymm9, ymm8
neg rsi
cmp r10, 0
vpand ymm11, ymm5, ymm11
cmovge r9, r11
cmovl rax, r12
vpmuldq ymm12, ymm10, ymm11
cmovl rsi, r13
mov r10, qword ptr [rsp+8]
vpsubq ymm8, ymm8, ymm12
mov r11, rax
vpaddq ymm8, ymm8, ymmword ptr [rsp+544]
lea r12, [rax+r9]
test rax, 1
cmovne r10, rsi
cmove r12, rax
vpsrlq ymm8, ymm8, 30
lea r13, [rsi+1]
vpsllq ymm11, ymm11, 15
sub rax, r9
sar rax, 1
sar r12, 1
vmovapd ymm12, ymmword ptr [rsp+64]
neg rsi
vpermq ymm13, ymm12, 78
cmp r10, 0
cmovge r9, r11
cmovl rax, r12
vpmuldq ymm14, ymm12, ymm6
cmovl rsi, r13
vpmuldq ymm15, ymm13, ymm7
mov r10, -1
mov r11, rax
vpaddq ymm14, ymm15, ymm14
lea r12, [rax+r9]
test rax, 1
vpsrlq ymm3, ymm3, 30
cmovne r10, rsi
vpsrlq ymm1, ymm1, 30
cmove r12, rax
lea r13, [rsi+1]
sub rax, r9
vpmuldq ymm2, ymm2, ymm3
sar rax, 1
sar r12, 1
vpmuldq ymm4, ymm4, ymm1
neg rsi
cmp r10, 0
vpaddq ymm2, ymm4, ymm2
cmovge r9, r11
cmovl rax, r12
vpaddq ymm2, ymm14, ymm2
cmovl rsi, r13
mov r10, -1
vpaddq ymm2, ymm8, ymm2
mov r11, rax
lea r12, [rax+r9]
vpmuldq ymm4, ymm9, ymm2
test rax, 1
cmovne r10, rsi
cmove r12, rax
vpand ymm4, ymm5, ymm4
lea r13, [rsi+1]
vpmuldq ymm8, ymm10, ymm4
sub rax, r9
sar rax, 1
vpsubq ymm2, ymm2, ymm8
sar r12, 1
neg rsi
vpaddq ymm2, ymm0, ymm2
cmp r10, 0
cmovge r9, r11
vpsrlq ymm2, ymm2, 30
cmovl rax, r12
cmovl rsi, r13
mov r10, qword ptr [rsp+8]
vpsllq ymm4, ymm4, 15
mov r11, rax
vmovapd ymm8, ymmword ptr [rsp+96]
lea r12, [rax+r9]
test rax, 1
vpermq ymm9, ymm8, 78
cmovne r10, rsi
cmove r12, rax
vpmuldq ymm10, ymm12, ymm3
lea r13, [rsi+1]
sub rax, r9
vpmuldq ymm12, ymm13, ymm1
sar rax, 1
vpaddq ymm10, ymm12, ymm10
sar r12, 1
neg rsi
cmp r10, 0
vpmuldq ymm12, ymm8, ymm6
cmovge r9, r11
cmovl rax, r12
vpmuldq ymm13, ymm9, ymm7
cmovl rsi, r13
mov r10, qword ptr [rsp+8]
vpaddq ymm12, ymm13, ymm12
mov r11, rax
lea r12, [rax+r9]
vpaddq ymm12, ymm10, ymm12
test rax, 1
cmovne r10, rsi
vpaddq ymm12, ymm2, ymm12
cmove r12, rax
lea r13, [rsi+1]
vpaddq ymm2, ymm0, ymm12
sub rax, r9
sar rax, 1
vpsrlq ymm2, ymm2, 30
sar r12, 1
vmovapd ymm10, ymmword ptr [rsp+128]
neg rsi
cmp r10, 0
cmovge r9, r11
vpermq ymm13, ymm10, 78
cmovl rax, r12
cmovl rsi, r13
vpmuldq ymm8, ymm8, ymm3
vpmuldq ymm9, ymm9, ymm1
mov r10, qword ptr [rsp+8]
mov r11, rax
lea r12, [rax+r9]
test rax, 1
vpaddq ymm8, ymm9, ymm8
cmovne r10, rsi
cmove r12, rax
vpmuldq ymm9, ymm10, ymm6
lea r13, [rsi+1]
vpmuldq ymm14, ymm13, ymm7
sub rax, r9
sar rax, 1
sar r12, 1
vpaddq ymm9, ymm14, ymm9
neg rsi
cmp r10, 0
vpaddq ymm9, ymm8, ymm9
cmovge r9, r11
cmovl rax, r12
cmovl rsi, r13
vpaddq ymm9, ymm2, ymm9
mov r10, -1
vpand ymm12, ymm5, ymm12
mov r11, rax
lea r12, [rax+r9]
vpaddq ymm2, ymm0, ymm9
test rax, 1
vpsrlq ymm2, ymm2, 30
cmovne r10, rsi
cmove r12, rax
lea r13, [rsi+1]
vpand ymm9, ymm5, ymm9
sub rax, r9
sar rax, 1
vmovapd ymmword ptr [rsp+64], ymm9
sar r12, 1
vpsllq ymm8, ymm9, 30
neg rsi
cmp r10, 0
cmovge r9, r11
vpaddq ymm8, ymm12, ymm8
cmovl rax, r12
cmovl rsi, r13
vmovapd ymmword ptr [rsp+640], ymm8
mov r10, qword ptr [rsp+8]
mov r11, rax
lea r12, [rax+r9]
vmovapd ymm8, ymmword ptr [rsp+160]
vpermq ymm9, ymm8, 78
test rax, 1
cmovne r10, rsi
cmove r12, rax
vpmuldq ymm10, ymm10, ymm3
lea r13, [rsi+1]
sub rax, r9
vpmuldq ymm13, ymm13, ymm1
sar rax, 1
sar r12, 1
vpaddq ymm10, ymm13, ymm10
neg rsi
vpmuldq ymm13, ymm8, ymm6
cmp r10, 0
cmovge r9, r11
cmovl rax, r12
vpmuldq ymm14, ymm9, ymm7
cmovl rsi, r13
mov r10, -1
vpaddq ymm13, ymm14, ymm13
mov r11, rax
lea r12, [rax+r9]
vpaddq ymm13, ymm10, ymm13
test rax, 1
cmovne r10, rsi
cmove r12, rax
vpaddq ymm13, ymm2, ymm13
lea r13, [rsi+1]
sub rax, r9
vpaddq ymm2, ymm0, ymm13
vpsrlq ymm2, ymm2, 30
sar rax, 1
sar r12, 1
neg rsi
vmovapd ymm10, ymmword ptr [rsp+192]
cmp r10, 0
cmovge r9, r11
vpermq ymm14, ymm10, 78
cmovl rax, r12
cmovl rsi, r13
mov r10, -1
vpmuldq ymm8, ymm8, ymm3
mov r11, rax
vpmuldq ymm9, ymm9, ymm1
lea r12, [rax+r9]
test rax, 1
vpaddq ymm8, ymm9, ymm8
cmovne r10, rsi
cmove r12, rax
lea r13, [rsi+1]
vpmuldq ymm9, ymm10, ymm6
vpmuldq ymm15, ymm14, ymm7
sub rax, r9
sar rax, 1
sar r12, 1
vpaddq ymm9, ymm15, ymm9
neg rsi
cmp r10, 0
vpaddq ymm9, ymm8, ymm9
cmovge r9, r11
cmovl rax, r12
vpaddq ymm9, ymm2, ymm9
cmovl rsi, r13
mov r10, qword ptr [rsp+8]
vpaddq ymm2, ymm0, ymm9
mov r11, rax
lea r12, [rax+r9]
vpsrlq ymm2, ymm2, 30
test rax, 1
cmovne r10, rsi
vpand ymm9, ymm5, ymm9
cmove r12, rax
lea r13, [rsi+1]
vpand ymm13, ymm5, ymm13
sub rax, r9
sar rax, 1
vmovapd ymmword ptr [rsp+96], ymm13
sar r12, 1
neg rsi
cmp r10, 0
vpsllq ymm8, ymm9, 30
cmovge r9, r11
vpaddq ymm8, ymm13, ymm8
cmovl rax, r12
cmovl rsi, r13
vmovapd ymmword ptr [rsp+672], ymm8
mov r10, qword ptr [rsp+8]
mov r11, rax
vmovapd ymm8, ymmword ptr [rsp+224]
lea r12, [rax+r9]
test rax, 1
vpermq ymm13, ymm8, 78
cmovne r10, rsi
cmove r12, rax
vpmuldq ymm10, ymm10, ymm3
lea r13, [rsi+1]
sub rax, r9
vpmuldq ymm14, ymm14, ymm1
sar rax, 1
vpaddq ymm10, ymm14, ymm10
sar r12, 1
neg rsi
cmp r10, 0
vpmuldq ymm14, ymm8, ymm6
cmovge r9, r11
cmovl rax, r12
vpmuldq ymm15, ymm13, ymm7
cmovl rsi, r13
mov r10, qword ptr [rsp+8]
vpaddq ymm14, ymm15, ymm14
mov r11, rax
lea r12, [rax+r9]
test rax, 1
vpaddq ymm14, ymm10, ymm14
cmovne r10, rsi
cmove r12, rax
lea r13, [rsi+1]
vpaddq ymm14, ymm2, ymm14
sub rax, r9
sar rax, 1
vpaddq ymm2, ymm0, ymm14
vpsrlq ymm2, ymm2, 30
sar r12, 1
neg rsi
cmp r10, 0
vmovapd ymmword ptr [rsp+128], ymm9
vmovapd ymm9, ymmword ptr [rsp+256]
cmovge r9, r11
cmovl rax, r12
cmovl rsi, r13
vpermq ymm10, ymm9, 78
mov r10, qword ptr [rsp+8]
vpmuldq ymm8, ymm8, ymm3
mov r11, rax
lea r12, [rax+r9]
test rax, 1
vpmuldq ymm13, ymm13, ymm1
cmovne r10, rsi
cmove r12, rax
vpaddq ymm8, ymm13, ymm8
lea r13, [rsi+1]
sub rax, r9
vpmuldq ymm13, ymm9, ymm6
sar rax, 1
sar r12, 1
vpmuldq ymm15, ymm10, ymm7
neg rsi
cmp r10, 0
vpaddq ymm13, ymm15, ymm13
cmovge r9, r11
cmovl rax, r12
vpaddq ymm13, ymm8, ymm13
cmovl rsi, r13
mov r10, qword ptr [rsp+8]
vpaddq ymm13, ymm2, ymm13
mov r11, rax
lea r12, [rax+r9]
vpaddq ymm2, ymm0, ymm13
test rax, 1
cmovne r10, rsi
vpsrlq ymm2, ymm2, 30
cmove r12, rax
vpand ymm14, ymm5, ymm14
lea r13, [rsi+1]
sub rax, r9
sar rax, 1
vmovapd ymmword ptr [rsp+160], ymm14
sar r12, 1
vmovapd ymm8, ymmword ptr [rsp+288]
neg rsi
cmp r10, 0
cmovge r9, r11
vpermq ymm14, ymm8, 78
cmovl rax, r12
cmovl rsi, r13
vpmuldq ymm9, ymm9, ymm3
mov r10, -1
mov r11, rax
vpmuldq ymm10, ymm10, ymm1
lea r12, [rax+r9]
test rax, 1
cmovne r10, rsi
vpaddq ymm9, ymm10, ymm9
cmove r12, rax
vpmuldq ymm6, ymm8, ymm6
lea r13, [rsi+1]
sub rax, r9
vpmuldq ymm7, ymm14, ymm7
sar rax, 1
vpaddq ymm6, ymm7, ymm6
sar r12, 1
neg rsi
cmp r10, 0
cmovge r9, r11
vpaddq ymm6, ymm9, ymm6
vpaddq ymm6, ymm2, ymm6
cmovl rax, r12
cmovl rsi, r13
mov r10, qword ptr [rsp+8]
vpaddq ymm6, ymm11, ymm6
mov r11, rax
lea r12, [rax+r9]
vpaddq ymm2, ymm0, ymm6
test rax, 1
vpsrlq ymm2, ymm2, 30
cmovne r10, rsi
cmove r12, rax
lea r13, [rsi+1]
vpand ymm13, ymm5, ymm13
sub rax, r9
sar rax, 1
sar r12, 1
vmovapd ymmword ptr [rsp+192], ymm13
neg rsi
vpmuldq ymm3, ymm8, ymm3
cmp r10, 0
cmovge r9, r11
vpmuldq ymm1, ymm14, ymm1
cmovl rax, r12
cmovl rsi, r13
vpaddq ymm1, ymm1, ymm3
mov r10, qword ptr [rsp+8]
mov r11, rax
vpaddq ymm4, ymm1, ymm4
lea r12, [rax+r9]
test rax, 1
vpaddq ymm4, ymm2, ymm4
cmovne r10, rsi
cmove r12, rax
vpaddq ymm1, ymm0, ymm4
lea r13, [rsi+1]
sub rax, r9
vpsrlq ymm1, ymm1, 30
sar rax, 1
vpand ymm6, ymm5, ymm6
sar r12, 1
neg rsi
cmp r10, 0
vmovapd ymmword ptr [rsp+224], ymm6
cmovge r9, r11
vmovapd ymm2, ymmword ptr [rsp+384]
cmovl rax, r12
cmovl rsi, r13

_extract_init:
mov r10, qword ptr [inv_round41+REG_REL]
lea r11, [rax+r10]
vmovapd ymm3, ymmword ptr [rsp+512]
vpaddq ymm6, ymm0, ymm1
sar r11, 42
mov r12, rdx
vpsrlq ymm6, ymm6, 15
imul rdx, r11
lea r10, [r9+r10]
vpsubq ymm6, ymm6, ymm3
sar r10, 42
imul r12, r10
vpsubq ymm1, ymm1, ymmword ptr [rsp+480]
mov r13, qword ptr [inv_round20+REG_REL]
lea rax, [rax+r13]
vpand ymm4, ymm5, ymm4
shl rax, 22
sar rax, 43
vpand ymm1, ymm2, ymm1
mov r14, rdi
imul r14, rax
vpmuldq ymm2, ymm6, ymmword ptr [rsp+352]
lea r9, [r9+r13]
vpaddq ymm12, ymm2, ymm12
shl r9, 22
sar r9, 43
imul rdi, r9
vmovapd ymmword ptr [rsp+256], ymm4
add rdi, r12
add rdx, r14
vmovapd ymmword ptr [rsp+288], ymm1
sar rdi, 20
vmovapd ymmword ptr [rsp+32], ymm12
sar rdx, 20
mov qword ptr [rsp+608], r10
mov qword ptr [rsp+576], r9
mov qword ptr [rsp+592], r11
mov qword ptr [rsp+624], rax
mov r9, 2

_loop20:
andn rax, rcx, rdi
andn r10, rcx, rdx
add rax, qword ptr [inv_bias41+REG_REL]
add r10, qword ptr [inv_bias62+REG_REL]
mov r11, 2

_loop2:
mov r12, -1
mov r13, r10
lea r14, [r10+rax]
test r10, 1
cmovne r12, rsi
cmove r14, r10
lea r15, [rsi+1]
sub r10, rax
sar r10, 1
sar r14, 1
neg rsi
cmp r12, 0
cmovge rax, r13
cmovl r10, r14
cmovl rsi, r15
mov r12, qword ptr [rsp+8]
mov r13, r10
lea r14, [r10+rax]
test r10, 1
cmovne r12, rsi
cmove r14, r10
lea r15, [rsi+1]
sub r10, rax
sar r10, 1
sar r14, 1
neg rsi
cmp r12, 0
cmovge rax, r13
cmovl r10, r14
cmovl rsi, r15
mov r12, -1
mov r13, r10
lea r14, [r10+rax]
test r10, 1
cmovne r12, rsi
cmove r14, r10
lea r15, [rsi+1]
sub r10, rax
sar r10, 1
sar r14, 1
neg rsi
cmp r12, 0
cmovge rax, r13
cmovl r10, r14
cmovl rsi, r15
mov r12, qword ptr [rsp+8]
mov r13, r10
lea r14, [r10+rax]
test r10, 1
cmovne r12, rsi
cmove r14, r10
lea r15, [rsi+1]
sub r10, rax
sar r10, 1
sar r14, 1
neg rsi
cmp r12, 0
cmovge rax, r13
cmovl r10, r14
cmovl rsi, r15
mov r12, qword ptr [rsp+8]
mov r13, r10
lea r14, [r10+rax]
test r10, 1
cmovne r12, rsi
cmove r14, r10
lea r15, [rsi+1]
sub r10, rax
sar r10, 1
sar r14, 1
neg rsi
cmp r12, 0
cmovge rax, r13
cmovl r10, r14
cmovl rsi, r15
mov r12, qword ptr [rsp+8]
mov r13, r10
lea r14, [r10+rax]
test r10, 1
cmovne r12, rsi
cmove r14, r10
lea r15, [rsi+1]
sub r10, rax
sar r10, 1
sar r14, 1
neg rsi
cmp r12, 0
cmovge rax, r13
cmovl r10, r14
cmovl rsi, r15
mov r12, qword ptr [rsp+8]
mov r13, r10
lea r14, [r10+rax]
test r10, 1
cmovne r12, rsi
cmove r14, r10
lea r15, [rsi+1]
sub r10, rax
sar r10, 1
sar r14, 1
neg rsi
cmp r12, 0
cmovge rax, r13
cmovl r10, r14
cmovl rsi, r15
mov r12, qword ptr [rsp+8]
mov r13, r10
lea r14, [r10+rax]
test r10, 1
cmovne r12, rsi
cmove r14, r10
lea r15, [rsi+1]
sub r10, rax
sar r10, 1
sar r14, 1
neg rsi
cmp r12, 0
cmovge rax, r13
cmovl r10, r14
cmovl rsi, r15
mov r12, qword ptr [rsp+8]
mov r13, r10
lea r14, [r10+rax]
test r10, 1
cmovne r12, rsi
cmove r14, r10
lea r15, [rsi+1]
sub r10, rax
sar r10, 1
sar r14, 1
neg rsi
cmp r12, 0
cmovge rax, r13
cmovl r10, r14
cmovl rsi, r15
mov r12, -1
mov r13, r10
lea r14, [r10+rax]
test r10, 1
cmovne r12, rsi
cmove r14, r10
lea r15, [rsi+1]
sub r10, rax
sar r10, 1
sar r14, 1
neg rsi
cmp r12, 0
cmovge rax, r13
cmovl r10, r14
cmovl rsi, r15
dec r11
jne _loop2
dec r9
je _lastloop

_extract:
mov r11, qword ptr [inv_round41+REG_REL]
lea r12, [r10+r11]
sar r12, 42
mov r13, rdx
imul rdx, r12
lea r11, [rax+r11]
sar r11, 42
imul r13, r11
mov r14, qword ptr [inv_round20+REG_REL]
lea r10, [r10+r14]
shl r10, 22
sar r10, 43
mov r15, rdi
imul r15, r10
lea rax, [rax+r14]
shl rax, 22
sar rax, 43
imul rdi, rax
add rdi, r13
add rdx, r15
sar rdi, 20
sar rdx, 20
mov r13, qword ptr [rsp+576]
imul r13, rax
mov r14, qword ptr [rsp+624]
imul r14, r11
mov r15, qword ptr [rsp+608]
imul rax, r15
mov rbx, qword ptr [rsp+592]
imul r11, rbx
imul r15, r10
imul rbx, r12
imul r10, qword ptr [rsp+576]
imul r12, qword ptr [rsp+624]
add r11, rax
lea rax, [r13+r14+0]
add r10, r12
lea r12, [r15+rbx]

_first_loop:
mov qword ptr [rsp+608], r11
mov qword ptr [rsp+576], rax
mov qword ptr [rsp+592], r12
mov qword ptr [rsp+624], r10
jmp _loop20

_lastloop:
mov rdi, qword ptr [inv_round41+REG_REL]
lea rdx, [r10+rdi]
sar rdx, 42
lea r11, [rax+rdi]
sar r11, 42
mov rdi, qword ptr [rsp+624]
imul rdi, r11
mov r9, qword ptr [rsp+592]
imul r11, r9
imul r9, rdx
mov r12, qword ptr [inv_round20+REG_REL]
lea r13, [r10+r12]
shl r13, 22
sar r13, 43
lea rax, [rax+r12]
shl rax, 22
sar rax, 43
mov r10, qword ptr [rsp+576]
imul r10, rax
mov r12, qword ptr [rsp+608]
imul rax, r12
imul r12, r13
imul rdx, qword ptr [rsp+624]
imul r13, qword ptr [rsp+576]
add r11, rax
lea r10, [r10+rdi]
add r13, rdx
lea r12, [r12+r9]
mov rdi, qword ptr [rsp+640]
mov r14, qword ptr [rsp+656]
mov r9, qword ptr [rsp+672]
mov r15, qword ptr [rsp+688]
dec r8
jne _bigloop
shl r9, 60
shl r15, 60
add rdi, r9
add r14, r15
imul rdi, r10
imul r14, r11
lea rdi, [rdi+r14]
sar rdi, 60
imul r10, rdi
imul r11, rdi

_cneg:
mov rax, qword ptr [rsp+296]
imul r10
mov r9, rdx
mov rbp, rax
mov rax, qword ptr [rsp+312]
imul r11
add rbp, rax
adc r9, rdx
shld r9, rbp, 48
shl rbp, 48
mov rax, qword ptr [rsp+232]
mov rdx, qword ptr [rsp+264]
shl rdx, 30
add rax, rdx
imul r10
mov rcx, rdx
mov r8, rax
mov rax, qword ptr [rsp+248]
mov rdx, qword ptr [rsp+280]
shl rdx, 30
add rax, rdx
imul r11
add r8, rax
adc rcx, rdx
mov rbx, r8
shrd r8, rcx, 12
shl rbx, 52
sar rcx, 12
add rbp, r8
adc r9, rcx
mov rax, qword ptr [rsp+168]
mov rdx, qword ptr [rsp+200]
shl rdx, 30
add rax, rdx
imul r10
mov rcx, rdx
mov r8, rax
mov rax, qword ptr [rsp+184]
mov rdx, qword ptr [rsp+216]
shl rdx, 30
add rax, rdx
imul r11
add r8, rax
adc rcx, rdx
mov rdi, r8
shrd r8, rcx, 8
shl rdi, 56
mov rdx, rcx
sar rcx, 8
sar rdx, 63
add rbx, r8
adc rbp, rcx
adc r9, rdx
mov rax, qword ptr [rsp+104]
mov rdx, qword ptr [rsp+136]
shl rdx, 30
add rax, rdx
imul r10
mov rcx, rdx
mov r8, rax
mov rax, qword ptr [rsp+120]
mov rdx, qword ptr [rsp+152]
shl rdx, 30
add rax, rdx
imul r11
add r8, rax
adc rcx, rdx
mov rsi, r8
shrd r8, rcx, 4
shl rsi, 60
mov rdx, rcx
sar rcx, 4
sar rdx, 63
add rdi, r8
adc rbx, rcx
adc rbp, rdx
adc r9, rdx
mov rax, qword ptr [rsp+40]
mov rdx, qword ptr [rsp+72]
shl rdx, 30
add rax, rdx
imul r10
mov rcx, rdx
mov r8, rax
mov rax, qword ptr [rsp+56]
mov rdx, qword ptr [rsp+88]
shl rdx, 30
add rax, rdx
imul r11
add r8, rax
adc rcx, rdx
mov rdx, rcx
sar rdx, 63
add rsi, r8
adc rdi, rcx
adc rbx, rdx
adc rbp, rdx
adc r9, rdx
btr rbp, 63
adc r9, r9
mov rcx, r9
mov rax, 19
imul r9
sar rcx, 63
xor r9, r9
add rsi, rax
adc rdi, rdx
adc rbx, rcx
adc rbp, rcx
adc r9, rcx
btr rbp, 63
adc r9, r9
mov rcx, r9
mov rax, 19
imul r9
sar rcx, 63
add rsi, rax
adc rdi, rdx
adc rbx, rcx
adc rbp, rcx
adc r9, rcx
xor r9, r9
mov rdx, -19
mov rcx, -1
mov r8, 9223372036854775807
cmp rbp, 0
cmovge rdx, r9
cmovge rcx, r9
cmovge r8, r9
add rsi, rdx
adc rdi, rcx
adc rbx, rcx
adc rbp, r8
add rsi, 19
adc rdi, 0
adc rbx, 0
adc rbp, 0
mov r9, rbp
sar r9, 63
btr rbp, 63
and r9, 19
add rsi, r9
adc rdi, 0
adc rbx, 0
adc rbp, 0
sub rsi, 19
sbb rdi, 0
sbb rbx, 0
sbb rbp, 0

;# inverse in: rbp rbx rdi rsi
;# result ← X2 · Z2^(-1)

xor     r13d, r13d
mov     rdx, qword ptr [rsp+704]
mulx    r9, r8, rsi
mulx    r10, rcx, rdi
adcx    r9, rcx
mulx    r11, rcx, rbx
adcx    r10, rcx
mulx    r12, rcx, rbp
adcx    r11, rcx
adcx    r12, r13 ;# zero
xor     r14d, r14d
mov     rdx, qword ptr [rsp+712]
mulx    rax, rcx, rsi
adcx    r9, rcx
adox    r10, rax
mulx    rax, rcx, rdi
adcx    r10, rcx
adox    r11, rax
mulx    rax, rcx, rbx
adcx    r11, rcx
adox    r12, rax
mulx    rax, rcx, rbp
adcx    r12, rcx
adox    r13, rax
adcx    r13, r14 ;# zero
xor     r15d, r15d
mov     rdx, qword ptr [rsp+720]
mulx    rax, rcx, rsi
adcx    r10, rcx
adox    r11, rax
mulx    rax, rcx, rdi
adcx    r11, rcx
adox    r12, rax
mulx    rax, rcx, rbx
adcx    r12, rcx
adox    r13, rax
mulx    rax, rcx, rbp
adcx    r13, rcx
adox    r14, rax
adcx    r14, r15 ;# zero
xor     eax, eax
mov     rdx, qword ptr [rsp+728]
mulx    rax, rcx, rsi
adcx    r11, rcx
adox    r12, rax
mulx    rax, rcx, rdi
adcx    r12, rcx
adox    r13, rax
mulx    rax, rcx, rbx
adcx    r13, rcx
adox    r14, rax
mulx    rax, rcx, rbp
adcx    r14, rcx
adox    r15, rax
adc     r15, 0
xor     ebp, ebp
mov     rdx, 38
mulx    r12, rax, r12
adcx    r8, rax
adox    r9, r12
mulx    r13, rcx, r13
adcx    r9, rcx
adox    r10, r13
mulx    r14, rcx, r14
adcx    r10, rcx
adox    r11, r14
mulx    r15, rcx, r15
adcx    r11, rcx
adox    r15, rbp ;# zero
adcx    r15, rbp ;# zero
shld    r15, r11, 1
btr     r11, 63
imul    r15, r15, 19
add     r8, r15
adc     r9, 0
adc     r10, 0
adc     r11, 0

;# final reduction to ensure 0 <= result < 2^255-19

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

mov    rdi, qword ptr [rsp+752]

;# output the result
mov    qword ptr [rdi], r8
mov    qword ptr [rdi+8], r9
mov    qword ptr [rdi+16], r10
mov    qword ptr [rdi+24], r11

;# restore registers
mov    rbx, qword ptr [rsp+736]
mov    rbp, qword ptr [rsp+744]
mov    r11, qword ptr [rsp+760]
mov    r12, qword ptr [rsp+768]
mov    r13, qword ptr [rsp+776]
mov    r14, qword ptr [rsp+784]
mov    r15, qword ptr [rsp+792]

add    rsp, r11
