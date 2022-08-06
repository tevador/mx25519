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

loop_byte_x:

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
xor    r13, r13
mov    rdx, qword ptr [rsp+32]
mulx   r9, r8, qword ptr [rsp+64]
mulx   r10, rcx, qword ptr [rsp+72]
adcx   r9, rcx
mulx   r11, rcx, qword ptr [rsp+80]
adcx   r10, rcx
mulx   r12, rcx, qword ptr [rsp+88]
adcx   r11, rcx
adcx   r12, r13
xor    r14, r14
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
xor    r15, r15
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
xor    rax, rax
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
xor    rbp, rbp
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
xor    r13, r13
mov    rdx, qword ptr [rsp+0]
mulx   r9, r8, qword ptr [rsp+96]
mulx   r10, rcx, qword ptr [rsp+104]
adcx   r9, rcx
mulx   r11, rcx, qword ptr [rsp+112]
adcx   r10, rcx
mulx   r12, rcx, qword ptr [rsp+120]
adcx   r11, rcx
adcx   r12, r13
xor    r14, r14
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
xor    r15, r15
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
xor    rax, rax
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
xor    rbp, rbp
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
xor    r13, r13
mov    rdx, rax
mulx   r10, r9, rbx
mulx   r11, rcx, rbp
adcx   r10, rcx
mulx   r12, rcx, rsi
adcx   r11, rcx
adcx   r12, r13
xor    r14, r14
mov    rdx, rbx
mulx   rdi, rcx, rbp
adcx   r11, rcx
adox   r12, rdi
mulx   rdi, rcx, rsi
adcx   r12, rcx
adox   r13, rdi
adcx   r13, r14
xor    r15, r15
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
xor    rdx, rdx
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
xor    rdi, rdi
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
xor    r13, r13
mov    rdx, qword ptr [rsp+0]
mulx   r10, r9, qword ptr [rsp+8]
mulx   r11, rcx, qword ptr [rsp+16]
adcx   r10, rcx
mulx   r12, rcx, qword ptr [rsp+24]
adcx   r11, rcx
adcx   r12, r13
xor    r14, r14
mov    rdx, qword ptr [rsp+8]
mulx   rdi, rcx, qword ptr [rsp+16]
adcx   r11, rcx
adox   r12, rdi
mulx   rdi, rcx, qword ptr [rsp+24]
adcx   r12, rcx
adox   r13, rdi
adcx   r13, r14
xor    r15, r15
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
xor    rdx, rdx
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
xor    rdi, rdi
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
mov    rdi, 0
mov    rcx, 38
cmovae rcx, rdi
sub    rax, rcx
sbb    rbx, rdi
sbb    rbp, rdi
sbb    rsi, rdi
cmovb  rdi, rcx
sub    rax, rdi

;# Z3 ← Z3^2
xor    r13, r13
mov    rdx, rax
mulx   r10, r9, rbx
mulx   r11, rcx, rbp
adcx   r10, rcx
mulx   r12, rcx, rsi
adcx   r11, rcx
adcx   r12, r13
xor    r14, r14
mov    rdx, rbx
mulx   rdi, rcx, rbp
adcx   r11, rcx
adox   r12, rdi
mulx   rdi, rcx, rsi
adcx   r12, rcx
adox   r13, rdi
adcx   r13, r14
xor    r15, r15
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
xor    rdx, rdx
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
xor    rdi, rdi
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
xor    r13, r13
mov    rdx, qword ptr [rsp+192]
mulx   r10, r9, qword ptr [rsp+200]
mulx   r11, rcx, qword ptr [rsp+208]
adcx   r10, rcx
mulx   r12, rcx, qword ptr [rsp+216]
adcx   r11, rcx
adcx   r12, r13
xor    r14, r14
mov    rdx, qword ptr [rsp+200]
mulx   rdi, rcx, qword ptr [rsp+208]
adcx   r11, rcx
adox   r12, rdi
mulx   rdi, rcx, qword ptr [rsp+216]
adcx   r12, rcx
adox   r13, rdi
adcx   r13, r14
xor    r15, r15
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
xor    rdx, rdx
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
xor    rdi, rdi
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
mov    rbp, 0
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
xor    r12, r12
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
mov    rbp, 0
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
xor    r13, r13
mov    rdx, qword ptr [rsp+0]
mulx   r9, r8, qword ptr [rsp+32]
mulx   r10, rcx, qword ptr [rsp+40]
adcx   r9, rcx
mulx   r11, rcx, qword ptr [rsp+48]
adcx   r10, rcx
mulx   r12, rcx, qword ptr [rsp+56]
adcx   r11, rcx
adcx   r12, r13
xor    r14, r14
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
xor    r15, r15
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
xor    rax, rax
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
xor    rbp, rbp
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
xor    r13, r13
mov    rdx, qword ptr [rsp+96]
mulx   r9, r8, qword ptr [rsp+64]
mulx   r10, rcx, qword ptr [rsp+72]
adcx   r9, rcx
mulx   r11, rcx, qword ptr [rsp+80]
adcx   r10, rcx
mulx   r12, rcx, qword ptr [rsp+88]
adcx   r11, rcx
adcx   r12, r13
xor    r14, r14
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
xor    r15, r15
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
xor    rax, rax
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
xor    rbp, rbp
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
xor    r13, r13
mov    rdx, qword ptr [rsp+256]
mulx   r9, r8, qword ptr [rsp+128]
mulx   r10, rcx, qword ptr [rsp+136]
adcx   r9, rcx
mulx   r11, rcx, qword ptr [rsp+144]
adcx   r10, rcx
mulx   r12, rcx, qword ptr [rsp+152]
adcx   r11, rcx
adcx   r12, r13
xor    r14, r14
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
xor    r15, r15
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
xor    rax, rax
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
xor    rbp, rbp
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

movzx  ecx, byte ptr [rsp+352]
sub    ecx, 1
mov    byte ptr [rsp+352], cl
;cmp    cl, 0
jge    loop_bit_x

mov    byte ptr [rsp+352], 7
lea    rsi, [rsp+360]
mov    eax, dword ptr [rsp+356]
sub    eax, 1
mov    dword ptr [rsp+356], eax
;cmp    eax, 0
jge    loop_byte_x

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

inv_loop_x:
;# ecx = current instruction
mov    ecx, dword ptr [r12]
test   cl, cl
jz     skip_square_x

square_loop_x:
xor    r13, r13
mov    rdx, r8
mulx   rax, rbp, r9
mulx   rsi, rdi, r10
adcx   rax, rdi
mulx   r12, rdi, r11
adcx   rsi, rdi
adcx   r12, r13
mov    rdx, r9
xor    r14, r14
mulx   rdx, rdi, r10
adcx   rsi, rdi
adox   r12, rdx
mov    rdx, r9
mulx   rdx, rdi, r11
adcx   r12, rdi
adox   r13, rdx
adcx   r13, r14
xor    r15, r15
mov    rdx, r10
mulx   r14, rdi, r11
adcx   r13, rdi
adcx   r14, r15
shld   r15, r14, 1
shld   r14, r13, 1
shld   r13, r12, 1
shld   r12, rsi, 1
shld   rsi, rax, 1
shld   rax, rbp, 1
shl    rbp, 1
xor    rdx, rdx
mov    rdx, r8
mulx   rdx, rbx, rdx
adcx   rbp, rdx
mov    rdx, r9
mulx   rdx, rdi, rdx
adcx   rax, rdi
adcx   rsi, rdx
mov    rdx, r10
mulx   rdx, rdi, rdx
adcx   r12, rdi
adcx   r13, rdx
mov    rdx, r11
mulx   rdx, rdi, rdx
adcx   r14, rdi
adcx   r15, rdx
;xor    r9, r9
mov    rdx, 38
mulx   r9, r8, r12
xor    r12, r12
adcx   r8, rbx
adox   r9, rbp
mulx   r10, rdi, r13
adcx   r9, rdi
adox   r10, rax
mulx   r11, rdi, r14
adcx   r10, rdi
adox   r11, rsi
mulx   r15, rdi, r15
adcx   r11, rdi
adox   r15, r12 ;# zero
adcx   r15, r12 ;# zero
shld   r15, r11, 1
btr    r11, 63
imul   r15, r15, 19
add    r8, r15
adc    r9, 0
adc    r10, 0
adc    r11, 0
sub    cl, 1
jnz    square_loop_x

skip_square_x:
shr    ecx, 8
test   cl, cl
jnz    skip_mul_x

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
xor    r13, r13
mov    rdx, qword ptr [rbx]
mulx   r9, r8, qword ptr [rdi]
mulx   r10, rsi, qword ptr [rdi+8]
adcx   r9, rsi
mulx   r11, rsi, qword ptr [rdi+16]
adcx   r10, rsi
mulx   r12, rsi, qword ptr [rdi+24]
adcx   r11, rsi
adcx   r12, r13 ;# zero
xor    r14, r14
mov    rdx, qword ptr [rbx+8]
mulx   rbp, rsi, qword ptr [rdi]
adcx   r9, rsi
adox   r10, rbp
mulx   rbp, rsi, qword ptr [rdi+8]
adcx   r10, rsi
adox   r11, rbp
mulx   rbp, rsi, qword ptr [rdi+16]
adcx   r11, rsi
adox   r12, rbp
mulx   rbp, rsi, qword ptr [rdi+24]
adcx   r12, rsi
adox   r13, rbp
adcx   r13, r14 ;#zero
xor    r15, r15
mov    rdx, qword ptr [rbx+16]
mulx   rbp, rsi, qword ptr [rdi]
adcx   r10, rsi
adox   r11, rbp
mulx   rbp, rsi, qword ptr [rdi+8]
adcx   r11, rsi
adox   r12, rbp
mulx   rbp, rsi, qword ptr [rdi+16]
adcx   r12, rsi
adox   r13, rbp
mulx   rbp, rsi, qword ptr [rdi+24]
adcx   r13, rsi
adox   r14, rbp
adcx   r14, r15
xor    rax, rax
mov    rdx, qword ptr [rbx+24]
mulx   rbp, rsi, qword ptr [rdi]
adcx   r11, rsi
adox   r12, rbp
mulx   rbp, rsi, qword ptr [rdi+8]
adcx   r12, rsi
adox   r13, rbp
mulx   rbp, rsi, qword ptr [rdi+16]
adcx   r13, rsi
adox   r14, rbp
mulx   rbp, rsi, qword ptr [rdi+24]
adcx   r14, rsi
adox   r15, rbp
adcx   r15, rax ;# zero
xor    rbp, rbp
mov    rdx, 38
mulx   r12, rax, r12
adcx   r8, rax
adox   r9, r12
mulx   r13, rsi, r13
adcx   r9, rsi
adox   r10, r13
mulx   r14, rsi, r14
adcx   r10, rsi
adox   r11, r14
mulx   r15, rsi, r15
adcx   r11, rsi
adox   r15, rbp ;# zero
adcx   r15, rbp ;# zero
shld   r15, r11, 1
btr    r11, 63
imul   r15, r15, 19
add    r8, r15
adc    r9, 0
adc    r10, 0
adc    r11, 0

skip_mul_x:
shr    ecx, 11
jz     skip_store_x

add    rcx, rsp

;# store temp T[1-3]
mov    qword ptr [rcx], r8
mov    qword ptr [rcx+8], r9
mov    qword ptr [rcx+16], r10
mov    qword ptr [rcx+24], r11

skip_store_x:
mov    ebx, dword ptr [rsp+352]
add    ebx, 4
lea    r12, [invtable+REG_REL]
add    r12, rbx
mov    dword ptr [rsp+352], ebx

cmp   ebx, 52
jb    inv_loop_x

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
