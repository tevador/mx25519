;# Copyright (c) 2022-2026 tevador <tevador@gmail.com>
;#
;# This file is part of mx25519, which is released under LGPLv3.
;# See LICENSE for full license details.

invtable:
;#     square times,
;#    	     skip mul,
;#                 mulsource,
;#    	                  destination
db     1,    1,    0,     1
db     2,    0,    2,     2
db     0,    0,    1,     1
db     1,    0,    2,     2
db     5,    0,    2,     2
db    10,    0,    2,     3
db    20,    0,    3,     0
db    10,    0,    2,     2
db    50,    0,    2,     3
db   100,    0,    3,     0
db    50,    0,    2,     0
db     5,    0,    1,     0
db     0,    0,    0,     0

p0:
db 237, 255, 255, 255, 255, 255, 255, 255
p12:
db 255, 255, 255, 255, 255, 255, 255, 255
p3:
db 255, 255, 255, 255, 255, 255, 255, 127

inv_bias62:  ;# 0xc000000000000000
db 0, 0, 0, 0, 0, 0, 0, 192
inv_round20: ;# 0x100000
db 0, 0, 16, 0, 0, 0, 0, 0
inv_bias41:  ;# 0xfffffe0000000000
db 0, 0, 0, 0, 0, 254, 255, 255
inv_round41: ;# 0x20000100000
db 0, 0, 16, 0, 0, 2, 0, 0
