;# Copyright (c) 2022 tevador <tevador@gmail.com>
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
