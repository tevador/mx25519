/* Copyright (c) 2022-2026 tevador <tevador@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifndef CPU_H
#define CPU_H

#include <mx25519.h>

typedef enum x25519_cpu_cap {
    X25519_CPU_CAP_AVX = 2,
    X25519_CPU_CAP_AVX2 = 4,
    X25519_CPU_CAP_MULX = 8,
    X25519_CPU_CAP_ADX = 16,
    X25519_CPU_CAP_BMI1 = 32,
} x25519_cpu_cap;

MX25519_PRIVATE x25519_cpu_cap mx25519_get_cpu_cap(void);

#endif
