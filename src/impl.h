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

#ifndef IMPL_H
#define IMPL_H

#include <mx25519.h>

#include <stdint.h>

typedef void scmul_func(uint8_t result[32],
    const uint8_t key[32],
    const uint8_t base[32]);

typedef struct mx25519_impl {
    scmul_func* scmul;
    mx25519_type type;
} mx25519_impl;

extern MX25519_PRIVATE const mx25519_impl* const mx25519_impls[4];

#endif
