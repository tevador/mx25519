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

#ifndef PORTABLE_SCALARMULT_H
#define PORTABLE_SCALARMULT_H

#include <mx25519.h>

#include <stdint.h>

MX25519_PRIVATE void mx25519_scalarmult_portable(uint8_t* q,
    const uint8_t* n,
    const uint8_t* p);

#endif
