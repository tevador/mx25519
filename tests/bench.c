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

#include "platform.h"

#include <stdio.h>
#include <math.h>

#include <mx25519.h>

#ifdef _DEBUG
#define BENCH_LOOPS 10
#else
#define BENCH_LOOPS 100000
#endif

typedef double bench_func();

static const mx25519_privkey test_key = { {
    102, 66, 236, 240, 6, 149, 92, 7, 43, 107, 163, 255, 64, 145, 5, 203,
    230, 54, 147, 234, 197, 5, 215, 214, 124, 189, 226, 219, 235, 71, 20, 254 } };

double bench_impl(mx25519_type type) {
    const mx25519_impl* impl = mx25519_select_impl(type);

    if (impl == NULL) {
        return NAN;
    }

    mx25519_pubkey result = { { 9 } };

    uint64_t elapsed = 0;
    uint64_t start = mx25519_cpu_cycles();
    for (uint32_t i = 0; i < BENCH_LOOPS; ++i) {
        mx25519_scmul_key_unclamped(impl, &result, &test_key, &result);
    }
    uint64_t end = mx25519_cpu_cycles();
    elapsed += (end - start);

    return elapsed / (double)BENCH_LOOPS;
}

double bench_portable() {
    return bench_impl(MX25519_TYPE_PORTABLE);
}

double bench_arm64() {
    return bench_impl(MX25519_TYPE_ARM64);
}

double bench_amd64() {
    return bench_impl(MX25519_TYPE_AMD64);
}

double bench_amd64x() {
    return bench_impl(MX25519_TYPE_AMD64X);
}

static void run_bench(const char* name, bench_func* func) {
    printf("    %-40s ... ", name);
    double cycles = func();
    if (isnan(cycles)) {
        printf("N/A\n");
    }
    else {
        printf("%.0f cycles/op.\n", cycles);
    }
}

#define RUN_BENCH(x) run_bench(#x, &x)

int main(int argc, const char* argv[]) {

    double wall_start = mx25519_wall_clock();
    uint64_t cpu_start = mx25519_cpu_cycles();

    RUN_BENCH(bench_portable);
    RUN_BENCH(bench_arm64);
    RUN_BENCH(bench_amd64);
    RUN_BENCH(bench_amd64x);

    double wall_end = mx25519_wall_clock();
    uint64_t cpu_end = mx25519_cpu_cycles();

    printf("\nCPU timer runs at %.3f MHz\n", (cpu_end - cpu_start) / (wall_end - wall_start) / 1e6);

    return 0;
}
