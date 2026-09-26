This library provides four constant-time implementations of scalar multiplication on Curve25519:

1. **PORTABLE** is a portable C-language implementation. It uses 25.5-bit limbs.
2. **ARM64** is an optimized assembly implementation for 64-bit ARM CPUs. It uses 25.5-bit limbs and the safegcd inversion.
3. **AMD64** is an optimized assembly implementation for 64-bit x86 CPUs. It uses 64-bit limbs.
4. **AMD64X** is an optimized assembly implementation targeting AMD Ryzen, Intel Broadwell and newer CPUs. It uses 64-bit limbs and the safegcd inversion.

A specific implementation can be selected at runtime using the [API](include/mx25519.h). Passing the `MX25519_TYPE_AUTO` flag automatically selects the fastest available implementation supported by the current machine.

**Important note**: This library does not perform internal clamping of the private key as specified in [RFC 7748](https://www.rfc-editor.org/info/rfc7748). This is a deliberate design choice to allow use-cases that require unclamped private keys (for example [Carrot](https://github.com/jeffro256/carrot/blob/master/carrot.md)). It is the caller's responsibility to clamp the private key as needed before calling `mx25519_scmul_base_unclamped` or `mx25519_scmul_key_unclamped`.

## Build

```
git clone https://github.com/tevador/mx25519.git
cd mx25519
mkdir build
cd build
cmake ..
make
```
```
./mx25519-tests
./mx25519-bench
```

On Windows, building with Visual Studio is also supported.

## Performance

Tested on AMD Ryzen 7 3700X (Turbo disabled):

| implementation | cycles per scalar mult. |
|----------------|-------------------------|
| PORTABLE       |   330 300               |
| AMD64          |   125 300               |
| AMD64X         |    94 600               |

Tested on ARM Cortex-A53:

| implementation | cycles per scalar mult. |
|----------------|-------------------------|
| PORTABLE       |   524 900               |
| ARM64          |   137 300               |

## Security

The assembly implementations have been verified to be constant-time with respect to secret values on commonly used hardware. The assembly implementations wipe all secrets from the registers and the stack before returning.

The portable C implementation makes a best-effort attempt to be constant-time with respect to secret values and to wipe all secrets from the stack. These properties ultimately depend on the compiler.

## License

The optimized assembly backends are licensed under the [Mozilla Public License 2.0](LICENSE-MPL). Everything else, including the portable implementation, is licensed under the [Apache License 2.0](LICENSE-APACHE). Each source file carries the notice of the license that applies to it.

Building with `cmake .. -DMX25519_COPYLEFT=off` excludes all MPL-licensed files. In that case, only the portable C-language backend is available (attempts to select the optimized backends will return `NULL`).

The NOTICE file must be included in all source and binary distributions of the software.
