This library provides four constant-time implementations of scalar multiplication on Curve25519:

1. **PORTABLE** is a C-language implementation based on public domain "ref10" code by Daniel J. Bernstein. It uses 26-bit limbs.
2. **ARM64** is an optimized 100% assembly implementation for 64-bit ARM CPUs written by Emil Lenngren. It uses 26-bit limbs and can run 3 field operations in parallel by interleaving A64 and NEON instructions.
3. **AMD64** is an optimized 100% assembly implementation for 64-bit x86 CPUs. It uses 64-bit limbs.
4. **AMD64X** is an optimized 100% assembly implementation targeting AMD Ryzen, Intel Broadwell and newer CPUs. It uses the `mulx`, `adcx` and `adox` instructions with 64-bit limbs.

A specific implementation can be selected at runtime using the [API](include/mx25519.h). Passing the `MX25519_TYPE_AUTO` flag automatically selects the fastest implementation supported by the current machine.

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

