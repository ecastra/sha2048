# SHA-2048: A High-Performance Implementation

![Language](https://img.shields.io/badge/Language-C-blue.svg)
![Vectorization](https://img.shields.io/badge/Vectorization-AVX2-orange.svg)
![License](https://img.shields.io/badge/License-Zlib-lightgrey.svg)

> **⚠️ Security Warning:** This is a non-standard cryptographic hash function. It has **not** undergone peer review or formal cryptanalysis. It is provided for academic, research, and performance demonstration purposes only. **DO NOT USE THIS FOR PRODUCTION CRYPTOGRAPHY.**

## What is this?

This repository contains a state-of-the-art C implementation of **SHA-2048**, a hypothetical hash function built upon the principles of the NIST standard SHA-512. It is designed to showcase advanced optimization techniques and explore a novel method for scaling hash function designs.

The algorithm produces a **2048-bit (256-byte)** digest from an input of any size.

## Key Features

This isn't just a simple C file; it's a high-performance engine featuring:

*   **🚀 AVX2 Vectorization:** The core compression logic is heavily optimized using AVX2 SIMD intrinsics, processing a massive 2048-bit state in parallel for maximum throughput.
*   **🧠 Runtime Dispatch:** The code automatically detects the host CPU's capabilities at runtime. If AVX2 is present, it uses the ultra-fast vectorized code path. If not, it seamlessly falls back to a portable and correct scalar C implementation. One binary, best performance.
*   **🔧 "Four Interlocking Gears" Design:** A novel architectural concept that manages the 2048-bit state as four parallel 512-bit "gears" that are interlocked to ensure full diffusion and avalanche effect.
*   **✅ Self-Validation:** Includes a known-answer test to verify correctness on both the scalar and AVX2 code paths.

## The "Four Interlocking Gears" Design - A Deeper Dive

A core challenge in designing a hash function with a very large internal state (like 2048 bits) is ensuring that a small change in the input affects the *entire* state. Simply running four SHA-512 instances in parallel would be insecure, as they would never mix.

This implementation solves this with the "Four Interlocking Gears" model.

1.  **The State:** The 2048-bit state is divided into four 512-bit "gears." Each gear is a set of 8 x 64-bit working variables (`a, b, c, d, e, f, g, h`), just like in standard SHA-512.
    *   **Gear 0:** `state[0]`...`state[7]`
    *   **Gear 1:** `state[8]`...`state[15]`
    *   **Gear 2:** `state[16]`...`state[23]`
    *   **Gear 3:** `state[24]`...`state[31]`

2.  **The Interlock:** The innovation is in the "interlock" mechanism. In each round, the calculation for a gear is made dependent on a value from the *previous* gear. Specifically, the `h` register from gear `j-1` is mixed into the calculation for gear `j`.

This creates a circular dependency chain that forces data to propagate across all four gears:

> **Gear 3 → Gear 0 → Gear 1 → Gear 2 → (repeats)**

This elegant design ensures that the entire 2048-bit state is thoroughly mixed over the algorithm's 128 rounds.

### Performance: Scalar vs. AVX2

*   **Scalar Path (`sha2048_transform_scalar`):** The reference implementation in portable C. It is easy to read and serves as the ground truth for the algorithm's logic.
*   **AVX2 Path (`sha2048_transform_avx2`):** The high-performance path. It uses a **transposed state** layout, where 256-bit AVX2 registers hold the same variable from all four gears (e.g., one register holds `[a0, a1, a2, a3]`). This allows a single SIMD instruction to perform an operation on all four gears at once, yielding a massive performance boost.

## Building and Running

You will need a C compiler that supports AVX2 intrinsics (like GCC, Clang, or MSVC).

### Compilation

#### GCC / Clang
```bash
# Compile with standard optimizations
gcc -O3 sha2048.c -o sha2048_test

# To guarantee the AVX2 path is compiled, you can add the flag:
gcc -O3 -mavx2 sha2048.c -o sha2048_test_avx2
```

#### MSVC (Visual Studio Command Prompt)
```bash
# Compile with optimizations and AVX2 support
cl /O2 /arch:AVX2 sha2048.c
```

### Running the Self-Test
The code includes a `sha2048_selftest()` function. To run it, you would create a `main.c` file like this:

**main.c:**
```c
#include "sha2048.h"

int main() {
    // The self-test will automatically detect AVX2 and report which path it used.
    return sha2048_selftest();
}
```
Then compile and run:
```bash
# Link the main file with the implementation
gcc -O3 sha2048.c main.c -o run_test

# Execute the test
./run_test
```

**Expected Output:**
```
SHA-2048 self-test PASSED (using AVX2 path).
```
or
```
SHA-2048 self-test PASSED (using Scalar path).
```

## API Usage

Integrating SHA-2048 into your project is straightforward and follows the standard `init`, `update`, `final` pattern.

### Example

```c
#include <stdio.h>
#include <string.h>
#include "sha2048.h"

int main() {
    // 1. Initialize the context structure
    SHA2048_CTX ctx;
    sha2048_init(&ctx);

    // 2. Feed data to the hash function (can be called multiple times)
    const char *message1 = "This is a test of the hypothetical SHA-2048 ";
    const char *message2 = "hashing algorithm.";
    sha2048_update(&ctx, (const uint8_t*)message1, strlen(message1));
    sha2048_update(&ctx, (const uint8_t*)message2, strlen(message2));

    // 3. Finalize the hash and get the result
    uint8_t hash[SHA2048_DIGEST_SIZE];
    sha2048_final(&ctx, hash);

    // 4. Print the resulting 2048-bit (256-byte) hash
    printf("SHA-2048 Hash:\n");
    for (int i = 0; i < SHA2048_DIGEST_SIZE; i++) {
        printf("%02x", hash[i]);
        if ((i + 1) % 32 == 0) {
            printf("\n");
        }
    }

    return 0;
}
```
