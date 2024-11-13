# Twofish Encryption Algorithm Implementation

## Overview

This repository provides a C implementation of the Twofish encryption algorithm, consisting of `twofish.h` and `twofish.c` files. Twofish is a symmetric key block cipher with a block size of 128 bits and supports key sizes up to 256 bits. It was one of the five finalists in the Advanced Encryption Standard (AES) competition.

This implementation includes functions for key preparation, encryption, and decryption of data using the Twofish algorithm.

## Files

- `twofish.h`: Header file containing function declarations and type definitions.
- `twofish.c`: Source file containing the implementation of the Twofish algorithm.

## Requirements

- C compiler (e.g., GCC)
- Standard C library

## Compilation

`twofish.c` does not contain a `main` function, and should be imported for use. You can compile your project along with `twofish.c`.

### Using GCC

To compile your program that uses Twofish:

```bash
gcc -o my_program my_program.c twofish.c
```

Replace `my_program.c` with the name of your C source file that includes `twofish.h` and uses the Twofish functions.

## Usage

### Including the Twofish Library

In your C source file, include the Twofish header:

```c
#include "twofish.h"
```

### Initialization

Before using any Twofish functions, you must initialize the Twofish implementation:

```c
Twofish_initialise();
```

This function performs necessary initializations and self-tests.

### Preparing the Key

To prepare a key for encryption or decryption, use the `Twofish_prepare_key` function.

#### Function Prototype

```c
void Twofish_prepare_key(
    Twofish_Byte key[],
    int key_len,
    Twofish_key *xkey
);
```

#### Parameters

- `key[]`: An array of bytes containing the encryption key.
- `key_len`: The length of the key in bytes (must be between 0 and 32).
- `xkey`: A pointer to a `Twofish_key` structure that will hold the expanded key.

#### Example

```c
Twofish_key xkey;
Twofish_Byte key[32]; // Your key data (up to 32 bytes)
int key_len = 16;     // For a 128-bit key

// Initialize your key data (example key)
for (int i = 0; i < key_len; i++) {
    key[i] = i; // Replace with your actual key data
}

Twofish_prepare_key(key, key_len, &xkey);
```

### Encryption

To encrypt a 16-byte block of plaintext, use the `Twofish_encrypt` function.

#### Function Prototype

```c
void Twofish_encrypt(
    Twofish_key *xkey,
    Twofish_Byte p[16],
    Twofish_Byte c[16]
);
```

#### Parameters

- `xkey`: A pointer to a `Twofish_key` structure containing the expanded key.
- `p[16]`: An array of 16 bytes containing the plaintext block.
- `c[16]`: An array of 16 bytes where the ciphertext will be stored.

#### Example

```c
Twofish_Byte plaintext[16];  // Your plaintext data
Twofish_Byte ciphertext[16]; // Array to hold the ciphertext

// Initialize your plaintext data
for (int i = 0; i < 16; i++) {
    plaintext[i] = i; // Replace with your actual plaintext data
}

Twofish_encrypt(&xkey, plaintext, ciphertext);

// Now, ciphertext contains the encrypted data
```

### Decryption

To decrypt a 16-byte block of ciphertext, use the `Twofish_decrypt` function.

#### Function Prototype

```c
void Twofish_decrypt(
    Twofish_key *xkey,
    Twofish_Byte c[16],
    Twofish_Byte p[16]
);
```

#### Parameters

- `xkey`: A pointer to a `Twofish_key` structure containing the expanded key.
- `c[16]`: An array of 16 bytes containing the ciphertext block.
- `p[16]`: An array of 16 bytes where the decrypted plaintext will be stored.

#### Example

```c
Twofish_Byte decrypted[16]; // Array to hold the decrypted plaintext

Twofish_decrypt(&xkey, ciphertext, decrypted);

// Now, decrypted contains the original plaintext data
```

### Full Example

Below is a complete example demonstrating the usage of the Twofish implementation.

```c
#include <stdio.h>
#include "twofish.h"

int main() {
    // Initialize Twofish
    Twofish_initialise();

    // Prepare the key
    Twofish_key xkey;
    Twofish_Byte key[16] = {
        0x9F, 0x58, 0x9F, 0x5C,
        0xF6, 0x12, 0x2C, 0x32,
        0xB6, 0xBF, 0xEC, 0x2F,
        0x2A, 0xE8, 0xC3, 0x5A
    };
    int key_len = 16; // 128-bit key

    Twofish_prepare_key(key, key_len, &xkey);

    // Plaintext block
    Twofish_Byte plaintext[16] = {
        0xD4, 0x91, 0xDB, 0x16,
        0xE7, 0xB1, 0xC3, 0x9E,
        0x86, 0xCB, 0x08, 0x6B,
        0x78, 0x9F, 0x54, 0x19
    };

    // Arrays to hold ciphertext and decrypted plaintext
    Twofish_Byte ciphertext[16];
    Twofish_Byte decrypted[16];

    // Encrypt
    Twofish_encrypt(&xkey, plaintext, ciphertext);

    // Decrypt
    Twofish_decrypt(&xkey, ciphertext, decrypted);

    // Output the results
    printf("Plaintext:  ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", plaintext[i]);
    }
    printf("\n");

    printf("Ciphertext: ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", ciphertext[i]);
    }
    printf("\n");

    printf("Decrypted:  ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", decrypted[i]);
    }
    printf("\n");

    return 0;
}
```

**Save this as `example.c`.**

Compile and run:

```bash
gcc -o twofish_example example.c twofish.c
./twofish_example
```

### Expected Output

```
Plaintext:  D4 91 DB 16 E7 B1 C3 9E 86 CB 08 6B 78 9F 54 19
Ciphertext: 01 9F 98 09 DE 17 11 85 8F AA C3 A3 BA 20 FB C3
Decrypted:  D4 91 DB 16 E7 B1 C3 9E 86 CB 08 6B 78 9F 54 19
```

## Important Notes

- **Block Size**: Twofish operates on 16-byte (128-bit) blocks. If your data is not a multiple of 16 bytes, you need to implement padding (e.g., PKCS#7 padding) or use a block cipher mode that handles incomplete blocks (e.g., CFB, OFB, or CTR modes). This implementation only provides the basic block cipher functionality.

- **Key Sizes**: The Twofish algorithm supports key sizes up to 32 bytes (256 bits). Valid key lengths are from 0 to 32 bytes. Keys shorter than 16, 24, or 32 bytes will be zero-padded to the next valid key size internally.

- **Endianness**: This implementation handles endianness internally. No special handling is required from the user.

- **Thread Safety**: This implementation is not thread-safe. If you plan to use it in a multi-threaded environment, ensure that the `Twofish_initialise` function is called only once, and that each thread uses its own `Twofish_key` structure.

## Self-Test

The `Twofish_initialise` function includes a self-test that verifies the correctness of the implementation using known test vectors. If the self-test fails, the program will terminate with an error message.
