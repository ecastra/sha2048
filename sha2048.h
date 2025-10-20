#ifndef SHA2048_H
#define SHA2048_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>
#include <stdint.h>

/****************************** MACROS ******************************/
#define SHA2048_BLOCK_SIZE 256   ///< Block size in bytes (2048 bits)
#define SHA2048_DIGEST_SIZE 256  ///< Digest size in bytes (2048 bits)

/**************************** DATA TYPES ****************************/

/**
 * @brief Context structure for a SHA-2048 hashing operation.
 */
typedef struct {
	uint8_t  data[SHA2048_BLOCK_SIZE]; ///< Buffer for the current block
	uint32_t datalen;                  ///< Bytes used in the current data block
	uint64_t bitlen[2];                ///< 128-bit message length counter
	uint64_t state[32];                ///< 32 * 64-bit = 2048-bit internal state
} SHA2048_CTX;

/*********************** FUNCTION DECLARATIONS **********************/

/**
 * @brief Initializes a SHA-2048 context.
 * @param ctx Pointer to the context to initialize.
 */
void sha2048_init(SHA2048_CTX *ctx);

/**
 * @brief Processes a chunk of data. This function can be called multiple times.
 * @param ctx Pointer to the SHA-2048 context.
 * @param data Pointer to the data to hash.
 * @param len Length of the data in bytes.
 */
void sha2048_update(SHA2048_CTX *ctx, const uint8_t data[], size_t len);

/**
 * @brief Finalizes the hash computation and produces the digest.
 * @param ctx Pointer to the SHA-2048 context. After this call, the context is invalid and must be re-initialized.
 * @param hash Buffer to store the 256-byte (2048-bit) hash digest.
 */
void sha2048_final(SHA2048_CTX *ctx, uint8_t hash[]);

/**
 * @brief Runs a self-test to verify the correctness of the implementation.
 *
 * This function computes the SHA-2048 hash of the ASCII string "abc" and
 * compares it against a known-correct vector.
 *
 * @return 0 on success, 1 on failure.
 */
int sha2048_selftest(void);

/**
 * @brief Prints the cryptographic constants used by the algorithm.
 *
 * This function is provided for forensic and academic consistency, allowing
 * other researchers to verify the initial state (H) and round constants (K).
 */
void sha2048_print_constants(void);

#endif // SHA2048_H
