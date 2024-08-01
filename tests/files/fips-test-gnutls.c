/** Simple C program that will calculate the hash of a fixed string using
 * GnuTLS.
 *
 * The hash to be used is passed as the first parameter to the binary.
 * This program demonstrates the use of GnuTLS for computing message digests.
 */

#include <stdio.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <stdlib.h>
#include <assert.h>

int main(int argc, char *argv[]) {
    gnutls_digest_algorithm_t digest_algorithm;
    const char *mess1 = "Test Message\n";
    const char *mess2 = "Hello World\n";
    unsigned char md_value[128]; // Adjusted size for two concatenated hash results
    size_t md_len;

    if (argc < 2) {
        fprintf(stderr, "Usage: mdtest digestname\n");
        return 1;
    }

    // Initialize GnuTLS
    gnutls_global_init();

    // Get the digest algorithm from the name
    digest_algorithm = gnutls_digest_get_id(argv[1]);
    if (digest_algorithm == GNUTLS_DIG_UNKNOWN) {
        fprintf(stderr, "Unknown message digest %s\n", argv[1]);
        gnutls_global_deinit();
        return 1;
    }

    // Calculate the first hash
    unsigned char hash1[64]; // Buffer to store the first hash result
    size_t hash1_size = gnutls_hash_get_len(digest_algorithm);
    if (gnutls_hash_fast(digest_algorithm, (const unsigned char *)mess1, strlen(mess1), hash1) != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "Hash calculation failed for the first message\n");
        gnutls_global_deinit();
        return 1;
    }

    // Calculate the second hash
    unsigned char hash2[64]; // Buffer to store the second hash result
    size_t hash2_size = gnutls_hash_get_len(digest_algorithm);
    if (gnutls_hash_fast(digest_algorithm, (const unsigned char *)mess2, strlen(mess2), hash2) != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "Hash calculation failed for the second message\n");
        gnutls_global_deinit();
        return 1;
    }

    // Concatenate hashes to compute the final result (for simplicity)
    memcpy(md_value, hash1, hash1_size);
    memcpy(md_value + hash1_size, hash2, hash2_size);
    md_len = hash1_size + hash2_size;

    // Cleanup
    gnutls_global_deinit();

    // Print the resulting digest
    printf("Digest is: ");
    for (size_t i = 0; i < md_len; i++) {
        printf("%02x", md_value[i]);
    }
    printf("\n");

    return 0;
}