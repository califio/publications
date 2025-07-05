#include "mbedtls/platform.h"
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#include "mbedtls/pem.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>  
#include <ctype.h>

#define BUFFER_SIZE 2048
int dummy_entropy(void *data, unsigned char *output, size_t len);
int dummy_random(void *p_rng, unsigned char *output, size_t output_len);
int test_rsa_verify_pkcs1(json_t *test_group);
void hex_to_bin(const char *hex, unsigned char *bin, size_t *len);
void hexdump(void *ptr, unsigned int buflen);
int load_rsa_key(mbedtls_rsa_context *rsa, json_t *test_group) ;

void hexdump(void *ptr, unsigned int buflen) {
  unsigned char *buf = (unsigned char*)ptr;
  unsigned int i, j;
  for (i=0; i<buflen; i+=16) {
    printf("%06x: ", i);
    for (j=0; j<16; j++) 
      if (i+j < buflen)
        printf("%02x ", buf[i+j]);
      else
        printf("   ");
    printf(" ");
    for (j=0; j<16; j++) 
      if (i+j < buflen)
        printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
    printf("\n");
  }
}

int dummy_random(void *p_rng, unsigned char *output, size_t output_len)
{
    int ret;
    size_t i;

#if defined(MBEDTLS_CTR_DRBG_C)
    //mbedtls_ctr_drbg_random requires a valid mbedtls_ctr_drbg_context in p_rng
    if (p_rng != NULL) {
        //use mbedtls_ctr_drbg_random to find bugs in it
        ret = mbedtls_ctr_drbg_random(p_rng, output, output_len);
    } else {
        //fall through to pseudo-random
        ret = 0;
    }
#else
    (void) p_rng;
    ret = 0;
#endif
    for (i = 0; i < output_len; i++) {
        //replace result with pseudo random
        output[i] = (unsigned char) rand();
    }
    return ret;
}
int dummy_entropy(void *data, unsigned char *output, size_t len)
{
    size_t i;
    (void) data;

    //use mbedtls_entropy_func to find bugs in it
    //test performance impact of entropy
    //ret = mbedtls_entropy_func(data, output, len);
    for (i = 0; i < len; i++) {
        //replace result with pseudo random
        output[i] = (unsigned char) rand();
    }
    return 0;
}

void hex_to_bin(const char *hex, unsigned char *bin, size_t *len) {
    size_t hex_len = strlen(hex);
    *len = hex_len / 2;
    for (size_t i = 0; i < *len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bin[i]);
    }
}

int load_rsa_key(mbedtls_rsa_context *rsa, json_t *test_group) {
    const char *n_hex = json_string_value(json_object_get(test_group, "n"));
    const char *e_hex = json_string_value(json_object_get(test_group, "e"));
    if (!n_hex || !e_hex ) return -1;

    mbedtls_mpi N, E;
    mbedtls_mpi_init(&N); mbedtls_mpi_init(&E);

    mbedtls_mpi_read_string(&N, 16, n_hex);
    mbedtls_mpi_read_string(&E, 16, e_hex);

    mbedtls_rsa_import(rsa, &N, NULL, NULL, NULL, &E);
    mbedtls_rsa_complete(rsa);

    mbedtls_mpi_free(&N); mbedtls_mpi_free(&E);
    return 0;
}

int test_rsa_verify_pkcs1(json_t *test_group) {
    int ret;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_md_type_t md_type ;
    unsigned int md_size;
    const char *pers = "rsa_test";

    // 
    mbedtls_rsa_init(&rsa);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // 
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, dummy_entropy, &entropy,
                              (const unsigned char *)pers, strlen(pers)) != 0) {
        fprintf(stderr, "Failed to seed DRBG\n");
        return -1;
    }
    if (load_rsa_key(&rsa, test_group) != 0) {
        printf("Failed to load RSA key.\n");
        goto exit;
    }
    const char *hash_type = json_string_value(json_object_get(test_group, "sha"));
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_string(hash_type);
    if (md_info == NULL) {
        if(strcmp(hash_type, "SHA-224") == 0){
            md_type = MBEDTLS_MD_SHA224;
            md_size = 28;
        }else if(strcmp(hash_type, "SHA-256") == 0){
            md_type = MBEDTLS_MD_SHA256;
            md_size = 32;
        }else if(strcmp(hash_type, "SHA-384") == 0){
            md_type = MBEDTLS_MD_SHA384;
            md_size = 48;
        }else if(strcmp(hash_type, "SHA-512") == 0){
            md_type = MBEDTLS_MD_SHA512;
            md_size = 64;
        }else{
            mbedtls_fprintf(stderr, "Message Digest '%s' not found\n", hash_type);
            goto exit;
        }
    }else{
        md_type = mbedtls_md_get_type(md_info);
        md_size = mbedtls_md_get_size(md_info);
    }
    json_t *tests = json_object_get(test_group, "tests");
    size_t index;
    json_t *test_case;

    json_array_foreach(tests, index, test_case) {
        int result;
        const char *msg_hex = json_string_value(json_object_get(test_case, "msg"));
        const char *sig_hex = json_string_value(json_object_get(test_case, "sig"));
        const char *expected = json_string_value(json_object_get(test_case, "result"));

        // 
        unsigned char msg[BUFFER_SIZE], sig[BUFFER_SIZE];
        unsigned char hash[MBEDTLS_MD_MAX_SIZE];
        memset(hash, 0, MBEDTLS_MD_MAX_SIZE);
        memset(msg, 0, BUFFER_SIZE);
        memset(sig, 0, BUFFER_SIZE);
        size_t msg_len = 0, sig_len = 0;
        hex_to_bin(msg_hex, msg, &msg_len);
        hex_to_bin(sig_hex, sig, &sig_len);

        // 
        ret = mbedtls_md(mbedtls_md_info_from_type(md_type), msg, msg_len, hash);
        if (ret != 0) {
            goto exit;
        }
        // 
        result = mbedtls_rsa_pkcs1_verify(&rsa, md_type, md_size, hash, sig);

        // 
        if (strcmp(expected, "valid") == 0) {
            if (result == 0) {
                printf("Test case %d: PASS (valid)\n", (int)json_integer_value(json_object_get(test_case, "tcId")));
            } else {
                printf("Test case %d: FAIL (valid)\n", (int)json_integer_value(json_object_get(test_case, "tcId")));
            }
        } else if (strcmp(expected, "invalid") == 0) {
            if (result != 0) {
                printf("Test case %d: PASS (invalid)\n", (int)json_integer_value(json_object_get(test_case, "tcId")));
            } else {
                printf("Test case %d: FAIL (invalid)\n", (int)json_integer_value(json_object_get(test_case, "tcId")));
            }
        } else if (strcmp(expected, "acceptable") == 0) {
            // 
            if (result == 0) {
                printf("Test case %d: ACCEPTABLE (signature accepted)\n", (int)json_integer_value(json_object_get(test_case, "tcId")));
            } else {
                printf("Test case %d: ACCEPTABLE (signature rejected) -0x%04x\n", (int)json_integer_value(json_object_get(test_case, "tcId")), (unsigned int) -result);
            }
        } else {
            printf("Test case %d: UNKNOWN result type: %s\n", (int)json_integer_value(json_object_get(test_case, "tcId")), expected);
        }
    }
    
exit:
    mbedtls_rsa_free(&rsa);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <wycheproof_json_file>\n", argv[0]);
        return 1;
    }

    json_error_t error;
    json_t *root = json_load_file(argv[1], 0, &error);
    if (!root) {
        fprintf(stderr, "Error loading JSON: %s\n", error.text);
        return 1;
    }

    json_t *test_groups = json_object_get(root, "testGroups");
    size_t index;
    json_t *test_group;

    json_array_foreach(test_groups, index, test_group) {
        printf("Running Test Group %zu...\n", index + 1);
        test_rsa_verify_pkcs1(test_group);
    }

    json_decref(root);
    return 0;
}
