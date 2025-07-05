#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


#define BUFFER_SIZE 2048
void hex_to_bin(const char *hex, unsigned char *bin, size_t *len);
int load_rsa_key(mbedtls_rsa_context *rsa, json_t *test_group);
void test_rsa_decrypt(json_t *test_group);
int dummy_entropy(void *data, unsigned char *output, size_t len);
int dummy_random(void *p_rng, unsigned char *output, size_t output_len);
void hexdump(void *ptr, unsigned int buflen);

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
    const char *d_hex = json_string_value(json_object_get(test_group, "d"));
    if (!n_hex || !e_hex || !d_hex) return -1;

    mbedtls_mpi N, E, D;
    mbedtls_mpi_init(&N); mbedtls_mpi_init(&E); mbedtls_mpi_init(&D);

    mbedtls_mpi_read_string(&N, 16, n_hex);
    mbedtls_mpi_read_string(&E, 16, e_hex);
    mbedtls_mpi_read_string(&D, 16, d_hex);

    mbedtls_rsa_import(rsa, &N, NULL, NULL, &D, &E);
    mbedtls_rsa_complete(rsa);

    mbedtls_mpi_free(&N); mbedtls_mpi_free(&E); mbedtls_mpi_free(&D);
    return 0;
}

void test_rsa_decrypt(json_t *test_group) {
    const char *pers = "rsa_decrypt";
    mbedtls_md_type_t md_type;
    //unsigned int md_size;
    //char buf[4096];
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, dummy_entropy,
                                &entropy, (const unsigned char *) pers,
                                strlen(pers));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n",
                       ret);
        goto exit;
    }
    mbedtls_rsa_init(&rsa);

    if (load_rsa_key(&rsa, test_group) != 0) {
        printf("Failed to load RSA key.\n");
        goto exit;
    }

    const char *hash_type = json_string_value(json_object_get(test_group, "sha"));
    const char *hash_mgf = json_string_value(json_object_get(test_group, "mgfSha"));
    if(strcmp(hash_type, hash_mgf) != 0){
        printf("sha # mgfsha not support\n");
        goto exit;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_string(hash_type);
    if (md_info == NULL) {
        if(strcmp(hash_type, "SHA-1") == 0){
            md_type = MBEDTLS_MD_SHA1;
        }else if(strcmp(hash_type, "SHA-224") == 0){
            md_type = MBEDTLS_MD_SHA224;
        }else if(strcmp(hash_type, "SHA-256") == 0){
            md_type = MBEDTLS_MD_SHA256;
        }else if(strcmp(hash_type, "SHA-384") == 0){
            md_type = MBEDTLS_MD_SHA384;
        }else if(strcmp(hash_type, "SHA-512") == 0){
            md_type = MBEDTLS_MD_SHA512;
        }else{
            mbedtls_fprintf(stderr, "Message Digest '%s' not found\n", hash_type);
            goto exit;
        }
    }else{
        md_type = mbedtls_md_get_type(md_info);
    }
    //
    if ((ret = mbedtls_rsa_set_padding(&rsa,
                                    MBEDTLS_RSA_PKCS_V21,
                                    md_type)) != 0) {
        mbedtls_printf(" failed\n  ! Invalid padding\n");
        goto exit;
    }

    json_t *tests = json_object_get(test_group, "tests");
    size_t index;
    json_t *test_case;

    json_array_foreach(tests, index, test_case) {
        json_int_t tcId = json_integer_value(json_object_get(test_case, "tcId"));
        const char *label_hex = json_string_value(json_object_get(test_case, "label"));
        const char *ct_hex = json_string_value(json_object_get(test_case, "ct"));
        const char *msg_hex = json_string_value(json_object_get(test_case, "msg"));
        const char *result = json_string_value(json_object_get(test_case, "result"));

        unsigned char ct[BUFFER_SIZE], pt[BUFFER_SIZE], expected_pt[BUFFER_SIZE], label[256];
        size_t ct_len, pt_len = 0, expected_len, label_len, olen;

        memset(ct,0,BUFFER_SIZE);
        memset(pt,0,BUFFER_SIZE);
        memset(expected_pt,0,BUFFER_SIZE);
        memset(label, 0, 256);
        hex_to_bin(ct_hex, ct, &ct_len);
        hex_to_bin(msg_hex, expected_pt, &expected_len);
        hex_to_bin(label_hex, label, &label_len);

        ret = mbedtls_rsa_rsaes_oaep_decrypt(&rsa, dummy_random, &ctr_drbg, label, label_len, &olen, ct, pt, sizeof(pt));
        if(ret == 0){
            if(strcmp(result, "invalid") == 0){
                printf("Test %zu: MALFORMED\n", index + 1); 
                printf("Invalid ciphertext returned: \n");
                hexdump(pt, pt_len);
                printf("ct_len = %zu\n",ct_len);
            }else if(memcmp(pt, expected_pt, expected_len) == 0){
                printf("Test %zu: PASS\n", index + 1);
            }else{
                printf("Test %zu: FAIL\n", index + 1); 
            }
        }else{
            if(strcmp(result, "invalid") == 0){
                printf("Test %zu - %"JSON_INTEGER_FORMAT": PASS (invalid case) -0x%04x\n", index + 1, tcId, (unsigned int) -ret);
            }else{
                printf("Test %zu: FAIL (valid case) -0x%04x\n", index + 1, (unsigned int) -ret);
            }
        }
    }
exit:
    mbedtls_rsa_free(&rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
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
        test_rsa_decrypt(test_group);
    }

    json_decref(root);
    return 0;
}