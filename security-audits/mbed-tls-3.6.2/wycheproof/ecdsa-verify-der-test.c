#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecp.h"
#include "mbedtls/platform.h"
#include "mbedtls/asn1write.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>  
#include <ctype.h>

int test_ecdsa_verify(json_t *test_group);
void verify_signature_der(mbedtls_ecdsa_context *ctx, const mbedtls_md_info_t *md_info, unsigned char *msg, size_t msg_len, unsigned char *sig, size_t sig_len, const char *result, int id);
void hex_to_bin(const char *hex, unsigned char *bin, size_t *len);
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

void hex_to_bin(const char *hex, unsigned char *bin, size_t *len) {
    size_t hex_len = strlen(hex);
    *len = hex_len / 2;
    for (size_t i = 0; i < *len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bin[i]);
    }
}

void verify_signature_der(mbedtls_ecdsa_context *ctx, const mbedtls_md_info_t *md_info, unsigned char *msg, size_t msg_len, unsigned char *sig, size_t sig_len, const char *result, int id) {
    unsigned char hash[64];
    memset(hash, 0, 64);
    int hash_len;
    hash_len = mbedtls_md_get_size(md_info);
    if (mbedtls_md(md_info, (const unsigned char*)msg, msg_len, hash) != 0) {
        fprintf(stderr, "\tFailed to hash the message.\n");
        return;
    }

    int ret = mbedtls_ecdsa_read_signature(ctx, hash, hash_len, sig, sig_len);
    if ((ret == 0 && strcmp(result, "valid") == 0)) {
        printf("Test %d passed valid.\n", id);
    } else if(ret != 0 && strcmp(result, "invalid") == 0){
        printf("Test %d passed invalid.\n", id);
    } else if (strcmp(result, "acceptable") == 0) {
        //
        if (ret == 0) {
            printf("Test %d ACCEPTABLE (signature accepted)\n", id);
        } else {
            printf("Test %d ACCEPTABLE (signature rejected)\n", id);
        }
    }
    else {
        printf("Test %d failed -0x%04x.\n", id, (unsigned int) -ret);
    }
}

int test_ecdsa_verify(json_t *test_group) {
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    const char *curve = json_string_value(json_object_get(json_object_get(test_group, "key"), "curve"));
    if (strcmp(curve, "secp192r1") == 0) {
        mbedtls_ecp_group_load(&ctx.private_grp, MBEDTLS_ECP_DP_SECP192R1);
    } else if (strcmp(curve, "secp224r1") == 0) {
        mbedtls_ecp_group_load(&ctx.private_grp, MBEDTLS_ECP_DP_SECP224R1);
    } else if (strcmp(curve, "secp256r1") == 0) {
        mbedtls_ecp_group_load(&ctx.private_grp, MBEDTLS_ECP_DP_SECP256R1);
    } else if (strcmp(curve, "secp384r1") == 0) {
        mbedtls_ecp_group_load(&ctx.private_grp, MBEDTLS_ECP_DP_SECP384R1);
    } else if (strcmp(curve, "secp521r1") == 0) {
        mbedtls_ecp_group_load(&ctx.private_grp, MBEDTLS_ECP_DP_SECP521R1);
    } else if (strcmp(curve, "brainpoolP256r1") == 0) {
        mbedtls_ecp_group_load(&ctx.private_grp, MBEDTLS_ECP_DP_BP256R1);
    } else if (strcmp(curve, "brainpoolP384r1") == 0) {
        mbedtls_ecp_group_load(&ctx.private_grp, MBEDTLS_ECP_DP_BP384R1);
    } else if (strcmp(curve, "brainpoolP512r1") == 0) {
        mbedtls_ecp_group_load(&ctx.private_grp, MBEDTLS_ECP_DP_BP512R1);
    } else if (strcmp(curve, "secp192k1") == 0) {
        mbedtls_ecp_group_load(&ctx.private_grp, MBEDTLS_ECP_DP_SECP192K1);
    } else if (strcmp(curve, "secp224k1") == 0) {
        mbedtls_ecp_group_load(&ctx.private_grp, MBEDTLS_ECP_DP_SECP224K1);
    } else if (strcmp(curve, "secp256k1") == 0) {
        mbedtls_ecp_group_load(&ctx.private_grp, MBEDTLS_ECP_DP_SECP256K1);
    }
    else {
        printf("%s not support\n",curve);
        goto cleanup;
    }
    //
    const char *hash_type = json_string_value(json_object_get(test_group, "sha"));
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_string(hash_type);
    if (md_info == NULL) {
        if(strcmp(hash_type, "SHA-224") == 0){
            md_info = mbedtls_md_info_from_string("SHA224");
        }else if(strcmp(hash_type, "SHA-256") == 0){
            md_info = mbedtls_md_info_from_string("SHA256");
        }else if(strcmp(hash_type, "SHA-384") == 0){
            md_info = mbedtls_md_info_from_string("SHA384");
        }else if(strcmp(hash_type, "SHA-512") == 0){
            md_info = mbedtls_md_info_from_string("SHA512");
        }else{
            mbedtls_fprintf(stderr, "Message Digest '%s' not found\n", hash_type);
            goto cleanup;
        }
    }
    ///
    const char *type = json_string_value(json_object_get(test_group, "type"));
    const char *pub_key_hex = json_string_value(json_object_get(json_object_get(test_group, "key"),"uncompressed"));
    unsigned char pub_key[1024];
    memset(pub_key, 0, 1024);
    size_t pub_key_len = 0;
    hex_to_bin(pub_key_hex, pub_key, &pub_key_len);
    if (mbedtls_ecp_point_read_binary(&ctx.private_grp, &ctx.private_Q, pub_key, pub_key_len) != 0) {
        fprintf(stderr, "Failed to load public key.\n");
        goto cleanup;
    }
    //
    json_t *tests = json_object_get(test_group, "tests");
    size_t index;
    json_t *test_case;
    unsigned char msg[8192], sig[8192];
    json_array_foreach(tests, index, test_case) {
        const char *msg_hex = json_string_value(json_object_get(test_case, "msg"));
        const char *sig_hex = json_string_value(json_object_get(test_case, "sig"));
        const char *result = json_string_value(json_object_get(test_case, "result"));
        
        memset(msg, 0, 8192);
        memset(sig, 0, 8192);
        size_t msg_len = 0, sig_len = 0;
        hex_to_bin(msg_hex, msg, &msg_len);
        hex_to_bin(sig_hex, sig, &sig_len);
        if (strcmp(type, "EcdsaVerify") == 0) {
            verify_signature_der(&ctx, md_info, msg, msg_len, sig, sig_len, result, (int)json_integer_value(json_object_get(test_case, "tcId")));
        } else {
            fprintf(stderr, "Unsupported test type: %s\n", type);
        }
    }

cleanup:
    mbedtls_ecdsa_free(&ctx);
    return 1;
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
        test_ecdsa_verify(test_group);
    }

    json_decref(root);
    return 0;
}