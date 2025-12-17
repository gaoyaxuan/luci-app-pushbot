// aes_crypto.c - Crypto implementations using mbedtls
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include <string.h>

#define AES_BLOCKLEN 16

// ========== ECB 模式 ==========
int aes_ecb_encrypt(const uint8_t* key, int key_bits, uint8_t* data, size_t data_len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    int ret = mbedtls_aes_setkey_enc(&aes, key, key_bits);
    if (ret != 0) {
        mbedtls_aes_free(&aes);
        return ret;
    }

    for (size_t i = 0; i < data_len; i += AES_BLOCKLEN) {
        ret = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, data + i, data + i);
        if (ret != 0) break;
    }

    mbedtls_aes_free(&aes);
    return ret;
}

int aes_ecb_decrypt(const uint8_t* key, int key_bits, uint8_t* data, size_t data_len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    int ret = mbedtls_aes_setkey_dec(&aes, key, key_bits);
    if (ret != 0) {
        mbedtls_aes_free(&aes);
        return ret;
    }

    for (size_t i = 0; i < data_len; i += AES_BLOCKLEN) {
        ret = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, data + i, data + i);
        if (ret != 0) break;
    }

    mbedtls_aes_free(&aes);
    return ret;
}

// ========== CBC 模式 ==========
int aes_cbc_encrypt(const uint8_t* key, int key_bits, const uint8_t* iv,
                    uint8_t* data, size_t data_len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    int ret = mbedtls_aes_setkey_enc(&aes, key, key_bits);
    if (ret != 0) {
        mbedtls_aes_free(&aes);
        return ret;
    }

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);

    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, data_len,
                                 iv_copy, data, data);

    mbedtls_aes_free(&aes);
    return ret;
}

int aes_cbc_decrypt(const uint8_t* key, int key_bits, const uint8_t* iv,
                    uint8_t* data, size_t data_len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    int ret = mbedtls_aes_setkey_dec(&aes, key, key_bits);
    if (ret != 0) {
        mbedtls_aes_free(&aes);
        return ret;
    }

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);

    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, data_len,
                                 iv_copy, data, data);

    mbedtls_aes_free(&aes);
    return ret;
}

// ========== CTR 模式 ==========
int aes_ctr_crypt(const uint8_t* key, int key_bits, const uint8_t* iv,
                  uint8_t* data, size_t data_len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    int ret = mbedtls_aes_setkey_enc(&aes, key, key_bits);
    if (ret != 0) {
        mbedtls_aes_free(&aes);
        return ret;
    }

    uint8_t nonce_counter[16];
    uint8_t stream_block[16];
    size_t nc_off = 0;

    memcpy(nonce_counter, iv, 16);
    memset(stream_block, 0, 16);

    ret = mbedtls_aes_crypt_ctr(&aes, data_len, &nc_off,
                                 nonce_counter, stream_block, data, data);

    mbedtls_aes_free(&aes);
    return ret;
}

// ========== GCM 模式 ==========
int aes_gcm_encrypt(const uint8_t* key, int key_bits, const uint8_t* iv, size_t iv_len,
                    const uint8_t* plaintext, size_t plaintext_len,
                    const uint8_t* aad, size_t aad_len,
                    uint8_t* ciphertext, uint8_t* tag, size_t tag_len) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, key_bits);
    if (ret != 0) {
        mbedtls_gcm_free(&gcm);
        return ret;
    }

    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                                     plaintext_len, iv, iv_len,
                                     aad, aad_len,
                                     plaintext, ciphertext,
                                     tag_len, tag);

    mbedtls_gcm_free(&gcm);
    return ret;
}

int aes_gcm_decrypt(const uint8_t* key, int key_bits, const uint8_t* iv, size_t iv_len,
                    const uint8_t* ciphertext, size_t ciphertext_len,
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* tag, size_t tag_len,
                    uint8_t* plaintext) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, key_bits);
    if (ret != 0) {
        mbedtls_gcm_free(&gcm);
        return ret;
    }

    ret = mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len,
                                    iv, iv_len,
                                    aad, aad_len,
                                    tag, tag_len,
                                    ciphertext, plaintext);

    mbedtls_gcm_free(&gcm);
    return ret;
}