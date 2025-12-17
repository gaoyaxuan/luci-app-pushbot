// aes_crypto.h - AES encryption/decryption function declarations
#ifndef AES_CRYPTO_H
#define AES_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ========== ECB 模式 ==========
/**
 * AES ECB 加密
 * @param key 密钥
 * @param key_bits 密钥位数 (128, 192, 256)
 * @param data 数据缓冲区（原地加密）
 * @param data_len 数据长度（必须是16的倍数）
 * @return 0 成功, 非0 失败
 */
int aes_ecb_encrypt(const uint8_t* key, int key_bits, uint8_t* data, size_t data_len);

/**
 * AES ECB 解密
 * @param key 密钥
 * @param key_bits 密钥位数 (128, 192, 256)
 * @param data 数据缓冲区（原地解密）
 * @param data_len 数据长度（必须是16的倍数）
 * @return 0 成功, 非0 失败
 */
int aes_ecb_decrypt(const uint8_t* key, int key_bits, uint8_t* data, size_t data_len);

// ========== CBC 模式 ==========
/**
 * AES CBC 加密
 * @param key 密钥
 * @param key_bits 密钥位数 (128, 192, 256)
 * @param iv 初始化向量（16字节）
 * @param data 数据缓冲区（原地加密）
 * @param data_len 数据长度（必须是16的倍数）
 * @return 0 成功, 非0 失败
 */
int aes_cbc_encrypt(const uint8_t* key, int key_bits, const uint8_t* iv,
                    uint8_t* data, size_t data_len);

/**
 * AES CBC 解密
 * @param key 密钥
 * @param key_bits 密钥位数 (128, 192, 256)
 * @param iv 初始化向量（16字节）
 * @param data 数据缓冲区（原地解密）
 * @param data_len 数据长度（必须是16的倍数）
 * @return 0 成功, 非0 失败
 */
int aes_cbc_decrypt(const uint8_t* key, int key_bits, const uint8_t* iv,
                    uint8_t* data, size_t data_len);

// ========== CTR 模式 ==========
/**
 * AES CTR 加密/解密（CTR模式加密和解密是相同的操作）
 * @param key 密钥
 * @param key_bits 密钥位数 (128, 192, 256)
 * @param iv 初始化向量/计数器（16字节）
 * @param data 数据缓冲区（原地加密/解密）
 * @param data_len 数据长度
 * @return 0 成功, 非0 失败
 */
int aes_ctr_crypt(const uint8_t* key, int key_bits, const uint8_t* iv,
                  uint8_t* data, size_t data_len);

// ========== GCM 模式 ==========
/**
 * AES GCM 加密
 * @param key 密钥
 * @param key_bits 密钥位数 (128, 192, 256)
 * @param iv 初始化向量
 * @param iv_len IV长度（推荐12字节）
 * @param plaintext 明文
 * @param plaintext_len 明文长度
 * @param aad 附加认证数据（可为NULL）
 * @param aad_len AAD长度
 * @param ciphertext 密文输出缓冲区
 * @param tag 认证标签输出缓冲区
 * @param tag_len 标签长度（通常16字节）
 * @return 0 成功, 非0 失败
 */
int aes_gcm_encrypt(const uint8_t* key, int key_bits,
                    const uint8_t* iv, size_t iv_len,
                    const uint8_t* plaintext, size_t plaintext_len,
                    const uint8_t* aad, size_t aad_len,
                    uint8_t* ciphertext, uint8_t* tag, size_t tag_len);

/**
 * AES GCM 解密
 * @param key 密钥
 * @param key_bits 密钥位数 (128, 192, 256)
 * @param iv 初始化向量
 * @param iv_len IV长度
 * @param ciphertext 密文
 * @param ciphertext_len 密文长度
 * @param aad 附加认证数据（可为NULL）
 * @param aad_len AAD长度
 * @param tag 认证标签
 * @param tag_len 标签长度
 * @param plaintext 明文输出缓冲区
 * @return 0 成功, 非0 失败（认证失败）
 */
int aes_gcm_decrypt(const uint8_t* key, int key_bits,
                    const uint8_t* iv, size_t iv_len,
                    const uint8_t* ciphertext, size_t ciphertext_len,
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* tag, size_t tag_len,
                    uint8_t* plaintext);

#ifdef __cplusplus
}
#endif

#endif // AES_CRYPTO_H
