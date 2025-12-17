// src/main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"

// ========== Base64 编码 ==========
static const char base64_chars[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* base64_encode(const uint8_t* data, size_t input_length, size_t* output_length) {
    *output_length = 4 * ((input_length + 2) / 3);
    char* encoded_data = malloc(*output_length + 1);
    if (!encoded_data) return NULL;
    
    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        
        encoded_data[j++] = base64_chars[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 0 * 6) & 0x3F];
    }
    
    int padding = (3 - (input_length % 3)) % 3;
    for (int i = 0; i < padding; i++)
        encoded_data[*output_length - 1 - i] = '=';
    
    encoded_data[*output_length] = '\0';
    return encoded_data;
}

uint8_t* base64_decode(const char* data, size_t input_length, size_t* output_length) {
    if (input_length % 4 != 0) return NULL;
    
    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;
    
    uint8_t* decoded_data = malloc(*output_length);
    if (!decoded_data) return NULL;
    
    for (size_t i = 0, j = 0; i < input_length;) {
        // 修复：显式转换为 uint32_t
        const char* pos;
        uint32_t sextet_a = (data[i] == '=') ? (i++, 0) : ((pos = strchr(base64_chars, data[i++])) ? (uint32_t)(pos - base64_chars) : 0);
        uint32_t sextet_b = (data[i] == '=') ? (i++, 0) : ((pos = strchr(base64_chars, data[i++])) ? (uint32_t)(pos - base64_chars) : 0);
        uint32_t sextet_c = (data[i] == '=') ? (i++, 0) : ((pos = strchr(base64_chars, data[i++])) ? (uint32_t)(pos - base64_chars) : 0);
        uint32_t sextet_d = (data[i] == '=') ? (i++, 0) : ((pos = strchr(base64_chars, data[i++])) ? (uint32_t)(pos - base64_chars) : 0);
        
        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;
        
        if (j < *output_length) decoded_data[j++] = (triple >> 16) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = triple & 0xFF;
    }
    
    return decoded_data;
}

// ========== 辅助函数 ==========
int hex_to_bytes(const char* hex, uint8_t* bytes, int expected_len) {
    int len = strlen(hex);
    if (len != expected_len * 2) return -1;
    for (int i = 0; i < expected_len; i++) {
        if (sscanf(hex + 2*i, "%2hhx", &bytes[i]) != 1) return -1;
    }
    return 0;
}

size_t pkcs7_pad(uint8_t* data, size_t data_len, size_t block_size) {
    size_t padding = block_size - (data_len % block_size);
    for (size_t i = 0; i < padding; i++) {
        data[data_len + i] = (uint8_t)padding;
    }
    return data_len + padding;
}

size_t pkcs7_unpad(uint8_t* data, size_t data_len) {
    if (data_len == 0) return 0;
    uint8_t padding = data[data_len - 1];
    if (padding > 16 || padding > data_len) return data_len;
    for (size_t i = 0; i < padding; i++) {
        if (data[data_len - 1 - i] != padding) return data_len;
    }
    return data_len - padding;
}

void print_usage(const char* prog) {
    printf("AES Encryption Tool - Base64 Output\n\n");
    printf("Usage:\n");
    printf("  Encrypt: %s enc <mode> <bits> <key> <iv> <plaintext>\n", prog);
    printf("  Decrypt: %s dec <mode> <bits> <key> <iv> <base64_ciphertext>\n\n", prog);
    printf("Modes: ecb, cbc, ctr\n");
    printf("Bits: 128, 192, 256\n\n");
    printf("Examples:\n");
    printf("  # CBC-128 encryption\n");
    printf("  %s enc cbc 128 \\\n", prog);
    printf("    0123456789abcdef0123456789abcdef \\\n");
    printf("    0123456789abcdef0123456789abcdef \\\n");
    printf("    \"Hello World\"\n\n");
    printf("  # CBC-256 encryption\n");
    printf("  %s enc cbc 256 \\\n", prog);
    printf("    0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \\\n");
    printf("    0123456789abcdef0123456789abcdef \\\n");
    printf("    \"Secret Message\"\n\n");
    printf("  # CTR mode (no padding needed)\n");
    printf("  %s enc ctr 128 <key> <iv> \"Text\"\n\n", prog);
    printf("  # Decryption\n");
    printf("  %s dec cbc 128 <key> <iv> \"SGVsbG8gV29ybGQ=\"\n", prog);
}

int main(int argc, char* argv[]) {
    if (argc != 7) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char* operation = argv[1];  // enc or dec
    const char* mode = argv[2];       // ecb, cbc, ctr
    int key_bits = atoi(argv[3]);
    const char* key_hex = argv[4];
    const char* iv_hex = argv[5];
    const char* input = argv[6];
    
    // 验证参数
    if (strcmp(operation, "enc") != 0 && strcmp(operation, "dec") != 0) {
        fprintf(stderr, "Error: Operation must be 'enc' or 'dec'\n");
        return 1;
    }
    
    if (key_bits != 128 && key_bits != 192 && key_bits != 256) {
        fprintf(stderr, "Error: Invalid key size\n");
        return 1;
    }
    
    // 解析密钥
    int key_len = key_bits / 8;
    uint8_t key[32];
    if (hex_to_bytes(key_hex, key, key_len) != 0) {
        fprintf(stderr, "Error: Invalid key (expected %d hex chars)\n", key_len * 2);
        return 1;
    }
    
    // 解析 IV（ECB 模式不需要）
    uint8_t iv[16] = {0};
    if (strcmp(mode, "ecb") != 0) {
        if (hex_to_bytes(iv_hex, iv, 16) != 0) {
            fprintf(stderr, "Error: Invalid IV (expected 32 hex chars)\n");
            return 1;
        }
    }
    
    struct AES_ctx ctx;
    
    // ========== 加密 ==========
    if (strcmp(operation, "enc") == 0) {
        size_t plaintext_len = strlen(input);
        size_t buffer_size = ((plaintext_len / AES_BLOCKLEN) + 1) * AES_BLOCKLEN;
        uint8_t* buffer = malloc(buffer_size);
        if (!buffer) {
            fprintf(stderr, "Memory allocation failed\n");
            return 1;
        }
        
        memcpy(buffer, input, plaintext_len);
        
        // CBC/ECB 模式需要填充
        if (strcmp(mode, "cbc") == 0 || strcmp(mode, "ecb") == 0) {
            buffer_size = pkcs7_pad(buffer, plaintext_len, AES_BLOCKLEN);
        } else {
            buffer_size = plaintext_len;  // CTR 不需要填充
        }
        
        // 执行加密
        if (strcmp(mode, "cbc") == 0) {
            AES_init_ctx_iv(&ctx, key, iv);
            AES_CBC_encrypt_buffer(&ctx, buffer, buffer_size);
        } else if (strcmp(mode, "ecb") == 0) {
            AES_init_ctx(&ctx, key);
            for (size_t i = 0; i < buffer_size; i += AES_BLOCKLEN) {
                AES_ECB_encrypt(&ctx, buffer + i);
            }
        } else if (strcmp(mode, "ctr") == 0) {
            AES_init_ctx_iv(&ctx, key, iv);
            AES_CTR_xcrypt_buffer(&ctx, buffer, buffer_size);
        } else {
            fprintf(stderr, "Error: Unknown mode '%s'\n", mode);
            free(buffer);
            return 1;
        }
        
        // 转换为 Base64
        size_t b64_len;
        char* base64 = base64_encode(buffer, buffer_size, &b64_len);
        free(buffer);
        
        if (!base64) {
            fprintf(stderr, "Base64 encoding failed\n");
            return 1;
        }
        
        // 输出 Base64（仅密文，无其他信息）
        printf("%s\n", base64);
        
        free(base64);
    }
    
    // ========== 解密 ==========
    else if (strcmp(operation, "dec") == 0) {
        // Base64 解码
        size_t ciphertext_len;
        uint8_t* ciphertext = base64_decode(input, strlen(input), &ciphertext_len);
        if (!ciphertext) {
            fprintf(stderr, "Error: Invalid Base64 input\n");
            return 1;
        }
        
        // 验证密文长度（CBC/ECB 必须是块大小的倍数）
        if ((strcmp(mode, "cbc") == 0 || strcmp(mode, "ecb") == 0) && 
            ciphertext_len % AES_BLOCKLEN != 0) {
            fprintf(stderr, "Error: Invalid ciphertext length\n");
            free(ciphertext);
            return 1;
        }
        
        // 执行解密
        if (strcmp(mode, "cbc") == 0) {
            AES_init_ctx_iv(&ctx, key, iv);
            AES_CBC_decrypt_buffer(&ctx, ciphertext, ciphertext_len);
        } else if (strcmp(mode, "ecb") == 0) {
            AES_init_ctx(&ctx, key);
            for (size_t i = 0; i < ciphertext_len; i += AES_BLOCKLEN) {
                AES_ECB_decrypt(&ctx, ciphertext + i);
            }
        } else if (strcmp(mode, "ctr") == 0) {
            AES_init_ctx_iv(&ctx, key, iv);
            AES_CTR_xcrypt_buffer(&ctx, ciphertext, ciphertext_len);
        } else {
            fprintf(stderr, "Error: Unknown mode '%s'\n", mode);
            free(ciphertext);
            return 1;
        }
        
        // 去除填充（CTR 模式不需要）
        size_t plaintext_len = ciphertext_len;
        if (strcmp(mode, "cbc") == 0 || strcmp(mode, "ecb") == 0) {
            plaintext_len = pkcs7_unpad(ciphertext, ciphertext_len);
        }
        
        // 输出明文
        fwrite(ciphertext, 1, plaintext_len, stdout);
        printf("\n");
        
        free(ciphertext);
    }
    
    return 0;
}
