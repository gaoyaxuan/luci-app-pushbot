// main.c - 完整版本，支持 binary/base64 格式 + hex/ascii key/iv
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "aes_crypto.h"

#define AES_BLOCKLEN 16

// ========== 文件操作 ==========
uint8_t* read_file(const char* filename, size_t* file_size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file '%s' for reading\n", filename);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t* buffer = malloc(*file_size);
    if (!buffer) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(file);
        return NULL;
    }

    size_t read_size = fread(buffer, 1, *file_size, file);
    fclose(file);

    if (read_size != *file_size) {
        fprintf(stderr, "Error: Failed to read complete file\n");
        free(buffer);
        return NULL;
    }

    return buffer;
}

int write_file(const char* filename, const void* data, size_t size) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file '%s' for writing\n", filename);
        return -1;
    }

    size_t written = fwrite(data, 1, size, file);
    fclose(file);

    if (written != size) {
        fprintf(stderr, "Error: Failed to write complete data\n");
        return -1;
    }

    return 0;
}

// ========== Base64 编码/解码 ==========
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
    // 移除换行和空格
    char* clean_data = malloc(input_length + 1);
    size_t clean_len = 0;
    for (size_t i = 0; i < input_length; i++) {
        if (data[i] != '\n' && data[i] != '\r' && data[i] != ' ' && data[i] != '\t') {
            clean_data[clean_len++] = data[i];
        }
    }
    clean_data[clean_len] = '\0';

    if (clean_len % 4 != 0) {
        free(clean_data);
        return NULL;
    }

    *output_length = clean_len / 4 * 3;
    if (clean_len > 0 && clean_data[clean_len - 1] == '=') (*output_length)--;
    if (clean_len > 1 && clean_data[clean_len - 2] == '=') (*output_length)--;

    uint8_t* decoded_data = malloc(*output_length);
    if (!decoded_data) {
        free(clean_data);
        return NULL;
    }

    for (size_t i = 0, j = 0; i < clean_len;) {
        const char* pos;
        uint32_t sextet_a = (clean_data[i] == '=') ? (i++, 0) : ((pos = strchr(base64_chars, clean_data[i++])) ? (uint32_t)(pos - base64_chars) : 0);
        uint32_t sextet_b = (clean_data[i] == '=') ? (i++, 0) : ((pos = strchr(base64_chars, clean_data[i++])) ? (uint32_t)(pos - base64_chars) : 0);
        uint32_t sextet_c = (clean_data[i] == '=') ? (i++, 0) : ((pos = strchr(base64_chars, clean_data[i++])) ? (uint32_t)(pos - base64_chars) : 0);
        uint32_t sextet_d = (clean_data[i] == '=') ? (i++, 0) : ((pos = strchr(base64_chars, clean_data[i++])) ? (uint32_t)(pos - base64_chars) : 0);

        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

        if (j < *output_length) decoded_data[j++] = (triple >> 16) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = triple & 0xFF;
    }

    free(clean_data);
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

// ASCII 字符串转字节数组（用于 key 和 iv）
int ascii_to_bytes(const char* ascii, uint8_t* bytes, int expected_len) {
    int len = strlen(ascii);

    if (len > expected_len) {
        // 如果字符串太长，截断
        memcpy(bytes, ascii, expected_len);
    } else if (len < expected_len) {
        // 如果字符串太短，用 0 填充
        memcpy(bytes, ascii, len);
        memset(bytes + len, 0, expected_len - len);
    } else {
        // 长度正好
        memcpy(bytes, ascii, expected_len);
    }

    return 0;
}

// 打印字节数组为 hex（用于调试）
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
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

    // 验证填充
    for (size_t i = 0; i < padding; i++) {
        if (data[data_len - 1 - i] != padding) return data_len;
    }
    return data_len - padding;
}

void print_usage(const char* prog) {
    printf("AES Encryption Tool\n\n");
    printf("Usage:\n");
    printf("  %s enc <mode> <bits> <key> <iv> <input> <output> [options]\n", prog);
    printf("  %s dec <mode> <bits> <key> <iv> <input> <output> [options]\n\n", prog);
    printf("Modes: ecb, cbc, ctr, gcm\n");
    printf("Bits: 128, 192, 256\n\n");
    printf("Parameters:\n");
    printf("  key      - Key (hex string or ASCII with --ascii)\n");
    printf("  iv       - IV (hex string or ASCII with --ascii)\n");
    printf("  input    - Input file\n");
    printf("  output   - Output file\n\n");
    printf("Options:\n");
    printf("  --binary, -b  - Use binary format (default: Base64)\n");
    printf("  --ascii, -a   - Key/IV are ASCII strings (default: hex)\n");
    printf("  aad           - Additional data for GCM mode\n\n");
    printf("Examples:\n");
    printf("  # Decrypt with hex key/iv (default)\n");
    printf("  %s dec cbc 256 0123...cdef 0123...cdef abc.txt plain.txt --binary\n\n", prog);
    printf("  # Decrypt with ASCII key/iv\n");
    printf("  %s dec cbc 256 \"my32bytesecretkey1234567890ab\" \"my16bytesiv12345\" \\\n", prog);
    printf("    abc.txt plain.txt --binary --ascii\n\n");
    printf("  # Encrypt with ASCII key/iv to Base64\n");
    printf("  %s enc cbc 256 \"my32bytesecretkey1234567890ab\" \"my16bytesiv12345\" \\\n", prog);
    printf("    plain.txt cipher.b64 --ascii\n\n");
    printf("  # GCM with ASCII key/iv and AAD\n");
    printf("  %s enc gcm 256 \"my32bytesecretkey1234567890ab\" \"my12bytesiv1\" \\\n", prog);
    printf("    plain.txt cipher.bin --ascii --binary \"user_id=123\"\n\n");
    printf("Key/IV length requirements:\n");
    printf("  AES-128: key=16 bytes (32 hex / 16 ASCII), iv=16 bytes (32 hex / 16 ASCII)\n");
    printf("  AES-192: key=24 bytes (48 hex / 24 ASCII), iv=16 bytes (32 hex / 16 ASCII)\n");
    printf("  AES-256: key=32 bytes (64 hex / 32 ASCII), iv=16 bytes (32 hex / 16 ASCII)\n");
    printf("  GCM mode: iv can be 12 bytes (24 hex / 12 ASCII) for better performance\n");
}

int main(int argc, char* argv[]) {
    if (argc < 8) {
        print_usage(argv[0]);
        return 1;
    }

    const char* operation = argv[1];
    const char* mode = argv[2];
    int key_bits = atoi(argv[3]);
    const char* key_input = argv[4];
    const char* iv_input = argv[5];
    const char* input_file = argv[6];
    const char* output_file = argv[7];

    // 检查选项
    int use_binary = 0;
    int use_ascii = 0;
    const char* aad_input = NULL;

    for (int i = 8; i < argc; i++) {
        if (strcmp(argv[i], "--binary") == 0 || strcmp(argv[i], "-b") == 0) {
            use_binary = 1;
        } else if (strcmp(argv[i], "--ascii") == 0 || strcmp(argv[i], "-a") == 0) {
            use_ascii = 1;
        } else {
            aad_input = argv[i];
        }
    }

    // 验证参数
    if (strcmp(operation, "enc") != 0 && strcmp(operation, "dec") != 0) {
        fprintf(stderr, "Error: Operation must be 'enc' or 'dec'\n");
        return 1;
    }

    if (key_bits != 128 && key_bits != 192 && key_bits != 256) {
        fprintf(stderr, "Error: Invalid key size (must be 128, 192, or 256)\n");
        return 1;
    }

    // 解析密钥
    int key_len = key_bits / 8;
    uint8_t key[32] = {0};

    if (use_ascii) {
        // ASCII 模式：直接使用字符串
        int ret = ascii_to_bytes(key_input, key, key_len);
        if (ret != 0) {
            fprintf(stderr, "Error: Failed to convert ASCII key\n");
            return 1;
        }
        printf("Using ASCII key (length: %zu, required: %d bytes)\n",
               strlen(key_input), key_len);
        if (strlen(key_input) != (size_t)key_len) {
            printf("Warning: Key length mismatch. ");
            if (strlen(key_input) < (size_t)key_len) {
                printf("Padding with zeros.\n");
            } else {
                printf("Truncating to %d bytes.\n", key_len);
            }
        }
        print_hex("Key", key, key_len);
    } else {
        // Hex 模式
        if (hex_to_bytes(key_input, key, key_len) != 0) {
            fprintf(stderr, "Error: Invalid hex key (expected %d hex chars, got %zu)\n",
                    key_len * 2, strlen(key_input));
            return 1;
        }
        printf("Using hex key\n");
        print_hex("Key", key, key_len);
    }

    // 解析 IV
    uint8_t iv[16] = {0};
    size_t iv_len = 16;

    if (strcmp(mode, "gcm") == 0) {
        // GCM 模式：IV 可以是 12 或 16 字节
        if (use_ascii) {
            size_t ascii_len = strlen(iv_input);
            iv_len = (ascii_len > 16) ? 16 : ascii_len;
            ascii_to_bytes(iv_input, iv, iv_len);
            printf("Using ASCII IV (length: %zu bytes)\n", iv_len);
        } else {
            iv_len = strlen(iv_input) / 2;
            if (iv_len > 16) iv_len = 16;
            if (hex_to_bytes(iv_input, iv, iv_len) != 0) {
                fprintf(stderr, "Error: Invalid hex IV\n");
                return 1;
            }
            printf("Using hex IV (length: %zu bytes)\n", iv_len);
        }
        print_hex("IV", iv, iv_len);
    } else if (strcmp(mode, "ecb") != 0) {
        // CBC/CTR 模式：IV 必须是 16 字节
        if (use_ascii) {
            ascii_to_bytes(iv_input, iv, 16);
            printf("Using ASCII IV (length: %zu, required: 16 bytes)\n", strlen(iv_input));
            if (strlen(iv_input) != 16) {
                printf("Warning: IV length mismatch. ");
                if (strlen(iv_input) < 16) {
                    printf("Padding with zeros.\n");
                } else {
                    printf("Truncating to 16 bytes.\n");
                }
            }
        } else {
            if (hex_to_bytes(iv_input, iv, 16) != 0) {
                fprintf(stderr, "Error: Invalid hex IV (expected 32 hex chars, got %zu)\n",
                        strlen(iv_input));
                return 1;
            }
            printf("Using hex IV\n");
        }
        print_hex("IV", iv, 16);
    }

    printf("\nReading input file: %s\n", input_file);
    printf("Output format: %s\n", use_binary ? "Binary" : "Base64");
    printf("Mode: %s-%d %s\n", mode, key_bits, operation);

    // 读取输入文件
    size_t input_size;
    uint8_t* input_data = read_file(input_file, &input_size);
    if (!input_data) {
        return 1;
    }

    printf("Input size: %zu bytes\n\n", input_size);

    // ========== 加密 ==========
    if (strcmp(operation, "enc") == 0) {
        // GCM 模式
        if (strcmp(mode, "gcm") == 0) {
            size_t aad_len = aad_input ? strlen(aad_input) : 0;
            uint8_t* ciphertext = malloc(input_size);
            uint8_t tag[16];

            if (!ciphertext) {
                fprintf(stderr, "Memory allocation failed\n");
                free(input_data);
                return 1;
            }

            int ret = aes_gcm_encrypt(key, key_bits, iv, iv_len,
                                      input_data, input_size,
                                      (const uint8_t*)aad_input, aad_len,
                                      ciphertext, tag, 16);

            if (ret != 0) {
                fprintf(stderr, "GCM encryption failed (error: 0x%04x)\n", -ret);
                free(ciphertext);
                free(input_data);
                return 1;
            }

            // 合并 ciphertext + tag
            uint8_t* output = malloc(input_size + 16);
            if (!output) {
                fprintf(stderr, "Memory allocation failed\n");
                free(ciphertext);
                free(input_data);
                return 1;
            }

            memcpy(output, ciphertext, input_size);
            memcpy(output + input_size, tag, 16);
            free(ciphertext);
            free(input_data);

            if (use_binary) {
                if (write_file(output_file, output, input_size + 16) != 0) {
                    free(output);
                    return 1;
                }
                printf("Binary output: %zu bytes\n", input_size + 16);
            } else {
                size_t b64_len;
                char* base64 = base64_encode(output, input_size + 16, &b64_len);
                if (!base64) {
                    fprintf(stderr, "Base64 encoding failed\n");
                    free(output);
                    return 1;
                }

                if (write_file(output_file, base64, b64_len) != 0) {
                    free(base64);
                    free(output);
                    return 1;
                }
                printf("Base64 output: %zu bytes\n", b64_len);
                free(base64);
            }

            free(output);
            printf("Encryption successful!\n");
            return 0;
        }

        // ECB/CBC/CTR 模式
        size_t buffer_size = ((input_size / AES_BLOCKLEN) + 1) * AES_BLOCKLEN;
        uint8_t* buffer = malloc(buffer_size);
        if (!buffer) {
            fprintf(stderr, "Memory allocation failed\n");
            free(input_data);
            return 1;
        }

        memcpy(buffer, input_data, input_size);
        free(input_data);

        // PKCS7 填充
        if (strcmp(mode, "cbc") == 0 || strcmp(mode, "ecb") == 0) {
            buffer_size = pkcs7_pad(buffer, input_size, AES_BLOCKLEN);
            printf("After PKCS7 padding: %zu bytes\n", buffer_size);
        } else {
            buffer_size = input_size;
        }

        // 执行加密
        int ret = 0;
        if (strcmp(mode, "cbc") == 0) {
            ret = aes_cbc_encrypt(key, key_bits, iv, buffer, buffer_size);
        } else if (strcmp(mode, "ecb") == 0) {
            ret = aes_ecb_encrypt(key, key_bits, buffer, buffer_size);
        } else if (strcmp(mode, "ctr") == 0) {
            ret = aes_ctr_crypt(key, key_bits, iv, buffer, buffer_size);
        } else {
            fprintf(stderr, "Error: Unknown mode '%s'\n", mode);
            free(buffer);
            return 1;
        }

        if (ret != 0) {
            fprintf(stderr, "Encryption failed (error: 0x%04x)\n", -ret);
            free(buffer);
            return 1;
        }

        if (use_binary) {
            if (write_file(output_file, buffer, buffer_size) != 0) {
                free(buffer);
                return 1;
            }
            printf("Binary output: %zu bytes\n", buffer_size);
        } else {
            size_t b64_len;
            char* base64 = base64_encode(buffer, buffer_size, &b64_len);
            if (!base64) {
                fprintf(stderr, "Base64 encoding failed\n");
                free(buffer);
                return 1;
            }

            if (write_file(output_file, base64, b64_len) != 0) {
                free(base64);
                free(buffer);
                return 1;
            }
            printf("Base64 output: %zu bytes\n", b64_len);
            free(base64);
        }

        free(buffer);
        printf("Encryption successful!\n");
        return 0;
    }

    // ========== 解密 ==========
    if (strcmp(operation, "dec") == 0) {
        uint8_t* decoded = NULL;
        size_t decoded_len = 0;

        if (use_binary) {
            decoded = input_data;
            decoded_len = input_size;
            printf("Using binary input directly\n");
        } else {
            decoded = base64_decode((char*)input_data, input_size, &decoded_len);
            free(input_data);

            if (!decoded) {
                fprintf(stderr, "Error: Invalid Base64 input\n");
                return 1;
            }
            printf("Decoded from Base64: %zu bytes\n", decoded_len);
        }

        // GCM 模式
        if (strcmp(mode, "gcm") == 0) {
            if (decoded_len < 16) {
                fprintf(stderr, "Error: Input too short for GCM\n");
                free(decoded);
                return 1;
            }

            size_t ciphertext_len = decoded_len - 16;
            uint8_t* plaintext = malloc(ciphertext_len);
            if (!plaintext) {
                fprintf(stderr, "Memory allocation failed\n");
                free(decoded);
                return 1;
            }

            size_t aad_len = aad_input ? strlen(aad_input) : 0;

            int ret = aes_gcm_decrypt(key, key_bits, iv, iv_len,
                                      decoded, ciphertext_len,
                                      (const uint8_t*)aad_input, aad_len,
                                      decoded + ciphertext_len, 16, plaintext);

            if (ret != 0) {
                fprintf(stderr, "GCM decryption failed (error: 0x%04x)\n", -ret);
                fprintf(stderr, "Authentication tag verification failed!\n");
                free(decoded);
                free(plaintext);
                return 1;
            }

            if (write_file(output_file, plaintext, ciphertext_len) != 0) {
                free(decoded);
                free(plaintext);
                return 1;
            }

            printf("Decryption successful! Output: %zu bytes\n", ciphertext_len);
            free(decoded);
            free(plaintext);
            return 0;
        }

        // ECB/CBC/CTR 模式
        if ((strcmp(mode, "cbc") == 0 || strcmp(mode, "ecb") == 0) &&
            decoded_len % AES_BLOCKLEN != 0) {
            fprintf(stderr, "Error: Invalid ciphertext length %zu (must be multiple of 16)\n",
                    decoded_len);
            free(decoded);
            return 1;
        }

        // 执行解密
        int ret = 0;
        if (strcmp(mode, "cbc") == 0) {
            ret = aes_cbc_decrypt(key, key_bits, iv, decoded, decoded_len);
        } else if (strcmp(mode, "ecb") == 0) {
            ret = aes_ecb_decrypt(key, key_bits, decoded, decoded_len);
        } else if (strcmp(mode, "ctr") == 0) {
            ret = aes_ctr_crypt(key, key_bits, iv, decoded, decoded_len);
        } else {
            fprintf(stderr, "Error: Unknown mode '%s'\n", mode);
            free(decoded);
            return 1;
        }

        if (ret != 0) {
            fprintf(stderr, "Decryption failed (error: 0x%04x)\n", -ret);
            free(decoded);
            return 1;
        }

        // 去除填充
        size_t plaintext_len = decoded_len;
        if (strcmp(mode, "cbc") == 0 || strcmp(mode, "ecb") == 0) {
            plaintext_len = pkcs7_unpad(decoded, decoded_len);
            printf("After removing PKCS7 padding: %zu bytes\n", plaintext_len);
        }

        if (write_file(output_file, decoded, plaintext_len) != 0) {
            free(decoded);
            return 1;
        }

        printf("Decryption successful! Output: %zu bytes\n", plaintext_len);
        free(decoded);
        return 0;
    }

    return 0;
}
