#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define BUFFER_SIZE 4096
#define SALT_SIZE 16
#define KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16

int derive_key_iv(const char *password, unsigned char *salt, unsigned char *key, unsigned char *iv) {
    unsigned char key_iv_material[KEY_SIZE + IV_SIZE];
    
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, 
                          10000, EVP_sha256(), KEY_SIZE + IV_SIZE, key_iv_material) == 0) {
        OPENSSL_cleanse(key_iv_material, KEY_SIZE + IV_SIZE);
        return 0;
    }
    
    memcpy(key, key_iv_material, KEY_SIZE);
    memcpy(iv, key_iv_material + KEY_SIZE, IV_SIZE);
    
    OPENSSL_cleanse(key_iv_material, KEY_SIZE + IV_SIZE);
    return 1;
}

int encrypt_file(const char *input_file, const char *output_file, const char *password) {
    FILE *in = NULL, *out = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char salt[SALT_SIZE];
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char tag[TAG_SIZE];
    unsigned char in_buf[BUFFER_SIZE];
    unsigned char out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int bytes_read, out_len, final_len;
    int ret = 0;

    in = fopen(input_file, "rb");
    if (!in) {
        fprintf(stderr, "Error: Cannot open input file '%s'\n", input_file);
        return 0;
    }

    out = fopen(output_file, "wb");
    if (!out) {
        fprintf(stderr, "Error: Cannot create output file '%s'\n", output_file);
        fclose(in);
        return 0;
    }

    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        fprintf(stderr, "Error: Failed to generate random salt\n");
        goto cleanup;
    }

    if (fwrite(salt, 1, SALT_SIZE, out) != SALT_SIZE) {
        fprintf(stderr, "Error: Failed to write salt\n");
        goto cleanup;
    }

    if (!derive_key_iv(password, salt, key, iv)) {
        fprintf(stderr, "Error: Failed to derive key\n");
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto cleanup;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) goto cleanup;

    while ((bytes_read = fread(in_buf, 1, BUFFER_SIZE, in)) > 0) {
        if (EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, bytes_read) != 1) goto cleanup;
        if (fwrite(out_buf, 1, out_len, out) != (size_t)out_len) goto cleanup;
    }

    if (EVP_EncryptFinal_ex(ctx, out_buf, &final_len) != 1) goto cleanup;
    if (fwrite(out_buf, 1, final_len, out) != (size_t)final_len) goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) goto cleanup;
    if (fwrite(tag, 1, TAG_SIZE, out) != TAG_SIZE) goto cleanup;

    ret = 1;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (in) fclose(in);
    if (out) fclose(out);
    OPENSSL_cleanse(key, KEY_SIZE);
    OPENSSL_cleanse(iv, IV_SIZE);
    return ret;
}

int decrypt_file(const char *input_file, const char *output_file, const char *password) {
    FILE *in = NULL, *out = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char salt[SALT_SIZE];
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char tag[TAG_SIZE];
    unsigned char in_buf[BUFFER_SIZE];
    unsigned char out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    long file_size, enc_size;
    int bytes_read, out_len, final_len;
    int ret = 0;

    in = fopen(input_file, "rb");
    if (!in) {
        fprintf(stderr, "Error: Cannot open input file '%s'\n", input_file);
        return 0;
    }

    fseek(in, 0, SEEK_END);
    file_size = ftell(in);
    fseek(in, 0, SEEK_SET);

    if (file_size < SALT_SIZE + TAG_SIZE) {
        fprintf(stderr, "Error: File too small\n");
        fclose(in);
        return 0;
    }

    if (fread(salt, 1, SALT_SIZE, in) != SALT_SIZE) goto cleanup;
    fseek(in, -TAG_SIZE, SEEK_END);
    if (fread(tag, 1, TAG_SIZE, in) != TAG_SIZE) goto cleanup;
    fseek(in, SALT_SIZE, SEEK_SET);
    enc_size = file_size - SALT_SIZE - TAG_SIZE;

    out = fopen(output_file, "wb");
    if (!out) {
        fprintf(stderr, "Error: Cannot create output file '%s'\n", output_file);
        fclose(in);
        return 0;
    }

    if (!derive_key_iv(password, salt, key, iv)) goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto cleanup;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag) != 1) goto cleanup;

    long processed = 0;
    while (processed < enc_size) {
        size_t to_read = (enc_size - processed > BUFFER_SIZE) ? BUFFER_SIZE : (enc_size - processed);
        bytes_read = fread(in_buf, 1, to_read, in);
        if (bytes_read <= 0) break;

        if (EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, bytes_read) != 1) goto cleanup;
        if (fwrite(out_buf, 1, out_len, out) != (size_t)out_len) goto cleanup;

        processed += bytes_read;
    }

    if (EVP_DecryptFinal_ex(ctx, out_buf, &final_len) != 1) {
        fprintf(stderr, "Authentication failed: wrong password or corrupted file\n");
        goto cleanup;
    }

    fwrite(out_buf, 1, final_len, out);
    ret = 1;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (in) fclose(in);
    if (out) fclose(out);
    OPENSSL_cleanse(key, KEY_SIZE);
    OPENSSL_cleanse(iv, IV_SIZE);
    return ret;
}
