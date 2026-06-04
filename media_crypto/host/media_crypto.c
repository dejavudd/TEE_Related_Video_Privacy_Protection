#define _FILE_OFFSET_BITS 64

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/types.h>
#include <tee_client_api.h>

#include "ta_media_crypto.h"

#define CHUNK_SIZE (64U * 1024U)
#define CIPHER_BLOCK_SIZE 16U
#define MEDIA_CRYPTO_VERSION 2U
#define MEDIA_CRYPTO_ALG_SM4_CTR 1U
#define MEDIA_CRYPTO_FLAG_VIDEO 1U

static const uint8_t file_magic[8] = {
    'M', 'C', 'T', 'E', 'E', 'v', '2', '\0'
};

typedef struct __attribute__((packed)) media_crypto_header {
    uint8_t magic[8];
    uint32_t version;
    uint32_t algorithm;
    uint32_t flags;
    uint32_t header_size;
    uint64_t plain_size;
    uint64_t cipher_size;
    uint32_t chunk_size;
    uint8_t iv[TA_MEDIA_CRYPTO_IV_SIZE];
    char media_type[16];
    uint8_t reserved[16];
} media_crypto_header_t;

static TEEC_Context ctx;
static TEEC_Session sess;
static const TEEC_UUID uuid = TA_MEDIA_CRYPTO_UUID;

static int read_exact(FILE *file, void *buf, size_t len);

static double now_seconds(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0.0;

    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

static double bytes_to_mib(uint64_t bytes)
{
    return (double)bytes / (1024.0 * 1024.0);
}

static void print_perf(const char *phase, uint64_t bytes, double seconds)
{
    double mib = bytes_to_mib(bytes);
    double throughput = seconds > 0.0 ? mib / seconds : 0.0;

    printf("%s stats: %.2f MiB in %.3f s, %.2f MiB/s\n",
           phase, mib, seconds, throughput);
}

static void init_tee(void)
{
    TEEC_Result res;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed: 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
        TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_OpenSession failed: 0x%x, origin: 0x%x",
             res, err_origin);
}

static void finalize_tee(void)
{
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
}

static int get_file_size(FILE *file, uint64_t *size)
{
    off_t end;

    if (fseeko(file, 0, SEEK_END) != 0)
        return -1;

    end = ftello(file);
    if (end < 0)
        return -1;

    if (fseeko(file, 0, SEEK_SET) != 0)
        return -1;

    *size = (uint64_t)end;
    return 0;
}

static int get_path_size(const char *path, uint64_t *size)
{
    FILE *file = NULL;
    int ret;

    file = fopen(path, "rb");
    if (!file) {
        perror("fopen");
        return -1;
    }

    ret = get_file_size(file, size);
    if (ret != 0)
        perror("get file size");

    fclose(file);
    return ret;
}

static char *make_suffixed_path(const char *prefix, const char *suffix)
{
    size_t prefix_len = strlen(prefix);
    size_t suffix_len = strlen(suffix);
    char *path = malloc(prefix_len + suffix_len + 1);

    if (!path)
        return NULL;

    memcpy(path, prefix, prefix_len);
    memcpy(path + prefix_len, suffix, suffix_len + 1);
    return path;
}

static int compare_files(const char *left_path, const char *right_path,
                         bool *equal)
{
    FILE *left = NULL;
    FILE *right = NULL;
    uint8_t *left_buf = NULL;
    uint8_t *right_buf = NULL;
    uint64_t left_size = 0;
    uint64_t right_size = 0;
    uint64_t remaining;
    int ret = 1;

    *equal = false;

    left = fopen(left_path, "rb");
    if (!left) {
        perror("fopen left");
        goto out;
    }

    right = fopen(right_path, "rb");
    if (!right) {
        perror("fopen right");
        goto out;
    }

    if (get_file_size(left, &left_size) != 0) {
        perror("get left size");
        goto out;
    }

    if (get_file_size(right, &right_size) != 0) {
        perror("get right size");
        goto out;
    }

    if (left_size != right_size) {
        ret = 0;
        goto out;
    }

    left_buf = malloc(CHUNK_SIZE);
    right_buf = malloc(CHUNK_SIZE);
    if (!left_buf || !right_buf) {
        perror("malloc");
        goto out;
    }

    remaining = left_size;
    while (remaining > 0) {
        size_t to_read = remaining > CHUNK_SIZE ?
                 CHUNK_SIZE : (size_t)remaining;

        if (read_exact(left, left_buf, to_read) != 0 ||
            read_exact(right, right_buf, to_read) != 0) {
            fprintf(stderr, "failed to compare files\n");
            goto out;
        }

        if (memcmp(left_buf, right_buf, to_read) != 0) {
            ret = 0;
            goto out;
        }

        remaining -= to_read;
    }

    *equal = true;
    ret = 0;

out:
    free(left_buf);
    free(right_buf);
    if (left)
        fclose(left);
    if (right)
        fclose(right);
    return ret;
}

static bool has_video_extension(const char *path)
{
    const char *dot = strrchr(path, '.');

    if (!dot)
        return false;

    return strcasecmp(dot, ".mp4") == 0 ||
           strcasecmp(dot, ".mkv") == 0 ||
           strcasecmp(dot, ".avi") == 0 ||
           strcasecmp(dot, ".mov") == 0 ||
           strcasecmp(dot, ".flv") == 0 ||
           strcasecmp(dot, ".webm") == 0 ||
           strcasecmp(dot, ".h264") == 0 ||
           strcasecmp(dot, ".h265") == 0;
}

static void print_progress(bool show, const char *phase,
                           uint64_t done, uint64_t total)
{
    unsigned int percent = 100;

    if (!show)
        return;

    if (total != 0)
        percent = (unsigned int)((done * 100U) / total);

    fprintf(stderr, "\r%s: %llu/%llu bytes (%u%%)", phase,
            (unsigned long long)done,
            (unsigned long long)total,
            percent);
    fflush(stderr);
}

static TEEC_Result cipher_init(bool encrypt, uint8_t iv[TA_MEDIA_CRYPTO_IV_SIZE])
{
    TEEC_Operation op;
    uint32_t err_origin;

    memset(&op, 0, sizeof(op));

    if (encrypt) {
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                         TEEC_NONE, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = iv;
        op.params[0].tmpref.size = TA_MEDIA_CRYPTO_IV_SIZE;
        return TEEC_InvokeCommand(&sess, TA_MEDIA_CRYPTO_CMD_ENCRYPT_INIT,
                                  &op, &err_origin);
    }

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = iv;
    op.params[0].tmpref.size = TA_MEDIA_CRYPTO_IV_SIZE;
    return TEEC_InvokeCommand(&sess, TA_MEDIA_CRYPTO_CMD_DECRYPT_INIT,
                              &op, &err_origin);
}

static TEEC_Result cipher_update(uint8_t *input, size_t len,
                                 uint8_t *output, size_t *output_len)
{
    TEEC_Operation op;
    uint32_t err_origin;
    TEEC_Result res;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = input;
    op.params[0].tmpref.size = len;
    op.params[1].tmpref.buffer = output;
    op.params[1].tmpref.size = *output_len;

    res = TEEC_InvokeCommand(&sess, TA_MEDIA_CRYPTO_CMD_UPDATE,
                             &op, &err_origin);
    *output_len = op.params[1].tmpref.size;
    return res;
}

static void cipher_finish(void)
{
    TEEC_Operation op;
    uint32_t err_origin;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);
    (void)TEEC_InvokeCommand(&sess, TA_MEDIA_CRYPTO_CMD_FINISH,
                             &op, &err_origin);
}

static TEEC_Result hmac_init(void)
{
    TEEC_Operation op;
    uint32_t err_origin;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);
    return TEEC_InvokeCommand(&sess, TA_MEDIA_CRYPTO_CMD_HMAC_INIT,
                              &op, &err_origin);
}

static TEEC_Result hmac_update(const void *data, size_t len)
{
    TEEC_Operation op;
    uint32_t err_origin;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)data;
    op.params[0].tmpref.size = len;
    return TEEC_InvokeCommand(&sess, TA_MEDIA_CRYPTO_CMD_HMAC_UPDATE,
                              &op, &err_origin);
}

static TEEC_Result hmac_final(uint8_t tag[TA_MEDIA_CRYPTO_HMAC_SIZE])
{
    TEEC_Operation op;
    uint32_t err_origin;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = tag;
    op.params[0].tmpref.size = TA_MEDIA_CRYPTO_HMAC_SIZE;
    return TEEC_InvokeCommand(&sess, TA_MEDIA_CRYPTO_CMD_HMAC_FINAL,
                              &op, &err_origin);
}

static void hmac_finish(void)
{
    TEEC_Operation op;
    uint32_t err_origin;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);
    (void)TEEC_InvokeCommand(&sess, TA_MEDIA_CRYPTO_CMD_HMAC_FINISH,
                             &op, &err_origin);
}

static int write_all(FILE *file, const void *buf, size_t len)
{
    return fwrite(buf, 1, len, file) == len ? 0 : -1;
}

static int read_exact(FILE *file, void *buf, size_t len)
{
    return fread(buf, 1, len, file) == len ? 0 : -1;
}

static int copy_with_byte_xor(const char *input_path, const char *output_path,
                              uint64_t flip_offset, uint8_t mask)
{
    FILE *input = NULL;
    FILE *output = NULL;
    uint8_t *buf = NULL;
    uint64_t file_size = 0;
    uint64_t copied = 0;
    int ret = 1;

    if (strcmp(input_path, output_path) == 0) {
        fprintf(stderr, "input and output must be different files\n");
        return 1;
    }

    input = fopen(input_path, "rb");
    if (!input) {
        perror("fopen input");
        goto out;
    }

    if (get_file_size(input, &file_size) != 0) {
        perror("get input size");
        goto out;
    }

    if (flip_offset >= file_size) {
        fprintf(stderr, "attack offset is outside input file\n");
        goto out;
    }

    output = fopen(output_path, "wb");
    if (!output) {
        perror("fopen output");
        goto out;
    }

    buf = malloc(CHUNK_SIZE);
    if (!buf) {
        perror("malloc");
        goto out;
    }

    while (copied < file_size) {
        size_t to_read = file_size - copied > CHUNK_SIZE ?
                 CHUNK_SIZE : (size_t)(file_size - copied);

        if (read_exact(input, buf, to_read) != 0) {
            fprintf(stderr, "failed to read input file\n");
            goto out;
        }

        if (flip_offset >= copied && flip_offset < copied + to_read)
            buf[flip_offset - copied] ^= mask;

        if (write_all(output, buf, to_read) != 0) {
            perror("write output");
            goto out;
        }

        copied += to_read;
    }

    ret = 0;

out:
    free(buf);
    if (input)
        fclose(input);
    if (output)
        fclose(output);
    return ret;
}

static int copy_prefix(const char *input_path, const char *output_path,
                       uint64_t keep_size)
{
    FILE *input = NULL;
    FILE *output = NULL;
    uint8_t *buf = NULL;
    uint64_t file_size = 0;
    uint64_t copied = 0;
    int ret = 1;

    if (strcmp(input_path, output_path) == 0) {
        fprintf(stderr, "input and output must be different files\n");
        return 1;
    }

    input = fopen(input_path, "rb");
    if (!input) {
        perror("fopen input");
        goto out;
    }

    if (get_file_size(input, &file_size) != 0) {
        perror("get input size");
        goto out;
    }

    if (keep_size > file_size) {
        fprintf(stderr, "truncate size is outside input file\n");
        goto out;
    }

    output = fopen(output_path, "wb");
    if (!output) {
        perror("fopen output");
        goto out;
    }

    buf = malloc(CHUNK_SIZE);
    if (!buf) {
        perror("malloc");
        goto out;
    }

    while (copied < keep_size) {
        size_t to_read = keep_size - copied > CHUNK_SIZE ?
                 CHUNK_SIZE : (size_t)(keep_size - copied);

        if (read_exact(input, buf, to_read) != 0) {
            fprintf(stderr, "failed to read input file\n");
            goto out;
        }

        if (write_all(output, buf, to_read) != 0) {
            perror("write output");
            goto out;
        }

        copied += to_read;
    }

    ret = 0;

out:
    free(buf);
    if (input)
        fclose(input);
    if (output)
        fclose(output);
    return ret;
}

static bool header_valid(const media_crypto_header_t *header)
{
    return memcmp(header->magic, file_magic, sizeof(header->magic)) == 0 &&
           header->version == MEDIA_CRYPTO_VERSION &&
           header->algorithm == MEDIA_CRYPTO_ALG_SM4_CTR &&
           header->header_size == sizeof(*header) &&
           header->chunk_size == CHUNK_SIZE &&
           header->cipher_size >= header->plain_size &&
           header->cipher_size - header->plain_size < CIPHER_BLOCK_SIZE;
}

static int load_encrypted_header(const char *input_path,
                                 media_crypto_header_t *header,
                                 uint64_t *file_size)
{
    FILE *input = NULL;
    uint64_t expected_size;
    int ret = 1;

    input = fopen(input_path, "rb");
    if (!input) {
        perror("fopen input");
        goto out;
    }

    if (get_file_size(input, file_size) != 0) {
        perror("get encrypted file size");
        goto out;
    }

    if (*file_size < sizeof(*header) + TA_MEDIA_CRYPTO_HMAC_SIZE) {
        fprintf(stderr, "input is too small to be a media crypto file\n");
        goto out;
    }

    if (read_exact(input, header, sizeof(*header)) != 0) {
        fprintf(stderr, "failed to read media crypto header\n");
        goto out;
    }

    if (!header_valid(header)) {
        fprintf(stderr, "invalid media crypto header\n");
        goto out;
    }

    expected_size = header->header_size + header->cipher_size +
                    TA_MEDIA_CRYPTO_HMAC_SIZE;
    if (*file_size != expected_size) {
        fprintf(stderr, "encrypted file size does not match header\n");
        goto out;
    }

    ret = 0;

out:
    if (input)
        fclose(input);
    return ret;
}

static const char *algorithm_name(uint32_t algorithm)
{
    switch (algorithm) {
    case MEDIA_CRYPTO_ALG_SM4_CTR:
        return "SM4-CTR";
    default:
        return "unknown";
    }
}

static int fill_header(media_crypto_header_t *header,
                       uint64_t plain_size, bool video)
{
    memset(header, 0, sizeof(*header));
    memcpy(header->magic, file_magic, sizeof(header->magic));
    header->version = MEDIA_CRYPTO_VERSION;
    header->algorithm = MEDIA_CRYPTO_ALG_SM4_CTR;
    header->flags = video ? MEDIA_CRYPTO_FLAG_VIDEO : 0;
    header->header_size = sizeof(*header);
    header->plain_size = plain_size;
    header->cipher_size = ((plain_size + CIPHER_BLOCK_SIZE - 1) /
                   CIPHER_BLOCK_SIZE) * CIPHER_BLOCK_SIZE;
    header->chunk_size = CHUNK_SIZE;
    snprintf(header->media_type, sizeof(header->media_type),
             "%s", video ? "video" : "file");
    return 0;
}

static int encrypt_file(const char *input_path, const char *output_path,
                        bool video)
{
    FILE *input = NULL;
    FILE *output = NULL;
    uint8_t *input_buf = NULL;
    uint8_t *output_buf = NULL;
    uint8_t tag[TA_MEDIA_CRYPTO_HMAC_SIZE] = { 0 };
    media_crypto_header_t header;
    uint64_t plain_size = 0;
    uint64_t processed = 0;
    size_t input_len;
    double start_time = 0.0;
    int ret = 1;

    if (video && !has_video_extension(input_path))
        fprintf(stderr, "warning: input suffix is not a common video type\n");

    input = fopen(input_path, "rb");
    if (!input) {
        perror("fopen input");
        goto out;
    }

    if (get_file_size(input, &plain_size) != 0) {
        perror("get input size");
        goto out;
    }

    output = fopen(output_path, "wb");
    if (!output) {
        perror("fopen output");
        goto out;
    }

    fill_header(&header, plain_size, video);
    start_time = now_seconds();

    TEEC_Result res = hmac_init();
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TA hmac init failed: 0x%x\n", res);
        goto out;
    }

    res = cipher_init(true, header.iv);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TA encrypt init failed: 0x%x\n", res);
        goto out_hmac;
    }

    res = hmac_update(&header, sizeof(header));
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TA hmac header failed: 0x%x\n", res);
        goto out_finish;
    }

    if (write_all(output, &header, sizeof(header)) != 0) {
        perror("write header");
        goto out_finish;
    }

    input_buf = malloc(CHUNK_SIZE);
    output_buf = malloc(CHUNK_SIZE);
    if (!input_buf || !output_buf) {
        perror("malloc");
        goto out_finish;
    }

    while ((input_len = fread(input_buf, 1, CHUNK_SIZE, input)) > 0) {
        size_t process_len = input_len;
        size_t output_len = CHUNK_SIZE;

        if (processed + input_len == plain_size &&
            process_len % CIPHER_BLOCK_SIZE != 0) {
            size_t padded_len = ((process_len + CIPHER_BLOCK_SIZE - 1) /
                         CIPHER_BLOCK_SIZE) * CIPHER_BLOCK_SIZE;

            memset(input_buf + process_len, 0, padded_len - process_len);
            process_len = padded_len;
        }

        res = cipher_update(input_buf, process_len, output_buf, &output_len);
        if (res != TEEC_SUCCESS) {
            fprintf(stderr, "TA encrypt update failed: 0x%x\n", res);
            goto out_finish;
        }

        if (output_len != process_len) {
            fprintf(stderr, "unexpected encrypted block length: %zu != %zu\n",
                    output_len, process_len);
            goto out_finish;
        }

        res = hmac_update(output_buf, output_len);
        if (res != TEEC_SUCCESS) {
            fprintf(stderr, "TA hmac data failed: 0x%x\n", res);
            goto out_finish;
        }

        if (write_all(output, output_buf, output_len) != 0) {
            perror("write ciphertext");
            goto out_finish;
        }

        processed += input_len;
        print_progress(video, "video encrypt", processed, plain_size);
    }

    if (video)
        fprintf(stderr, "\n");

    if (ferror(input)) {
        perror("read input");
        goto out_finish;
    }

    res = hmac_final(tag);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TA hmac final failed: 0x%x\n", res);
        goto out_cipher;
    }

    if (write_all(output, tag, sizeof(tag)) != 0) {
        perror("write hmac");
        goto out_cipher;
    }

    ret = 0;
    print_perf(video ? "video encrypt" : "encrypt",
               processed, now_seconds() - start_time);

out_cipher:
    cipher_finish();
    goto out;
out_finish:
    cipher_finish();
out_hmac:
    hmac_finish();
out:
    free(input_buf);
    free(output_buf);
    if (input)
        fclose(input);
    if (output)
        fclose(output);
    return ret;
}

static int verify_encrypted_file(FILE *input,
                                 const media_crypto_header_t *header,
                                 uint8_t expected_tag[TA_MEDIA_CRYPTO_HMAC_SIZE],
                                 bool video)
{
    uint8_t *buf = NULL;
    uint8_t tag[TA_MEDIA_CRYPTO_HMAC_SIZE] = { 0 };
    uint64_t remaining = header->cipher_size;
    uint64_t processed = 0;
    int ret = 1;

    if (fseeko(input, header->header_size, SEEK_SET) != 0) {
        perror("seek ciphertext");
        return 1;
    }

    TEEC_Result res = hmac_init();
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TA hmac init failed: 0x%x\n", res);
        return 1;
    }

    res = hmac_update(header, sizeof(*header));
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TA hmac header failed: 0x%x\n", res);
        goto out_hmac;
    }

    buf = malloc(CHUNK_SIZE);
    if (!buf) {
        perror("malloc");
        goto out_hmac;
    }

    while (remaining > 0) {
        size_t to_read = remaining > CHUNK_SIZE ? CHUNK_SIZE : (size_t)remaining;

        if (read_exact(input, buf, to_read) != 0) {
            fprintf(stderr, "failed to read ciphertext for hmac\n");
            goto out_hmac;
        }

        res = hmac_update(buf, to_read);
        if (res != TEEC_SUCCESS) {
            fprintf(stderr, "TA hmac data failed: 0x%x\n", res);
            goto out_hmac;
        }

        remaining -= to_read;
        processed += to_read;
        print_progress(video, "video verify", processed, header->cipher_size);
    }

    if (video)
        fprintf(stderr, "\n");

    if (read_exact(input, expected_tag, TA_MEDIA_CRYPTO_HMAC_SIZE) != 0) {
        fprintf(stderr, "failed to read hmac tag\n");
        goto out_hmac;
    }

    res = hmac_final(tag);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TA hmac final failed: 0x%x\n", res);
        goto out_no_hmac;
    }

    if (memcmp(tag, expected_tag, TA_MEDIA_CRYPTO_HMAC_SIZE) != 0) {
        fprintf(stderr, "hmac check failed: encrypted file may be corrupted\n");
        goto out_no_hmac;
    }

    ret = 0;
    goto out_no_hmac;

out_hmac:
    hmac_finish();
out_no_hmac:
    free(buf);
    return ret;
}

static int decrypt_file(const char *input_path, const char *output_path,
                        bool expect_video)
{
    FILE *input = NULL;
    FILE *output = NULL;
    uint8_t *input_buf = NULL;
    uint8_t *output_buf = NULL;
    uint8_t expected_tag[TA_MEDIA_CRYPTO_HMAC_SIZE] = { 0 };
    media_crypto_header_t header;
    uint64_t file_size = 0;
    uint64_t remaining;
    uint64_t written = 0;
    double start_time = 0.0;
    int ret = 1;

    input = fopen(input_path, "rb");
    if (!input) {
        perror("fopen input");
        goto out;
    }

    if (get_file_size(input, &file_size) != 0) {
        perror("get encrypted file size");
        goto out;
    }

    if (read_exact(input, &header, sizeof(header)) != 0) {
        fprintf(stderr, "failed to read media crypto header\n");
        goto out;
    }

    if (!header_valid(&header)) {
        fprintf(stderr, "invalid media crypto header\n");
        goto out;
    }

    if (file_size != header.header_size + header.cipher_size +
                     TA_MEDIA_CRYPTO_HMAC_SIZE) {
        fprintf(stderr, "encrypted file size does not match header\n");
        goto out;
    }

    if (expect_video && (header.flags & MEDIA_CRYPTO_FLAG_VIDEO) == 0)
        fprintf(stderr, "warning: encrypted file is not marked as video\n");

    if (verify_encrypted_file(input, &header, expected_tag,
                              (header.flags & MEDIA_CRYPTO_FLAG_VIDEO) != 0) != 0)
        goto out;

    output = fopen(output_path, "wb");
    if (!output) {
        perror("fopen output");
        goto out;
    }

    if (fseeko(input, header.header_size, SEEK_SET) != 0) {
        perror("seek ciphertext");
        goto out;
    }

    start_time = now_seconds();

    TEEC_Result res = cipher_init(false, header.iv);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TA decrypt init failed: 0x%x\n", res);
        goto out;
    }

    input_buf = malloc(CHUNK_SIZE);
    output_buf = malloc(CHUNK_SIZE);
    if (!input_buf || !output_buf) {
        perror("malloc");
        goto out_finish;
    }

    remaining = header.cipher_size;
    while (remaining > 0) {
        size_t input_len = remaining > CHUNK_SIZE ? CHUNK_SIZE : (size_t)remaining;
        size_t output_len = CHUNK_SIZE;
        size_t write_len;

        if (read_exact(input, input_buf, input_len) != 0) {
            fprintf(stderr, "failed to read ciphertext\n");
            goto out_finish;
        }

        res = cipher_update(input_buf, input_len, output_buf, &output_len);
        if (res != TEEC_SUCCESS) {
            fprintf(stderr, "TA decrypt update failed: 0x%x\n", res);
            goto out_finish;
        }

        write_len = output_len;
        if (written + write_len > header.plain_size)
            write_len = header.plain_size - written;

        if (write_all(output, output_buf, write_len) != 0) {
            perror("write plaintext");
            goto out_finish;
        }

        remaining -= input_len;
        written += write_len;
        print_progress((header.flags & MEDIA_CRYPTO_FLAG_VIDEO) != 0,
                       "video decrypt", written, header.plain_size);
    }

    if ((header.flags & MEDIA_CRYPTO_FLAG_VIDEO) != 0)
        fprintf(stderr, "\n");

    if (written != header.plain_size) {
        fprintf(stderr, "decrypted size mismatch: %llu != %llu\n",
                (unsigned long long)written,
                (unsigned long long)header.plain_size);
        goto out_finish;
    }

    ret = 0;
    print_perf((header.flags & MEDIA_CRYPTO_FLAG_VIDEO) != 0 ?
               "video decrypt" : "decrypt",
               written, now_seconds() - start_time);

out_finish:
    cipher_finish();
out:
    free(input_buf);
    free(output_buf);
    if (input)
        fclose(input);
    if (output)
        fclose(output);
    return ret;
}

static int show_info(const char *input_path)
{
    FILE *input = NULL;
    media_crypto_header_t header;
    uint64_t file_size = 0;
    uint64_t expected_size;
    int ret = 1;

    input = fopen(input_path, "rb");
    if (!input) {
        perror("fopen input");
        goto out;
    }

    if (get_file_size(input, &file_size) != 0) {
        perror("get encrypted file size");
        goto out;
    }

    if (read_exact(input, &header, sizeof(header)) != 0) {
        fprintf(stderr, "failed to read media crypto header\n");
        goto out;
    }

    if (!header_valid(&header)) {
        fprintf(stderr, "invalid media crypto header\n");
        goto out;
    }

    expected_size = header.header_size + header.cipher_size +
                    TA_MEDIA_CRYPTO_HMAC_SIZE;

    printf("Media Crypto File Info\n");
    printf("  Type          : %s\n", header.media_type);
    printf("  Version       : %u\n", header.version);
    printf("  Algorithm     : %s\n", algorithm_name(header.algorithm));
    printf("  Integrity     : HMAC-SM3 enabled\n");
    printf("  TEE key       : TA private demo key\n");
    printf("  Plain size    : %llu bytes (%.2f MiB)\n",
           (unsigned long long)header.plain_size,
           bytes_to_mib(header.plain_size));
    printf("  Cipher size   : %llu bytes (%.2f MiB)\n",
           (unsigned long long)header.cipher_size,
           bytes_to_mib(header.cipher_size));
    printf("  Chunk size    : %u bytes\n", header.chunk_size);
    printf("  Header size   : %u bytes\n", header.header_size);
    printf("  HMAC size     : %u bytes\n", TA_MEDIA_CRYPTO_HMAC_SIZE);
    printf("  File size     : %llu bytes\n",
           (unsigned long long)file_size);
    printf("  Size check    : %s\n",
           file_size == expected_size ? "ok" : "mismatch");
    ret = file_size == expected_size ? 0 : 1;

out:
    if (input)
        fclose(input);
    return ret;
}

static int attack_bitflip(const char *input_path, const char *output_path)
{
    media_crypto_header_t header;
    uint64_t file_size = 0;
    uint64_t offset;

    if (load_encrypted_header(input_path, &header, &file_size) != 0)
        return 1;

    if (header.cipher_size == 0) {
        fprintf(stderr, "ciphertext is empty, bitflip attack is not available\n");
        return 1;
    }

    offset = header.header_size + header.cipher_size / 2;
    if (copy_with_byte_xor(input_path, output_path, offset, 0x01) != 0)
        return 1;

    printf("attack-bitflip wrote %s\n", output_path);
    printf("  modified ciphertext byte offset: %llu\n",
           (unsigned long long)offset);
    printf("  expected result: decrypt should fail with HMAC check error\n");
    (void)file_size;
    return 0;
}

static int attack_header(const char *input_path, const char *output_path)
{
    media_crypto_header_t header;
    uint64_t file_size = 0;
    uint64_t offset;

    if (load_encrypted_header(input_path, &header, &file_size) != 0)
        return 1;

    offset = offsetof(media_crypto_header_t, reserved);
    if (copy_with_byte_xor(input_path, output_path, offset, 0x01) != 0)
        return 1;

    printf("attack-header wrote %s\n", output_path);
    printf("  modified protected header byte offset: %llu\n",
           (unsigned long long)offset);
    printf("  expected result: header may parse, but decrypt should fail HMAC\n");
    (void)file_size;
    return 0;
}

static int attack_tag(const char *input_path, const char *output_path)
{
    media_crypto_header_t header;
    uint64_t file_size = 0;
    uint64_t offset;

    if (load_encrypted_header(input_path, &header, &file_size) != 0)
        return 1;

    offset = file_size - 1;
    if (copy_with_byte_xor(input_path, output_path, offset, 0x01) != 0)
        return 1;

    printf("attack-tag wrote %s\n", output_path);
    printf("  modified HMAC tag byte offset: %llu\n",
           (unsigned long long)offset);
    printf("  expected result: decrypt should fail with HMAC check error\n");
    return 0;
}

static int attack_truncate(const char *input_path, const char *output_path)
{
    media_crypto_header_t header;
    uint64_t file_size = 0;
    uint64_t drop_size = TA_MEDIA_CRYPTO_HMAC_SIZE;
    uint64_t keep_size;

    if (load_encrypted_header(input_path, &header, &file_size) != 0)
        return 1;

    if (file_size <= drop_size)
        drop_size = 1;

    keep_size = file_size - drop_size;
    if (copy_prefix(input_path, output_path, keep_size) != 0)
        return 1;

    printf("attack-truncate wrote %s\n", output_path);
    printf("  removed tail bytes: %llu\n",
           (unsigned long long)drop_size);
    printf("  expected result: decrypt/info should fail size validation\n");
    return 0;
}

static int attack_all(const char *input_path, const char *output_prefix)
{
    char *bitflip_path = NULL;
    char *header_path = NULL;
    char *tag_path = NULL;
    char *truncate_path = NULL;
    int ret = 1;

    bitflip_path = make_suffixed_path(output_prefix, ".bitflip.enc");
    header_path = make_suffixed_path(output_prefix, ".header.enc");
    tag_path = make_suffixed_path(output_prefix, ".tag.enc");
    truncate_path = make_suffixed_path(output_prefix, ".truncated.enc");
    if (!bitflip_path || !header_path || !tag_path || !truncate_path) {
        perror("malloc");
        goto out;
    }

    printf("Media Crypto Attack-All\n");
    printf("  source        : %s\n", input_path);
    printf("  output prefix : %s\n", output_prefix);

    if (attack_bitflip(input_path, bitflip_path) != 0)
        goto out;
    if (attack_header(input_path, header_path) != 0)
        goto out;
    if (attack_tag(input_path, tag_path) != 0)
        goto out;
    if (attack_truncate(input_path, truncate_path) != 0)
        goto out;

    printf("Attack samples generated:\n");
    printf("  bitflip   : %s\n", bitflip_path);
    printf("  header    : %s\n", header_path);
    printf("  tag       : %s\n", tag_path);
    printf("  truncated : %s\n", truncate_path);
    printf("Expected verification result:\n");
    printf("  bitflip/header/tag should fail with HMAC check error\n");
    printf("  truncated should fail with file size validation error\n");
    ret = 0;

out:
    free(bitflip_path);
    free(header_path);
    free(tag_path);
    free(truncate_path);
    return ret;
}

static int benchmark_file(const char *input_path, const char *encrypted_path,
                          const char *decrypted_path, bool video)
{
    media_crypto_header_t header;
    uint64_t plain_size = 0;
    uint64_t encrypted_size = 0;
    uint64_t decrypted_size = 0;
    uint64_t overhead = 0;
    double encrypt_start;
    double decrypt_start;
    double encrypt_seconds;
    double decrypt_seconds;
    double total_seconds;
    bool equal = false;
    int ret = 1;

    if (get_path_size(input_path, &plain_size) != 0)
        return 1;

    printf("Media Crypto Benchmark\n");
    printf("  Input       : %s\n", input_path);
    printf("  Encrypted   : %s\n", encrypted_path);
    printf("  Decrypted   : %s\n", decrypted_path);
    printf("  Type        : %s\n", video ? "video" : "file");
    printf("  Algorithm   : SM4-CTR + HMAC-SM3\n");
    printf("  Chunk size  : %u bytes\n", CHUNK_SIZE);
    printf("  Input size  : %llu bytes (%.2f MiB)\n",
           (unsigned long long)plain_size, bytes_to_mib(plain_size));

    encrypt_start = now_seconds();
    if (encrypt_file(input_path, encrypted_path, video) != 0)
        goto out;
    encrypt_seconds = now_seconds() - encrypt_start;

    if (load_encrypted_header(encrypted_path, &header, &encrypted_size) != 0)
        goto out;

    decrypt_start = now_seconds();
    if (decrypt_file(encrypted_path, decrypted_path, video) != 0)
        goto out;
    decrypt_seconds = now_seconds() - decrypt_start;

    if (get_path_size(decrypted_path, &decrypted_size) != 0)
        goto out;

    if (compare_files(input_path, decrypted_path, &equal) != 0)
        goto out;

    if (encrypted_size >= plain_size)
        overhead = encrypted_size - plain_size;

    total_seconds = encrypt_seconds + decrypt_seconds;

    printf("\nBenchmark Summary\n");
    printf("  Plain size        : %llu bytes (%.2f MiB)\n",
           (unsigned long long)plain_size, bytes_to_mib(plain_size));
    printf("  Cipher size       : %llu bytes (%.2f MiB)\n",
           (unsigned long long)header.cipher_size,
           bytes_to_mib(header.cipher_size));
    printf("  Encrypted file    : %llu bytes (%.2f MiB)\n",
           (unsigned long long)encrypted_size,
           bytes_to_mib(encrypted_size));
    printf("  Decrypted file    : %llu bytes (%.2f MiB)\n",
           (unsigned long long)decrypted_size,
           bytes_to_mib(decrypted_size));
    printf("  Encrypt time      : %.3f s\n", encrypt_seconds);
    printf("  Encrypt speed     : %.2f MiB/s\n",
           encrypt_seconds > 0.0 ?
           bytes_to_mib(plain_size) / encrypt_seconds : 0.0);
    printf("  Decrypt time      : %.3f s\n", decrypt_seconds);
    printf("  Decrypt speed     : %.2f MiB/s\n",
           decrypt_seconds > 0.0 ?
           bytes_to_mib(plain_size) / decrypt_seconds : 0.0);
    printf("  Total crypto time : %.3f s\n", total_seconds);
    printf("  Storage overhead  : %llu bytes\n",
           (unsigned long long)overhead);
    printf("  Overhead ratio    : %.6f %%\n",
           plain_size != 0 ?
           ((double)overhead * 100.0) / (double)plain_size : 0.0);
    printf("  Header overhead   : %u bytes\n", header.header_size);
    printf("  HMAC overhead     : %u bytes\n", TA_MEDIA_CRYPTO_HMAC_SIZE);
    printf("  Padding overhead  : %llu bytes\n",
           (unsigned long long)(header.cipher_size - header.plain_size));
    printf("  Compare result    : %s\n", equal ? "match" : "mismatch");

    if (!equal) {
        fprintf(stderr, "benchmark compare failed\n");
        goto out;
    }

    ret = 0;

out:
    return ret;
}

static void usage(const char *prog)
{
    printf("Usage:\n");
    printf("  %s encrypt input_file output_file\n", prog);
    printf("  %s decrypt input_file output_file\n", prog);
    printf("  %s video-encrypt input_video output_file\n", prog);
    printf("  %s video-decrypt input_file output_video\n", prog);
    printf("  %s info encrypted_file\n", prog);
    printf("  %s attack-bitflip encrypted_file tampered_file\n", prog);
    printf("  %s attack-header encrypted_file tampered_file\n", prog);
    printf("  %s attack-tag encrypted_file tampered_file\n", prog);
    printf("  %s attack-truncate encrypted_file tampered_file\n", prog);
    printf("  %s attack-all encrypted_file output_prefix\n", prog);
    printf("  %s benchmark input_file encrypted_file decrypted_file\n", prog);
    printf("  %s video-benchmark input_video encrypted_file decrypted_video\n", prog);
}

int main(int argc, char* argv[])
{
    int res = 0;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "info") == 0) {
        if (argc != 3) {
            usage(argv[0]);
            return 1;
        }
        return show_info(argv[2]);
    }

    if (strcmp(argv[1], "attack-bitflip") == 0 ||
        strcmp(argv[1], "attack-header") == 0 ||
        strcmp(argv[1], "attack-tag") == 0 ||
        strcmp(argv[1], "attack-truncate") == 0 ||
        strcmp(argv[1], "attack-all") == 0) {
        if (argc != 4) {
            usage(argv[0]);
            return 1;
        }

        if (strcmp(argv[1], "attack-bitflip") == 0)
            return attack_bitflip(argv[2], argv[3]);
        if (strcmp(argv[1], "attack-header") == 0)
            return attack_header(argv[2], argv[3]);
        if (strcmp(argv[1], "attack-tag") == 0)
            return attack_tag(argv[2], argv[3]);
        if (strcmp(argv[1], "attack-truncate") == 0)
            return attack_truncate(argv[2], argv[3]);
        return attack_all(argv[2], argv[3]);
    }

    if (argc < 4) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "benchmark") == 0 ||
        strcmp(argv[1], "video-benchmark") == 0) {
        if (argc != 5) {
            usage(argv[0]);
            return 1;
        }
    }

    init_tee();

    if (strcmp(argv[1], "encrypt") == 0)
        res = encrypt_file(argv[2], argv[3], false);
    else if (strcmp(argv[1], "decrypt") == 0)
        res = decrypt_file(argv[2], argv[3], false);
    else if (strcmp(argv[1], "video-encrypt") == 0)
        res = encrypt_file(argv[2], argv[3], true);
    else if (strcmp(argv[1], "video-decrypt") == 0)
        res = decrypt_file(argv[2], argv[3], true);
    else if (strcmp(argv[1], "benchmark") == 0)
        res = benchmark_file(argv[2], argv[3], argv[4], false);
    else if (strcmp(argv[1], "video-benchmark") == 0)
        res = benchmark_file(argv[2], argv[3], argv[4], true);
    else {
        printf("Unknown command: %s\n", argv[1]);
        usage(argv[0]);
        finalize_tee();
        return 1;
    }

    finalize_tee();
    if (res != 0)
        return 1;

    printf("%s completed successfully.\n", argv[1]);
    return 0;
}
