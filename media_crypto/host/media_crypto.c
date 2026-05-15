#define _FILE_OFFSET_BITS 64

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

static void usage(const char *prog)
{
    printf("Usage:\n");
    printf("  %s encrypt input_file output_file\n", prog);
    printf("  %s decrypt input_file output_file\n", prog);
    printf("  %s video-encrypt input_video output_file\n", prog);
    printf("  %s video-decrypt input_file output_video\n", prog);
    printf("  %s info encrypted_file\n", prog);
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

    if (argc < 4) {
        usage(argv[0]);
        return 1;
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
