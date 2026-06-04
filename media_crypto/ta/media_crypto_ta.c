/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define STR_TRACE_USER_TA "MEDIA_CRYPTO"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ta_media_crypto.h"

typedef struct persisted_keys {
    uint8_t enc_key[TA_MEDIA_CRYPTO_KEY_SIZE];
    uint8_t hmac_key[TA_MEDIA_CRYPTO_HMAC_KEY_SIZE];
} persisted_keys_t;

static const uint8_t default_enc_key[TA_MEDIA_CRYPTO_KEY_SIZE] = {
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
};

static const uint8_t default_hmac_key[TA_MEDIA_CRYPTO_HMAC_KEY_SIZE] = {
    0x42, 0x17, 0x6a, 0xc3, 0x9d, 0xe8, 0x01, 0x54,
    0xb6, 0x2f, 0x73, 0x88, 0xac, 0xd1, 0x05, 0xfa,
    0x6e, 0x11, 0x92, 0x40, 0xcb, 0x3a, 0x58, 0x7d,
    0x24, 0xf0, 0x99, 0xbe, 0x13, 0x67, 0xd4, 0x2c,
    0x8f, 0x31, 0x4b, 0xea, 0x75, 0x06, 0xbc, 0x90,
    0x2a, 0xd8, 0x5f, 0x1c, 0xe2, 0x49, 0x83, 0x36,
    0xa7, 0xcd, 0x0e, 0x61, 0x9b, 0x25, 0xf4, 0x70,
    0x3d, 0x84, 0x12, 0xaf, 0x56, 0xe9, 0x0b, 0xc8
};

typedef struct media_crypto_ctx {
    TEE_OperationHandle cipher_op;
    TEE_ObjectHandle cipher_key_obj;
    uint32_t cipher_active;
    TEE_OperationHandle hmac_op;
    TEE_ObjectHandle hmac_key_obj;
    uint32_t hmac_active;
} media_crypto_ctx_t;

static void free_cipher_state(media_crypto_ctx_t *ctx)
{
    if (!ctx)
        return;

    if (ctx->cipher_op != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->cipher_op);
        ctx->cipher_op = TEE_HANDLE_NULL;
    }

    if (ctx->cipher_key_obj != TEE_HANDLE_NULL) {
        TEE_CloseObject(ctx->cipher_key_obj);
        ctx->cipher_key_obj = TEE_HANDLE_NULL;
    }

    ctx->cipher_active = 0;
}

static void free_hmac_state(media_crypto_ctx_t *ctx)
{
    if (!ctx)
        return;

    if (ctx->hmac_op != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->hmac_op);
        ctx->hmac_op = TEE_HANDLE_NULL;
    }

    if (ctx->hmac_key_obj != TEE_HANDLE_NULL) {
        TEE_CloseObject(ctx->hmac_key_obj);
        ctx->hmac_key_obj = TEE_HANDLE_NULL;
    }

    ctx->hmac_active = 0;
}

static TEE_Result load_key_store(persisted_keys_t *keys)
{
    TEE_MemMove(keys->enc_key, default_enc_key, sizeof(keys->enc_key));
    TEE_MemMove(keys->hmac_key, default_hmac_key, sizeof(keys->hmac_key));

    return TEE_SUCCESS;
}

static TEE_Result make_secret_key(TEE_ObjectHandle *key_obj,
                  uint32_t object_type, uint32_t max_key_size,
                  const uint8_t *key, size_t key_len)
{
    TEE_Result res;
    TEE_Attribute attr;

    res = TEE_AllocateTransientObject(object_type, max_key_size, key_obj);
    if (res != TEE_SUCCESS)
        return res;

    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
                 (void *)key, key_len);
    res = TEE_PopulateTransientObject(*key_obj, &attr, 1);
    if (res != TEE_SUCCESS) {
        TEE_CloseObject(*key_obj);
        *key_obj = TEE_HANDLE_NULL;
    }

    return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
        TEE_Param params[4], void **sess_ctx)
{
    media_crypto_ctx_t *ctx = NULL;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    (void)&params;

    ctx = TEE_Malloc(sizeof(*ctx), TEE_MALLOC_FILL_ZERO);
    if (!ctx)
        return TEE_ERROR_OUT_OF_MEMORY;

    ctx->cipher_op = TEE_HANDLE_NULL;
    ctx->cipher_key_obj = TEE_HANDLE_NULL;
    ctx->hmac_op = TEE_HANDLE_NULL;
    ctx->hmac_key_obj = TEE_HANDLE_NULL;
    *sess_ctx = ctx;

    DMSG("Media crypto session opened\n");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    media_crypto_ctx_t *ctx = (media_crypto_ctx_t *)sess_ctx;

    free_cipher_state(ctx);
    free_hmac_state(ctx);
    TEE_Free(ctx);
    DMSG("Media crypto session closed\n");
}

static TEE_Result inc_value(uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    params[0].value.a++;
    return TEE_SUCCESS;
}

static TEE_Result cipher_init(media_crypto_ctx_t *ctx, uint32_t mode,
        uint32_t param_types, TEE_Param params[4])
{
    persisted_keys_t keys;
    TEE_Result res;
    uint8_t iv[TA_MEDIA_CRYPTO_IV_SIZE] = { 0 };
    uint32_t exp_param_types;

    if (!ctx)
        return TEE_ERROR_BAD_STATE;

    if (mode == TEE_MODE_ENCRYPT) {
        exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                          TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE);
    } else {
        exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                          TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE);
    }

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[0].memref.size != TA_MEDIA_CRYPTO_IV_SIZE)
        return TEE_ERROR_BAD_PARAMETERS;

    free_cipher_state(ctx);

    res = load_key_store(&keys);
    if (res != TEE_SUCCESS)
        goto err;

    res = make_secret_key(&ctx->cipher_key_obj, TEE_TYPE_SM4, 128,
                  keys.enc_key, sizeof(keys.enc_key));
    if (res != TEE_SUCCESS)
        goto err;

    res = TEE_AllocateOperation(&ctx->cipher_op, TEE_ALG_SM4_CTR,
                    mode, 128);
    if (res != TEE_SUCCESS)
        goto err;

    res = TEE_SetOperationKey(ctx->cipher_op, ctx->cipher_key_obj);
    if (res != TEE_SUCCESS)
        goto err;

    if (mode == TEE_MODE_ENCRYPT) {
        TEE_GenerateRandom(iv, sizeof(iv));
        TEE_MemMove(params[0].memref.buffer, iv, sizeof(iv));
    } else {
        TEE_MemMove(iv, params[0].memref.buffer, sizeof(iv));
    }

    TEE_CipherInit(ctx->cipher_op, iv, sizeof(iv));
    ctx->cipher_active = 1;
    return TEE_SUCCESS;

err:
    free_cipher_state(ctx);
    return res;
}

static TEE_Result cipher_update(media_crypto_ctx_t *ctx,
        uint32_t param_types, TEE_Param params[4])
{
    TEE_Result res;
    size_t output_len;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                           TEE_PARAM_TYPE_MEMREF_OUTPUT,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE);

    if (!ctx || !ctx->cipher_active || ctx->cipher_op == TEE_HANDLE_NULL)
        return TEE_ERROR_BAD_STATE;

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[1].memref.size < params[0].memref.size)
        return TEE_ERROR_SHORT_BUFFER;

    output_len = params[1].memref.size;
    res = TEE_CipherUpdate(ctx->cipher_op,
                   params[0].memref.buffer, params[0].memref.size,
                   params[1].memref.buffer, &output_len);
    if (res == TEE_SUCCESS)
        params[1].memref.size = output_len;

    return res;
}

static TEE_Result cipher_finish(media_crypto_ctx_t *ctx,
        uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE);

    (void)&params;

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    free_cipher_state(ctx);
    return TEE_SUCCESS;
}

static TEE_Result hmac_init(media_crypto_ctx_t *ctx,
        uint32_t param_types, TEE_Param params[4])
{
    persisted_keys_t keys;
    TEE_Result res;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE);

    (void)&params;

    if (!ctx)
        return TEE_ERROR_BAD_STATE;

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    free_hmac_state(ctx);

    res = load_key_store(&keys);
    if (res != TEE_SUCCESS)
        goto err;

    res = make_secret_key(&ctx->hmac_key_obj, TEE_TYPE_HMAC_SM3, 512,
                  keys.hmac_key, sizeof(keys.hmac_key));
    if (res != TEE_SUCCESS)
        goto err;

    res = TEE_AllocateOperation(&ctx->hmac_op, TEE_ALG_HMAC_SM3,
                    TEE_MODE_MAC, 512);
    if (res != TEE_SUCCESS)
        goto err;

    res = TEE_SetOperationKey(ctx->hmac_op, ctx->hmac_key_obj);
    if (res != TEE_SUCCESS)
        goto err;

    TEE_MACInit(ctx->hmac_op, NULL, 0);
    ctx->hmac_active = 1;
    return TEE_SUCCESS;

err:
    free_hmac_state(ctx);
    return res;
}

static TEE_Result hmac_update(media_crypto_ctx_t *ctx,
        uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE);

    if (!ctx || !ctx->hmac_active || ctx->hmac_op == TEE_HANDLE_NULL)
        return TEE_ERROR_BAD_STATE;

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    TEE_MACUpdate(ctx->hmac_op,
              params[0].memref.buffer, params[0].memref.size);
    return TEE_SUCCESS;
}

static TEE_Result hmac_final(media_crypto_ctx_t *ctx,
        uint32_t param_types, TEE_Param params[4])
{
    TEE_Result res;
    size_t mac_len;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE);

    if (!ctx || !ctx->hmac_active || ctx->hmac_op == TEE_HANDLE_NULL)
        return TEE_ERROR_BAD_STATE;

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[0].memref.size < TA_MEDIA_CRYPTO_HMAC_SIZE)
        return TEE_ERROR_SHORT_BUFFER;

    mac_len = params[0].memref.size;
    res = TEE_MACComputeFinal(ctx->hmac_op, NULL, 0,
                  params[0].memref.buffer, &mac_len);
    if (res == TEE_SUCCESS)
        params[0].memref.size = mac_len;

    free_hmac_state(ctx);
    return res;
}

static TEE_Result hmac_finish(media_crypto_ctx_t *ctx,
        uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE);

    (void)&params;

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    free_hmac_state(ctx);
    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
            uint32_t param_types, TEE_Param params[4])
{
    media_crypto_ctx_t *ctx = (media_crypto_ctx_t *)sess_ctx;

    switch (cmd_id) {
    case TA_MEDIA_CRYPTO_CMD_INC_VALUE:
        return inc_value(param_types, params);
    case TA_MEDIA_CRYPTO_CMD_ENCRYPT_INIT:
        return cipher_init(ctx, TEE_MODE_ENCRYPT, param_types, params);
    case TA_MEDIA_CRYPTO_CMD_DECRYPT_INIT:
        return cipher_init(ctx, TEE_MODE_DECRYPT, param_types, params);
    case TA_MEDIA_CRYPTO_CMD_UPDATE:
        return cipher_update(ctx, param_types, params);
    case TA_MEDIA_CRYPTO_CMD_FINISH:
        return cipher_finish(ctx, param_types, params);
    case TA_MEDIA_CRYPTO_CMD_HMAC_INIT:
        return hmac_init(ctx, param_types, params);
    case TA_MEDIA_CRYPTO_CMD_HMAC_UPDATE:
        return hmac_update(ctx, param_types, params);
    case TA_MEDIA_CRYPTO_CMD_HMAC_FINAL:
        return hmac_final(ctx, param_types, params);
    case TA_MEDIA_CRYPTO_CMD_HMAC_FINISH:
        return hmac_finish(ctx, param_types, params);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
