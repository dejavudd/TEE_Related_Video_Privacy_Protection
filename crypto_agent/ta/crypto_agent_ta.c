// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Phytium Limited. All rights reserved.
 *
 * File Name: crypto_services_ta.c
 * Purpose: crypto services is one of the typical TAs provided by Phytium TEE.
 *
 * Contact author: email to sulianghu@phytium.com.cn
 *
 */


#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ta_crypto_agent.h"
#include <string.h>


#define TEE_ATTR_HUKKDF_SALT    0xC0000100
#define MAX_PIN_LEN             (16)

const char* MASTER_KEY_ID = "anyong_master_key";
const char* HMAC_KEY_ID = "anyong_hmac_key";
const char* PRIV_KEY_ID = "anyong_sm2_priv_key";
const char* PUB_KEY_ID = "anyong_sm2_pub_key";
const char* PIN_KEY_ID = "anyong_pin";


typedef struct sess_ctx {
	TEE_OperationHandle op;
	TEE_ObjectHandle    masterKeyObj;
	TEE_ObjectHandle    hmacKeyObj;
	TEE_ObjectHandle    sessionKeyObj;
	TEE_ObjectHandle    sm2KeyObj;
	uint8_t             pin[MAX_PIN_LEN];
} Sess_ctx_t;

static TEE_Result key_obj_initialize(TEE_ObjectHandle *key_obj, uint32_t max_key_size, TEE_ObjectType object_type, uint8_t* key, uint32_t key_len);

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param params[4] __unused,
				    void **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	*sess_ctx = TEE_Malloc(sizeof(Sess_ctx_t), TEE_MALLOC_FILL_ZERO);

	if (*sess_ctx == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	Sess_ctx_t *ctx = (Sess_ctx_t *)sess_ctx;

	if (ctx != NULL) {
		if (ctx->op != TEE_HANDLE_NULL) {
			TEE_FreeOperation(ctx->op);
			ctx->op = TEE_HANDLE_NULL;
		}

		if (ctx->masterKeyObj != TEE_HANDLE_NULL) {
			TEE_CloseObject(ctx->masterKeyObj);
			ctx->masterKeyObj = TEE_HANDLE_NULL;
		}

		if (ctx->hmacKeyObj != TEE_HANDLE_NULL) {
			TEE_CloseObject(ctx->hmacKeyObj);
			ctx->hmacKeyObj = TEE_HANDLE_NULL;
		}

		if (ctx->sessionKeyObj != TEE_HANDLE_NULL) {
			TEE_CloseObject(ctx->sessionKeyObj);
			ctx->sessionKeyObj = TEE_HANDLE_NULL;
		}
        
		if (ctx->sm2KeyObj != TEE_HANDLE_NULL) {
			TEE_CloseObject(ctx->sm2KeyObj);
			ctx->sm2KeyObj = TEE_HANDLE_NULL;
		}

		TEE_Free(ctx);
	}
}

static TEE_Result sm4_cell_encrypt_init(Sess_ctx_t *ctx,
			       uint32_t param_types,
			       TEE_Param params[4])
{
	TEE_OperationHandle  key_op = TEE_HANDLE_NULL;
	TEE_OperationHandle  session_op = TEE_HANDLE_NULL;
	TEE_Result res;
	uint8_t rand_session_key[16] = {0};
	uint8_t iv[16] = {0};
	uint8_t* rand_iv = NULL;
	void*    encypted_key_buf = NULL;
	uint32_t key_len;
	uint32_t iv_len;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	encypted_key_buf = params[0].memref.buffer;
	key_len = params[0].memref.size;

	rand_iv = params[1].memref.buffer;
	iv_len = params[1].memref.size;

    // SM4 Key size is 16 bytes
    if (key_len != 16 || iv_len != 16) {
		return TEE_ERROR_BAD_PARAMETERS;
	}
    
	// Encrypt random session key 
	res = TEE_AllocateOperation(&key_op, TEE_ALG_SM4_ECB_NOPAD, TEE_MODE_ENCRYPT, 128);
	if (res != TEE_SUCCESS)
		goto ERR;

	TEE_GenerateRandom(rand_session_key, 16);


	res = TEE_SetOperationKey(key_op, ctx->masterKeyObj);
	if (res != TEE_SUCCESS)
		goto ERR;

	TEE_CipherInit(key_op, NULL, 0);
    
    res = TEE_CipherUpdate(key_op, rand_session_key, 16, encypted_key_buf, &key_len);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}
	TEE_FreeOperation(key_op);
	key_op = TEE_HANDLE_NULL;

	res = key_obj_initialize(&ctx->sessionKeyObj, 128, TEE_TYPE_SM4, rand_session_key, 16);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}

	// Create session encryption operation
	res = TEE_AllocateOperation(&session_op, TEE_ALG_SM4_CBC_NOPAD, TEE_MODE_ENCRYPT, 128);
	if (res != TEE_SUCCESS)
		goto ERR;

	res = TEE_SetOperationKey(session_op, ctx->sessionKeyObj);
	if (res != TEE_SUCCESS)
		goto ERR;
    
	TEE_GenerateRandom(iv, 16);

	TEE_CipherInit(session_op, iv, 16);
        if (ctx->op != TEE_HANDLE_NULL) {
		TEE_FreeOperation(ctx->op);
	}
	ctx->op = session_op;
	session_op = TEE_HANDLE_NULL;
	memcpy(rand_iv, iv, 16);

	return TEE_SUCCESS;

ERR:
    if (session_op != TEE_HANDLE_NULL) {
		TEE_FreeOperation(session_op);
	}

    if (ctx->sessionKeyObj != TEE_HANDLE_NULL) {
		TEE_CloseObject(ctx->sessionKeyObj);
		ctx->sessionKeyObj = TEE_HANDLE_NULL;
	}

	if (key_op != TEE_HANDLE_NULL) {
		TEE_FreeOperation(key_op);
	}

	return res;
}


static TEE_Result sm4_cell_decrypt_init(Sess_ctx_t *ctx,
			       uint32_t param_types,
			       TEE_Param params[4])
{
	TEE_OperationHandle  key_op;
	TEE_OperationHandle  session_op;
	TEE_Result res;
	uint8_t session_key[16] = {0};
	uint32_t decrypted_key_len = 16;
	void *encypted_key_buf, *iv;
	uint32_t key_len, iv_len; 
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	encypted_key_buf = params[0].memref.buffer;
	key_len = params[0].memref.size;

	iv = params[1].memref.buffer;
	iv_len = params[1].memref.size;

    // SM4 Key size is 16 bytes
    if (key_len != 16 || iv_len != 16) {
		return TEE_ERROR_BAD_PARAMETERS;
	}
    
	// Encrypt random session key 
	res = TEE_AllocateOperation(&key_op, TEE_ALG_SM4_ECB_NOPAD, TEE_MODE_DECRYPT, 128);
	if (res != TEE_SUCCESS)
		goto ERR;

	res = TEE_SetOperationKey(key_op, ctx->masterKeyObj);
	if (res != TEE_SUCCESS)
		goto ERR;

	TEE_CipherInit(key_op, NULL, 0);
    
    res = TEE_CipherUpdate(key_op, encypted_key_buf, key_len, session_key, &decrypted_key_len);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}
	TEE_FreeOperation(key_op);
	key_op = TEE_HANDLE_NULL;

	res = key_obj_initialize(&ctx->sessionKeyObj, 128, TEE_TYPE_SM4, session_key, 16);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}
    
	// Create session encryption operation
	res = TEE_AllocateOperation(&session_op, TEE_ALG_SM4_CBC_NOPAD, TEE_MODE_DECRYPT, 128);
	if (res != TEE_SUCCESS)
		goto ERR;

	res = TEE_SetOperationKey(session_op, ctx->sessionKeyObj);
	if (res != TEE_SUCCESS)
		goto ERR;

	TEE_CipherInit(session_op, iv, 16);
    if (ctx->op != TEE_HANDLE_NULL) {
		TEE_FreeOperation(ctx->op);
	}
	ctx->op = session_op;
	session_op = TEE_HANDLE_NULL;

	return TEE_SUCCESS;

ERR:
    if (session_op != TEE_HANDLE_NULL) {
		TEE_FreeOperation(session_op);
	}

    if (ctx->sessionKeyObj != TEE_HANDLE_NULL) {
		TEE_CloseObject(ctx->sessionKeyObj);
		ctx->sessionKeyObj = TEE_HANDLE_NULL;
	}

	if (key_op != TEE_HANDLE_NULL) {
		TEE_FreeOperation(key_op);
	}

	return res;
}

static TEE_Result sm4_cell_do_chiper(Sess_ctx_t *ctx,
				uint32_t param_types,
				TEE_Param params[4])
{
	void *src_data, *dest_data;
	uint32_t src_len, dest_len;
	TEE_OperationHandle op = ctx->op;
	TEE_Result res;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	if (op == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	src_data = params[0].memref.buffer;
	src_len = params[0].memref.size;
	dest_data = params[1].memref.buffer;
	dest_len = params[1].memref.size;

	if (dest_len < src_len)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_CipherUpdate(op, src_data, src_len, dest_data, &dest_len);

	return res;
}

static TEE_Result sm4_cell_chiper_finish(Sess_ctx_t *ctx,
				uint32_t param_types,
				TEE_Param params[4])
{
	if (ctx->sessionKeyObj != TEE_HANDLE_NULL) {
		TEE_CloseObject(ctx->sessionKeyObj);
		ctx->sessionKeyObj = TEE_HANDLE_NULL;
	}

    if (ctx->op != TEE_HANDLE_NULL) {
		TEE_FreeOperation(ctx->op);
		ctx->op = TEE_HANDLE_NULL;
	}

	return TEE_SUCCESS;
}

static TEE_Result sm3_digest_init(Sess_ctx_t *ctx,
				  uint32_t param_types,
				  TEE_Param params[4] __unused)
{
	TEE_OperationHandle op;
	TEE_Result res;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_AllocateOperation(&op, TEE_ALG_SM3, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		return res;

	if (ctx->op != NULL)
		TEE_FreeOperation(ctx->op);

	ctx->op = op;

	return TEE_SUCCESS;
}

static TEE_Result sm3_digest_update(Sess_ctx_t *ctx,
				    uint32_t param_types,
				    TEE_Param params[4])
{
	void *srcData = 0;
	uint32_t srcLen = 0;
	TEE_OperationHandle op = ctx->op;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	if (op == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	srcData = params[0].memref.buffer;
	srcLen = params[0].memref.size;

	TEE_DigestUpdate(op, srcData, srcLen);

	return TEE_SUCCESS;
}

static TEE_Result sm3_digest_final(Sess_ctx_t *ctx,
				   uint32_t param_types,
				   TEE_Param params[4])
{
	void *digest_buf;
	uint32_t digest_len;
	TEE_Result res;
	TEE_OperationHandle op = ctx->op;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	if (op == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	digest_buf = params[0].memref.buffer;
	digest_len = params[0].memref.size;

	if (digest_len < 32)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_DigestDoFinal(op, NULL, 0, digest_buf, &digest_len);

	return res;
}

static TEE_Result sm3_hmac_init(Sess_ctx_t *ctx,
				uint32_t param_types,
				TEE_Param params[4] __unused)
{
	TEE_OperationHandle op;
	TEE_Result res;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	if (ctx->hmacKeyObj == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SM3, TEE_MODE_MAC, 1024);
	if (res != TEE_SUCCESS)
		goto ERR;

	res = TEE_SetOperationKey(op, ctx->hmacKeyObj);
	if (res != TEE_SUCCESS)
		goto ERR;

	TEE_MACInit(op, NULL, 0);

	if (ctx->op != NULL)
		TEE_FreeOperation(ctx->op);

	ctx->op = op;
	return TEE_SUCCESS;

ERR:
    if (op != TEE_HANDLE_NULL) {
	    TEE_FreeOperation(op);
	    ctx->op = TEE_HANDLE_NULL;
	}

	return res;
}

static TEE_Result sm3_hmac_update(Sess_ctx_t *ctx,
				  uint32_t param_types,
				  TEE_Param params[4])
{
	void *src_data;
	uint32_t src_len;
	TEE_OperationHandle op = ctx->op;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	if (op == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	src_data = params[0].memref.buffer;
	src_len = params[0].memref.size;

	TEE_MACUpdate(op, src_data, src_len);

	return TEE_SUCCESS;
}

static TEE_Result sm3_hmac_final(Sess_ctx_t *ctx,
				 uint32_t param_types,
				 TEE_Param params[4])
{
	void *mac_buf;
	uint32_t mac_len;
	TEE_Result res;
	TEE_OperationHandle op = ctx->op;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	if (op == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	mac_buf = params[0].memref.buffer;
	mac_len = params[0].memref.size;

	if (mac_len < 32)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_MACComputeFinal(op, NULL, 0, mac_buf, &mac_len);

	TEE_FreeOperation(op);
	ctx->op = TEE_HANDLE_NULL;

	return res;
}

TEE_Result key_obj_initialize(TEE_ObjectHandle *key_obj, uint32_t max_key_size, TEE_ObjectType object_type, uint8_t* key, uint32_t key_len) 
{
	TEE_Result res;
	TEE_Attribute *attrs = NULL;
	uint32_t attrslen;

	if (*key_obj != NULL) {
		TEE_CloseObject(*key_obj);
		*key_obj = TEE_HANDLE_NULL;
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = TEE_AllocateTransientObject(object_type, max_key_size, key_obj);
	if (res != TEE_SUCCESS)
		goto free_key;

	attrslen = 1;
	attrs = TEE_Malloc(attrslen * sizeof(*attrs), 0);
	if (!attrs) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		TEE_CloseObject(*key_obj);
		*key_obj = TEE_HANDLE_NULL;
		goto free_key;
	}

	attrs[0].attributeID = TEE_ATTR_SECRET_VALUE;
	attrs[0].content.ref.buffer = (void *)key;
	attrs[0].content.ref.length = key_len;

	res = TEE_PopulateTransientObject(*key_obj, attrs, attrslen);
	if (res != TEE_SUCCESS) {
		TEE_Free(attrs);
		TEE_CloseObject(*key_obj);
		*key_obj = TEE_HANDLE_NULL;
		goto free_key;
	}

	TEE_Free(attrs);
	return TEE_SUCCESS;
free_key:
    if (attrs != NULL) {
		TEE_Free(attrs);
	}

	return res;
}

static TEE_Result ecc_key_obj_initialize(TEE_ObjectHandle *key_obj, uint8_t* priv_key, uint8_t* pub_key) 
{
	TEE_Result res;
	TEE_Attribute *attrs = NULL;
	uint32_t attrslen = 3;

	if (*key_obj != NULL) {
		TEE_CloseObject(*key_obj);
		*key_obj = TEE_HANDLE_NULL;
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_SM2_PKE_KEYPAIR, 256, key_obj);
	if (res != TEE_SUCCESS)
		goto free_key;

	attrs = TEE_Malloc(attrslen * sizeof(*attrs), 0);
	if (!attrs) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		TEE_CloseObject(*key_obj);
		*key_obj = TEE_HANDLE_NULL;
		goto free_key;
	}

	attrs[0].attributeID = TEE_ATTR_ECC_PRIVATE_VALUE;
	attrs[0].content.ref.buffer = (void *)priv_key;
	attrs[0].content.ref.length = 32;

	attrs[1].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_X;
	attrs[1].content.ref.buffer = (void *)pub_key;
	attrs[1].content.ref.length = 32;

	attrs[2].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_Y;
	attrs[2].content.ref.buffer = (void *)(pub_key + 32);
	attrs[2].content.ref.length = 32;

	res = TEE_PopulateTransientObject(*key_obj, attrs, attrslen);
	if (res != TEE_SUCCESS) {
		TEE_Free(attrs);
		TEE_CloseObject(*key_obj);
		*key_obj = TEE_HANDLE_NULL;
		goto free_key;
	}

	TEE_Free(attrs);
	return TEE_SUCCESS;
free_key:
    if (attrs != NULL) {
		TEE_Free(attrs);
	}
	return res;
}

static TEE_Result ecc_pub_key_obj_initialize(TEE_ObjectHandle *key_obj, uint8_t* pub_key) 
{
	TEE_Result res;
	TEE_Attribute *attrs = NULL;
	uint32_t attrslen = 2;

	res = TEE_AllocateTransientObject(TEE_TYPE_SM2_PKE_PUBLIC_KEY, 256, key_obj);
	if (res != TEE_SUCCESS)
		goto free_key;

	attrs = TEE_Malloc(attrslen * sizeof(*attrs), 0);
	if (!attrs) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		TEE_CloseObject(*key_obj);
		*key_obj = TEE_HANDLE_NULL;
		goto free_key;
	}

	attrs[0].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_X;
	attrs[0].content.ref.buffer = (void *)pub_key;
	attrs[0].content.ref.length = 32;

	attrs[1].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_Y;
	attrs[1].content.ref.buffer = (void *)(pub_key + 32);
	attrs[1].content.ref.length = 32;

	res = TEE_PopulateTransientObject(*key_obj, attrs, attrslen);
	if (res != TEE_SUCCESS) {
		TEE_Free(attrs);
		TEE_CloseObject(*key_obj);
		*key_obj = TEE_HANDLE_NULL;
		goto free_key;
	}

	TEE_Free(attrs);
	return TEE_SUCCESS;
free_key:
    if (attrs != NULL) {
		TEE_Free(attrs);
	}
	return res;
}


static TEE_Result encrypt_master_key(uint8_t* key, const key_data_t* key_data, encrypted_key_data_t* encrypted_key) {
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	uint32_t   encrypted_len = sizeof(key_data_t);
    
	res = key_obj_initialize(&key_handle, 128, TEE_TYPE_SM4, key, 16);

	if (res != TEE_SUCCESS) {
		goto ERR;
	}
    
    res = TEE_AllocateOperation(&op, TEE_ALG_SM4_CBC_NOPAD, TEE_MODE_ENCRYPT, 128);
	if (res != TEE_SUCCESS)
		goto ERR;

	TEE_GenerateRandom(encrypted_key->iv, 16);
	res = TEE_SetOperationKey(op, key_handle);
	if (res != TEE_SUCCESS)
		goto ERR;

	TEE_CipherInit(op, encrypted_key->iv, 16);
    
    res = TEE_CipherUpdate(op, key_data, sizeof(key_data_t), &encrypted_key->key_data, &encrypted_len);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}
	TEE_FreeOperation(op);
    TEE_CloseObject(key_handle);

	encrypted_key->version[0] = 1;

	return TEE_SUCCESS;

ERR:
    if (key_handle != TEE_HANDLE_NULL) {
		TEE_CloseObject(key_handle);
	}
    return res;
}

static TEE_Result decrypt_master_key(uint8_t* key, const encrypted_key_data_t* encrypted_key, key_data_t* key_data) {
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint32_t  key_len = sizeof(key_data_t);

	res = key_obj_initialize(&key_handle, 128, TEE_TYPE_SM4, key, 16);

	if (res != TEE_SUCCESS) {
		goto ERR;
	}
    
    res = TEE_AllocateOperation(&op, TEE_ALG_SM4_CBC_NOPAD, TEE_MODE_DECRYPT, 128);
	if (res != TEE_SUCCESS)
		goto ERR;

	res = TEE_SetOperationKey(op, key_handle);
	if (res != TEE_SUCCESS)
		goto ERR;

	TEE_CipherInit(op, encrypted_key->iv, 16);
    
    res = TEE_CipherUpdate(op, &encrypted_key->key_data, sizeof(key_data_t), key_data, &key_len);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}
	TEE_FreeOperation(op);
    TEE_CloseObject(key_handle);

	return TEE_SUCCESS;

ERR:
    if (key_handle != TEE_HANDLE_NULL) {
		TEE_CloseObject(key_handle);
	}
    return res;
}

static TEE_Result debug_seal_master_key(TEE_ObjectHandle sm2_enc_key, uint32_t key_len, uint8_t* encrypted_key) {
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	uint8_t nonce[16] = {0};
	uint32_t nonce_len = 16;
	TEE_Result res;
    
	res = TEE_AllocateOperation(&op, TEE_ALG_SM2_PKE, TEE_MODE_DECRYPT, 256);
	if (res != TEE_SUCCESS)
		goto ERR;
    
	res = TEE_SetOperationKey(op, sm2_enc_key);
	if (res != TEE_SUCCESS)
		goto ERR;
    
	res = TEE_AsymmetricDecrypt(op, NULL, 0, encrypted_key, key_len, nonce, &nonce_len);
    if (res != TEE_SUCCESS)
		goto ERR;
    
	TEE_FreeOperation(op);
ERR:
    if (op != TEE_HANDLE_NULL) {
		TEE_FreeOperation(op);
	}
    return res;
}

static TEE_Result seal_master_key(uint8_t* pub_key, const key_data_t* key_data, key_data_seal_box_t* key_seal_box) {
	TEE_Result res;
    TEE_ObjectHandle pub_key_handle = TEE_HANDLE_NULL;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	uint8_t nonce[16] = {0};
	
	res = ecc_pub_key_obj_initialize(&pub_key_handle, pub_key);
    if (res != TEE_SUCCESS) {
		goto ERR;
	}
    
	TEE_GenerateRandom(nonce, 16);
    
	res = TEE_AllocateOperation(&op, TEE_ALG_SM2_PKE, TEE_MODE_ENCRYPT, 256);
	if (res != TEE_SUCCESS)
		goto ERR;

	res = TEE_SetOperationKey(op, pub_key_handle);
	if (res != TEE_SUCCESS)
		goto ERR;

 	res = TEE_AsymmetricEncrypt(op, NULL, 0, nonce, 16, key_seal_box->seal_key, &key_seal_box->seal_key_len);
    if (res != TEE_SUCCESS)
		goto ERR;
    
	TEE_FreeOperation(op);
	TEE_CloseObject(pub_key_handle);
    op = TEE_HANDLE_NULL;
	pub_key_handle = TEE_HANDLE_NULL;

	res = encrypt_master_key(nonce, key_data, &key_seal_box->encrypted_key);
    if (res != TEE_SUCCESS)
		goto ERR;
    
	return TEE_SUCCESS;
ERR:
    if (op != TEE_HANDLE_NULL) {
		TEE_FreeOperation(op);
	}
   
    if (pub_key_handle != TEE_HANDLE_NULL) {
		TEE_CloseObject(pub_key_handle);
	}

    return res;
}

static TEE_Result unseal_master_key(TEE_ObjectHandle sm2_enc_key, const key_data_seal_box_t* key_seal_box, key_data_t* key_data, int* debug) {
    TEE_OperationHandle op = TEE_HANDLE_NULL;
	uint8_t nonce[16] = {0};
	uint32_t nonce_len = 16;
	TEE_Result res;
    
	*debug = 20;
	res = TEE_AllocateOperation(&op, TEE_ALG_SM2_PKE, TEE_MODE_DECRYPT, 256);
	if (res != TEE_SUCCESS)
		goto ERR;
    
	*debug = 21;
	res = TEE_SetOperationKey(op, sm2_enc_key);
	if (res != TEE_SUCCESS)
		goto ERR;
    
	*debug = 22;
 	res = TEE_AsymmetricDecrypt(op, NULL, 0, key_seal_box->seal_key, key_seal_box->seal_key_len, nonce, &nonce_len);
    if (res != TEE_SUCCESS)
		goto ERR;
    
	TEE_FreeOperation(op);
	op = TEE_HANDLE_NULL;

	*debug = 23;
	res = decrypt_master_key(nonce, &key_seal_box->encrypted_key, key_data);
	if (res != TEE_SUCCESS)
		goto ERR;
    
	*debug = 24;
	return TEE_SUCCESS;
ERR:
    if (op != TEE_HANDLE_NULL) {
		TEE_FreeOperation(op);
	}
    return res;
}

static TEE_Result save_master_key(const char* object_id, uint8_t* data, uint32_t data_len) 
{
	TEE_Result res;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_SHARE_READ |
			TEE_DATA_FLAG_SHARE_WRITE |
			TEE_DATA_FLAG_OVERWRITE;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE_REE, object_id, strlen(object_id),
	    flags, TEE_HANDLE_NULL, data, data_len, &obj);
	
	if (res != TEE_SUCCESS) {
		return res;
	}

	TEE_CloseObject(obj);

	return TEE_SUCCESS;
}

static TEE_Result load_master_key(const char* object_id, uint8_t* data, uint32_t data_len)
{
	TEE_Result res;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ;
	uint32_t  read_len = 0;
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE_REE, object_id, strlen(object_id), flags, &obj);
	if (res != TEE_SUCCESS){
		return res;
	}

	res = TEE_ReadObjectData(obj, data, data_len, &read_len);
	if (res != TEE_SUCCESS) {
		TEE_CloseObject(obj);
		return res;
	}
	TEE_CloseObject(obj);
    
	if (read_len != data_len) {
		return TEE_ERROR_CORRUPT_OBJECT;
	}

    return TEE_SUCCESS;
}

static TEE_Result master_key_init(Sess_ctx_t* ctx,  uint32_t param_types, TEE_Param params[4]) 
{
	uint8_t rand_master_key[16] = {0};
	uint8_t rand_hmac_key[64] = {0};
	uint8_t sm2_priv_key[32] = {0};
	uint8_t sm2_pub_key[64] = {0};
	uint32_t key_size = 0;
	TEE_ObjectHandle sm2_key_handle;
	TEE_Result res = TEE_SUCCESS;
	int        step = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].memref.size > MAX_PIN_LEN || params[1].memref.size != 64) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

    memcpy(ctx->pin, params[0].memref.buffer, params[0].memref.size);
	TEE_GenerateRandom(rand_master_key, 16);
	TEE_GenerateRandom(rand_hmac_key, 64);

    res = TEE_AllocateTransientObject(TEE_TYPE_SM2_PKE_KEYPAIR, 256, &sm2_key_handle);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}
    
	res = TEE_GenerateKey(sm2_key_handle, 256, NULL, 0);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}

	res = key_obj_initialize(&ctx->masterKeyObj, 128, TEE_TYPE_SM4, rand_master_key, 16);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}
    
	res = key_obj_initialize(&ctx->hmacKeyObj, 512, TEE_TYPE_HMAC_SM3, rand_hmac_key, 64);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}

	res = save_master_key(MASTER_KEY_ID, rand_master_key, 16);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}

	res = save_master_key(HMAC_KEY_ID, rand_hmac_key, 64);
    if (res != TEE_SUCCESS) {
		goto ERR;
	}

    key_size = 32;
	res = TEE_GetObjectBufferAttribute(sm2_key_handle,
		TEE_ATTR_ECC_PRIVATE_VALUE, sm2_priv_key,
		&key_size);
    if (res != TEE_SUCCESS) {
		goto ERR;
	}
    res = save_master_key(PRIV_KEY_ID, sm2_priv_key, 32);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}

	key_size = 32;
	res = TEE_GetObjectBufferAttribute(sm2_key_handle,
		TEE_ATTR_ECC_PUBLIC_VALUE_X, sm2_pub_key,
		&key_size);
    if (res != TEE_SUCCESS) {
		goto ERR;
	}
    
	key_size = 32;
	res = TEE_GetObjectBufferAttribute(sm2_key_handle,
		TEE_ATTR_ECC_PUBLIC_VALUE_Y, sm2_pub_key + 32,
		&key_size);
    if (res != TEE_SUCCESS) {
		goto ERR;
	}

    res = save_master_key(PUB_KEY_ID, sm2_pub_key, 64);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}
    
	res = save_master_key(PIN_KEY_ID, ctx->pin, MAX_PIN_LEN);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}
    
	memcpy(params[1].memref.buffer, sm2_pub_key, 64);

	ctx->sm2KeyObj = sm2_key_handle;
	DMSG("Init master key success!\n");

	return TEE_SUCCESS;
ERR:
    if (sm2_key_handle != TEE_HANDLE_NULL) {
		TEE_CloseObject(sm2_key_handle);
	}
    return res;
}

static TEE_Result master_key_load(Sess_ctx_t* ctx, uint32_t param_types, TEE_Param params[4])
{
	uint8_t rand_master_key[16] = {0};
	uint8_t rand_hmac_key[64] = {0};
	uint8_t sm2_priv_key[32] = {0};
	uint8_t sm2_pub_key[64] = {0};
	TEE_Result res = TEE_SUCCESS;
	//void* master_key_buf = NULL;
	//void* hmac_key_buf = NULL;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].memref.size != 64) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	//master_key_buf = params[0].memref.buffer;
	//hmac_key_buf = params[1].memref.buffer;

	res = load_master_key(MASTER_KEY_ID, rand_master_key, 16);
	if (res != TEE_SUCCESS) {
		return res;
	}

	res = load_master_key(HMAC_KEY_ID, rand_hmac_key, 64);
	if (res != TEE_SUCCESS) {
		return res;
	}

	res = load_master_key(PRIV_KEY_ID, sm2_priv_key, 32);
	if (res != TEE_SUCCESS) {
		return res;
	}

	res = load_master_key(PUB_KEY_ID, sm2_pub_key, 64);
	if (res != TEE_SUCCESS) {
		return res;
	}

	res = load_master_key(PIN_KEY_ID, ctx->pin, 16);
	if (res != TEE_SUCCESS) {
		return res;
	}
     
	res = key_obj_initialize(&ctx->masterKeyObj, 128, TEE_TYPE_SM4, rand_master_key, 16);
	if (res != TEE_SUCCESS) {
		return res;
	}
    
	res = key_obj_initialize(&ctx->hmacKeyObj, 512, TEE_TYPE_HMAC_SM3, rand_hmac_key, 64);
	if (res != TEE_SUCCESS) {
		return res;
	}
    
	res = ecc_key_obj_initialize(&ctx->sm2KeyObj, sm2_priv_key, sm2_pub_key);
    if (res != TEE_SUCCESS) {
		return res;
	}

	memcpy(params[0].memref.buffer, sm2_pub_key, 64);
	
	return TEE_SUCCESS;
}

static TEE_Result export_key_encrypt_symmetric(Sess_ctx_t* ctx,  uint32_t param_types, TEE_Param params[4]) 
{
	key_data_t key_data;
	uint8_t pin[16] = {0};
	TEE_Result res = TEE_SUCCESS;
	encrypted_key_data_t encrypted_key; 
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
    
	if (params[0].memref.size > 16 || 
	    params[1].memref.size != 16 ||
		params[2].memref.size != sizeof(encrypted_key_data_t)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memcpy(pin, params[0].memref.buffer, params[0].memref.size);
    
	if (memcmp(pin, ctx->pin, 16) != 0) {
		return TEE_ERROR_ACCESS_DENIED;
	}
    res = load_master_key(MASTER_KEY_ID, key_data.sm4_key, 16);
	if (res != TEE_SUCCESS) {
		return res;
	}

	res = load_master_key(HMAC_KEY_ID, key_data.hmac_key, 64);
	if (res != TEE_SUCCESS) {
		return res;
	}
	
    res = encrypt_master_key(params[1].memref.buffer, &key_data, &encrypted_key);
	if (res != TEE_SUCCESS) {
		return res;
	}

	memcpy(params[2].memref.buffer, &encrypted_key, params[2].memref.size);
	return TEE_SUCCESS;
}

static TEE_Result import_key_encrypt_symmetric(Sess_ctx_t* ctx,  uint32_t param_types, TEE_Param params[4]) 
{
	key_data_t key_data;
	uint8_t pin[16] = {0};
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle new_master_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle new_hmac_handle = TEE_HANDLE_NULL;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT);
    
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	
	if (params[0].memref.size > 16 || 
	    params[1].memref.size != 16 ||
		params[2].memref.size != sizeof(encrypted_key_data_t)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memcpy(pin, params[0].memref.buffer, params[0].memref.size);
    
	if (memcmp(pin, ctx->pin, 16) != 0) {
		return TEE_ERROR_ACCESS_DENIED;
	}
	encrypted_key_data_t* encrypted_key = (encrypted_key_data_t*)params[2].memref.buffer;

    res = decrypt_master_key(params[1].memref.buffer, encrypted_key, &key_data);
    if (res != TEE_SUCCESS) {
		return res;
	}

	res = key_obj_initialize(&new_master_handle, 128, TEE_TYPE_SM4, key_data.sm4_key, 16);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}
    
	res = key_obj_initialize(&new_hmac_handle, 512, TEE_TYPE_HMAC_SM3, key_data.hmac_key, 64);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}

	res = save_master_key(MASTER_KEY_ID, key_data.sm4_key, 16);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}

	res = save_master_key(HMAC_KEY_ID, key_data.hmac_key, 64);
    if (res != TEE_SUCCESS) {
		goto ERR;
	}

	TEE_CloseObject(ctx->masterKeyObj);
	TEE_CloseObject(ctx->hmacKeyObj);
	ctx->masterKeyObj = new_master_handle;
	ctx->hmacKeyObj = new_hmac_handle;

    return TEE_SUCCESS;
ERR:
    if (new_master_handle != NULL) {
		TEE_CloseObject(new_master_handle);
	}

    if (new_hmac_handle != NULL) {
		TEE_CloseObject(new_hmac_handle);
	}

    return res;
}

static TEE_Result export_key_encrypt_asymmetric(Sess_ctx_t* ctx,  uint32_t param_types, TEE_Param params[4]) 
{
	key_data_t key_data;
	uint8_t pin[16] = {0};
	TEE_Result res = TEE_SUCCESS;
	key_data_seal_box_t key_box;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
    
	if (params[0].memref.size > 16 || 
	    params[1].memref.size != 64 ||
		params[2].memref.size != sizeof(key_data_seal_box_t)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memcpy(pin, params[0].memref.buffer, params[0].memref.size);
    
	if (memcmp(pin, ctx->pin, 16) != 0) {
		return TEE_ERROR_ACCESS_DENIED;
	}
    res = load_master_key(MASTER_KEY_ID, key_data.sm4_key, 16);
	if (res != TEE_SUCCESS) {
		return res;
	}
	res = load_master_key(HMAC_KEY_ID, key_data.hmac_key, 64);
	if (res != TEE_SUCCESS) {
		return res;
	}
	
	key_box.seal_key_len = sizeof(key_box.seal_key);
    res = seal_master_key(params[1].memref.buffer, &key_data, &key_box);
	if (res != TEE_SUCCESS) {
		return res;
	}
    
	res = debug_seal_master_key(ctx->sm2KeyObj, key_box.seal_key_len, key_box.seal_key);
	if (res != TEE_SUCCESS) {
		return res;
	}

	memcpy(params[2].memref.buffer, &key_box, params[2].memref.size);
	return TEE_SUCCESS;
}

static TEE_Result import_key_encrypt_asymmetric(Sess_ctx_t* ctx,  uint32_t param_types, TEE_Param params[4]) 
{
	key_data_t key_data;
	uint8_t pin[16] = {0};
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle new_master_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle new_hmac_handle = TEE_HANDLE_NULL;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_VALUE_OUTPUT);

	params[3].value.a = 0;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
    
	params[3].value.a++;
	if (params[0].memref.size > 16 || 
		params[1].memref.size != sizeof(key_data_seal_box_t)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}
    params[3].value.a++;
	memcpy(pin, params[0].memref.buffer, params[0].memref.size);
    
	if (memcmp(pin, ctx->pin, 16) != 0) {
		return TEE_ERROR_ACCESS_DENIED;
	}
	key_data_seal_box_t* encrypted_key = (key_data_seal_box_t*)params[1].memref.buffer;
    params[3].value.a++;
    res = unseal_master_key(ctx->sm2KeyObj, encrypted_key, &key_data, &params[3].value.a);
    if (res != TEE_SUCCESS) {
		goto ERR;
	}
    params[3].value.a++;
	res = key_obj_initialize(&new_master_handle, 128, TEE_TYPE_SM4, key_data.sm4_key, 16);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}
    params[3].value.a++;
	res = key_obj_initialize(&new_hmac_handle, 512, TEE_TYPE_HMAC_SM3, key_data.hmac_key, 64);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}
    params[3].value.a++;
	res = save_master_key(MASTER_KEY_ID, key_data.sm4_key, 16);
	if (res != TEE_SUCCESS) {
		goto ERR;
	}
    params[3].value.a++;
	res = save_master_key(HMAC_KEY_ID, key_data.hmac_key, 64);
    if (res != TEE_SUCCESS) {
		goto ERR;
	}
    params[3].value.a++;
	TEE_CloseObject(ctx->masterKeyObj);
	TEE_CloseObject(ctx->hmacKeyObj);
	ctx->masterKeyObj = new_master_handle;
	ctx->hmacKeyObj = new_hmac_handle;

    return TEE_SUCCESS;
ERR:
    if (new_master_handle != NULL) {
		TEE_CloseObject(new_master_handle);
	}

    if (new_hmac_handle != NULL) {
		TEE_CloseObject(new_hmac_handle);
	}

    return res;
}

static TEE_Result export_debug_master_key(Sess_ctx_t* ctx,  uint32_t param_types, TEE_Param params[4]) 
{
	key_data_t key_data;
	uint8_t pin[16] = {0};
	TEE_Result res = TEE_SUCCESS;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
    
	if (params[0].memref.size > 16 || 
		params[1].memref.size != sizeof(key_data_t)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memcpy(pin, params[0].memref.buffer, params[0].memref.size);
    
	if (memcmp(pin, ctx->pin, 16) != 0) {
		return TEE_ERROR_ACCESS_DENIED;
	}
     
	res = load_master_key(MASTER_KEY_ID, key_data.sm4_key, 16);
	if (res != TEE_SUCCESS) {
		return res;
	}
	res = load_master_key(HMAC_KEY_ID, key_data.hmac_key, 64);
	if (res != TEE_SUCCESS) {
		return res;
	}
	
	memcpy(params[1].memref.buffer, &key_data, params[1].memref.size);

    return TEE_SUCCESS;
}


/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
				      uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	Sess_ctx_t *ctx = (Sess_ctx_t *)sess_ctx;

	switch (cmd_id) {
	case SM4_CELL_ENCRYPT_INIT:
		return sm4_cell_encrypt_init(ctx, param_types, params);
	case SM4_CELL_DECRYPT_INIT:
	    return sm4_cell_decrypt_init(ctx, param_types, params);
	case SM4_CELL_DO_CIPHER:
		return sm4_cell_do_chiper(ctx, param_types, params);
	case SM4_CELL_CIPHER_FINISH:
	    return sm4_cell_chiper_finish(ctx, param_types, params);
	case SM3_INIT:
		return sm3_digest_init(ctx, param_types, params);
	case SM3_UPDATE:
		return sm3_digest_update(ctx, param_types, params);
	case SM3_FINAL:
		return sm3_digest_final(ctx, param_types, params);
	case SM3_HMAC_INIT:
		return sm3_hmac_init(ctx, param_types, params);
	case SM3_HMAC_UPDATE:
		return sm3_hmac_update(ctx, param_types, params);
	case SM3_HMAC_FINAL:
		return sm3_hmac_final(ctx, param_types, params);
	case MASTER_KEY_LOAD:
	    return master_key_load(ctx, param_types, params);
	case MASTER_KEY_INIT:
	    return master_key_init(ctx, param_types, params);
	case EXPORT_KEY_ENCRYPT_SYMMETRIC:
	    return export_key_encrypt_symmetric(ctx, param_types, params);
	case IMPORT_KEY_ENCRYPT_SYMMETRIC:
	    return import_key_encrypt_symmetric(ctx, param_types, params);
	case EXPORT_KEY_ENCRYPT_ASYMMETRIC:
	    return export_key_encrypt_asymmetric(ctx, param_types, params);
	case IMPORT_KEY_ENCRYPT_ASYMMETRIC:
	    return import_key_encrypt_asymmetric(ctx, param_types, params);

	case MASTER_KEY_DEBUG:
	    return export_debug_master_key(ctx, param_types, params);
	    
	default:
		return TEE_SUCCESS;
	}

	return TEE_SUCCESS;
}
