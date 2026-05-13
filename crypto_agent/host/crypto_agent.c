#include <stdio.h>
#include "string.h"
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <err.h>
#include "crypto_agent_phytium.h"
#include <tee_client_api.h>
#include <teec_trace.h>
#include "ta_crypto_agent.h"

#define  MAX_URL_LEN           (256)
#define  MAX_TOKEN_LEN         (128)
#define  SYMMETRIC_KEY_SIZE    (32)
#define  SM4_KEY_SIZE          (16)
#define  SM4_KEY_BITS          (128)
#define  MAX_SM4_BLOCK_SIZE    (2048)
#define  HASH_SIZE             (32)
#define  PUBLIC_KEY_LEN        (45)

#define  SYMMETRIC_ENC_SIZE_ADD   (44)

#define POLICY_UNIQUE 1
#define POLICY_PRODUCT 2

/* encrypted randomkey(32 + 44) + key hash (32byte) + data add size (44) */
#define  BLOCK_HEADER_SIZE           (44)

#define SM4_PADDING(x)           (((x + 15) >> 4) << 4)

#define MAJOR_VERSION            (0)
#define MIDDLE_VERSION           (0)
#define MINOR_VERSION            (1)
#define PLATFORM_PHYTIUM         (1)

#define VERSION_MAGIC            ((MAJOR_VERSION << 24) | (MIDDLE_VERSION << 16) | (MINOR_VERSION << 8) | PLATFORM_PHYTIUM)

typedef struct crypto_session_tag {
    TEEC_Session       session_handle;
}crypto_session_t;

typedef struct crypto_agent_tag {
    TEEC_Context       tee_context;
    int                max_count;
    crypto_session_t*  sessions;
}crypto_agent_t;

typedef struct crypto_cell_tag {
    unsigned int      version;   // byte 0  major version  byte 1 middle version byte 2 minor version  byte 3 platform
    unsigned char     encrypted_key[SM4_KEY_SIZE];
    unsigned char     iv[SM4_KEY_SIZE];
    unsigned int      raw_len;
    unsigned int      encrypted_len;
    unsigned char     encrypted[0];
}crypto_cell_t;

static crypto_agent_t* agent_t;

void sigsegv_handler(int signum){
    // fprintf(stdout, "SIGSEGV error\n");
    if(agent_t->sessions != NULL){
        for(int i = 0; i < agent_t->max_count; i++){
            crypto_session_t* session = &agent_t->sessions[i];
            TEEC_CloseSession(&session->session_handle);
        }
        free(agent_t->sessions);
    }
    
    TEEC_FinalizeContext(&agent_t->tee_context);
    if(agent_t != NULL)
    {
	    free(agent_t);
    }
    exit(1);
}

crypto_agent crypto_agent_create(int max_count) {
    TEEC_UUID uuid = TA_CRYPTO_AGENT_UUID;
    uint32_t err_origin;
    TEEC_Result res;
    crypto_agent_t* agent = (crypto_agent_t*)malloc(sizeof(crypto_agent_t));
    if (agent == NULL) {
        return NULL;
    }

    memset(agent, 0, sizeof(crypto_agent_t));
    res = TEEC_InitializeContext(NULL, &agent->tee_context);
    if (TEEC_SUCCESS != res) {
        goto ERR;
    }
    
    agent->max_count = max_count;
    agent->sessions = (crypto_session_t*)malloc(sizeof(crypto_session_t) * max_count);
    memset(agent->sessions, 0, sizeof(crypto_session_t) * max_count);
    agent_t=agent;
    for (int i = 0; i < max_count; i++) {
        crypto_session_t* session = &agent->sessions[i];
        TEEC_Operation op;
        uint8_t        pubkey[64] = {0};
    
        res = TEEC_OpenSession(&agent->tee_context, &session->session_handle, &uuid,
                   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

	    if (TEEC_SUCCESS != res) {
            goto ERR;
        }
        
        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
                     TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = pubkey;
        op.params[0].tmpref.size = 64;
        res = TEEC_InvokeCommand(&session->session_handle, MASTER_KEY_LOAD, &op, &err_origin);
        if (res != TEEC_SUCCESS) {
            errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
                res, err_origin);
            goto ERR;
        }

        fprintf(stdout,"create session %p\n",&agent->sessions[i]);
    }

    signal(SIGSEGV, sigsegv_handler);

    return agent;

ERR:
    if(agent_t->sessions != NULL){
        for(int i = 0; i < agent_t->max_count; i++){
            crypto_session_t* session = &agent_t->sessions[i];
            TEEC_CloseSession(&session->session_handle);
        }
        free(agent_t->sessions);
    }
    
    TEEC_FinalizeContext(&agent_t->tee_context);
    if(agent_t != NULL)
    {
	    free(agent_t);
    }
    return NULL;
}

int crypto_agent_destroy(crypto_agent agent) 
{
    crypto_agent_t* instance = (crypto_agent_t*)agent;
    
    if (instance == NULL) {
        fprintf(stdout,"crypto_agent_t is null\n");
        return 1;
    }
    
    if(instance->sessions != NULL){
        for(int i = 0; i < instance->max_count; i++){
            crypto_session_t* session = &instance->sessions[i];
            TEEC_CloseSession(&session->session_handle);
        }
        free(instance->sessions);
    }
    
    TEEC_FinalizeContext(&instance->tee_context);
    if(instance != NULL)
    {
	    free(instance);
    }
    return 0;
}

int crypto_agent_encrypt_dbshield_block(crypto_agent agent, int index,
    unsigned char* client_id, size_t id_len,
    unsigned char* data, size_t data_len,
    unsigned char* context, size_t context_len,
    unsigned char* result, size_t* result_len)
{
    crypto_agent_t* instance = (crypto_agent_t*)agent;
    crypto_session_t* session = NULL;
    if (instance == NULL || index >= instance->max_count || index < 0 ) {
        return 1;
    }
    
    session = &instance->sessions[index];
    crypto_cell_t* cell_result = (crypto_cell_t*)((void *)(result));
    unsigned char  block[SM4_KEY_SIZE] = {0};
    unsigned int   block_len = SM4_KEY_SIZE;
    unsigned int   first_len = SM4_PADDING(data_len) - block_len;
    unsigned int   total_len = SM4_PADDING(data_len) + BLOCK_HEADER_SIZE;
    unsigned int   start_size = 0;
    TEEC_Operation op;
    TEEC_Result res = TEEC_SUCCESS;
    uint32_t err_origin;

    //fprintf(stdout, "encrypt block with data_size:%lu\n", in->data_len);
    if (*result_len < total_len) {
        fprintf(stdout, "encrypt block failed with insufficant buffer size:%lu expect:%u\n", *result_len, total_len);
        goto ERR;
    }
    
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = cell_result->encrypted_key;
    op.params[0].tmpref.size = 16;
    op.params[1].tmpref.buffer = cell_result->iv;
    op.params[1].tmpref.size = 16;
    res = TEEC_InvokeCommand(&session->session_handle, SM4_CELL_ENCRYPT_INIT, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InvokeCommand SM4_CELL_ENCRYPT_INIT failed with code 0x%x origin 0x%x",
            res, err_origin);
        goto ERR;
    }
    
    while (first_len >= MAX_SM4_BLOCK_SIZE) {
        int encrypt_len = MAX_SM4_BLOCK_SIZE;
        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                        TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = data + start_size;
        op.params[0].tmpref.size = encrypt_len;
        op.params[1].tmpref.buffer = cell_result->encrypted + start_size;
        op.params[1].tmpref.size = encrypt_len;
        res = TEEC_InvokeCommand(&session->session_handle, SM4_CELL_DO_CIPHER, &op, &err_origin);
        if (res != TEEC_SUCCESS) {
            errx(1, "TEEC_InvokeCommand SM4_CELL_DO_CIPHER failed with code 0x%x origin 0x%x",
                res, err_origin);
            goto ERR;
        }
        first_len -= MAX_SM4_BLOCK_SIZE;
        start_size += MAX_SM4_BLOCK_SIZE;
    }
    
    if (first_len != 0) {
        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                        TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = data + start_size;
        op.params[0].tmpref.size = first_len;
        op.params[1].tmpref.buffer = cell_result->encrypted + start_size;
        op.params[1].tmpref.size = first_len;
        res = TEEC_InvokeCommand(&session->session_handle, SM4_CELL_DO_CIPHER, &op, &err_origin);
        if (res != TEEC_SUCCESS) {
            errx(1, "TEEC_InvokeCommand SM4_CELL_DO_CIPHER failed with code 0x%x origin 0x%x",
                res, err_origin);
            goto ERR;
        }
        start_size += first_len;
    }

    memcpy(block, data + first_len, data_len - start_size);
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                    TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = block;
    op.params[0].tmpref.size = block_len;
    op.params[1].tmpref.buffer = cell_result->encrypted + start_size;
    op.params[1].tmpref.size = block_len;
    res = TEEC_InvokeCommand(&session->session_handle, SM4_CELL_DO_CIPHER, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InvokeCommand SM4_CELL_DO_CIPHER failed with code 0x%x origin 0x%x",
            res, err_origin);
        goto ERR;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
                    TEEC_NONE, TEEC_NONE);
    res = TEEC_InvokeCommand(&session->session_handle, SM4_CELL_CIPHER_FINISH, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InvokeCommand SM4_CELL_CIPHER_FINISH failed with code 0x%x origin 0x%x",
            res, err_origin);
        goto ERR;
    }
    
    cell_result->version = VERSION_MAGIC;
    cell_result->raw_len = data_len;
    cell_result->encrypted_len = start_size + block_len;

    *result_len = total_len;
    return 0;
ERR:
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
                    TEEC_NONE, TEEC_NONE);
    TEEC_InvokeCommand(&session->session_handle, SM4_CELL_CIPHER_FINISH, &op, &err_origin);
    return res;
}

int crypto_agent_decrypt_dbshield_block(
    crypto_agent agent, int index,
    unsigned char* client_id, size_t id_len,
    unsigned char* key_data, size_t key_data_len,
    unsigned char* iv_init,
    unsigned char* data, size_t data_len,
    unsigned char* context, size_t context_len,
    unsigned char* plain, size_t* plain_len)
{
    crypto_agent_t* instance = (crypto_agent_t*)agent;
    crypto_session_t* session = NULL;
    if (instance == NULL || index >= instance->max_count || index < 0 ) {
        return 1;
    }
    
    unsigned      first_len = data_len - SM4_KEY_SIZE;
    unsigned char block[SM4_KEY_SIZE] = {0};
    unsigned int  block_len = SM4_KEY_SIZE;
    unsigned int   start_size = 0;
    TEEC_Operation op;
    TEEC_Result res = TEEC_SUCCESS;
    uint32_t err_origin;
    
    session = &instance->sessions[index];
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = key_data;
    op.params[0].tmpref.size = 16;
    op.params[1].tmpref.buffer = iv_init;
    op.params[1].tmpref.size = 16;
    res = TEEC_InvokeCommand(&session->session_handle, SM4_CELL_DECRYPT_INIT, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InvokeCommand SM4_CELL_DECRYPT_INIT failed with code 0x%x origin 0x%x",
            res, err_origin);
        goto ERR; 
    }
    
    while (first_len >= MAX_SM4_BLOCK_SIZE) {
        int encrypt_len = MAX_SM4_BLOCK_SIZE;
        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                        TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = data + start_size;
        op.params[0].tmpref.size = encrypt_len;
        op.params[1].tmpref.buffer = plain + start_size;
        op.params[1].tmpref.size = encrypt_len;
        res = TEEC_InvokeCommand(&session->session_handle, SM4_CELL_DO_CIPHER, &op, &err_origin);
        if (res != TEEC_SUCCESS) {
            errx(1, "TEEC_InvokeCommand SM4_CELL_DO_CIPHER failed with code 0x%x origin 0x%x",
                res, err_origin);
            goto ERR;
        }
        first_len -= MAX_SM4_BLOCK_SIZE;
        start_size += MAX_SM4_BLOCK_SIZE;
    }
    
    if (first_len != 0) {
        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                        TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = data + start_size;
        op.params[0].tmpref.size = first_len;
        op.params[1].tmpref.buffer = plain + start_size;
        op.params[1].tmpref.size = first_len;
        res = TEEC_InvokeCommand(&session->session_handle, SM4_CELL_DO_CIPHER, &op, &err_origin);
        if (res != TEEC_SUCCESS) {
            errx(1, "TEEC_InvokeCommand SM4_CELL_DO_CIPHER failed with code 0x%x origin 0x%x",
                res, err_origin);
            goto ERR;
        }
        start_size += first_len;
    }

    memcpy(block, data + first_len, data_len - start_size);
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                    TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = data + start_size;
    op.params[0].tmpref.size = block_len;
    op.params[1].tmpref.buffer = block;
    op.params[1].tmpref.size = block_len;
    res = TEEC_InvokeCommand(&session->session_handle, SM4_CELL_DO_CIPHER, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InvokeCommand SM4_CELL_DO_CIPHER failed with code 0x%x origin 0x%x",
            res, err_origin);
        goto ERR;
    }
    memcpy(plain + start_size, block, *plain_len - start_size);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
                    TEEC_NONE, TEEC_NONE);
    res = TEEC_InvokeCommand(&session->session_handle, SM4_CELL_CIPHER_FINISH, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InvokeCommand SM4_CELL_CIPHER_FINISH failed with code 0x%x origin 0x%x",
            res, err_origin);
        goto ERR;
    }
    
    return 0;
ERR:
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
                    TEEC_NONE, TEEC_NONE);
    TEEC_InvokeCommand(&session->session_handle, SM4_CELL_CIPHER_FINISH, &op, &err_origin);
    return res;
}

int crypto_agent_hmac(crypto_agent agent, int index,
    unsigned char* client_id, size_t id_len,
    unsigned char* data, size_t data_len,
    unsigned char* result, size_t* result_len) {
    
    crypto_agent_t* instance = (crypto_agent_t*)agent;
    crypto_session_t* session = NULL;
    if (instance == NULL || index >= instance->max_count || index < 0 ) {
        return 1;
    }
    
    TEEC_Operation op;
    TEEC_Result res = TEEC_SUCCESS;
    uint32_t err_origin;
    
    session = &instance->sessions[index];
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
                     TEEC_NONE, TEEC_NONE);
    res = TEEC_InvokeCommand(&session->session_handle, SM3_HMAC_INIT, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InvokeCommand SM3_HMAC_INIT failed with code 0x%x origin 0x%x",
            res, err_origin);
        goto ERR; 
    }
    
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
                    TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = data;
    op.params[0].tmpref.size = data_len;
    res = TEEC_InvokeCommand(&session->session_handle, SM3_HMAC_UPDATE, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InvokeCommand SM3_HMAC_UPDATE failed with code 0x%x origin 0x%x",
            res, err_origin);
        goto ERR;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
                    TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = result;
    op.params[0].tmpref.size = *result_len;
    res = TEEC_InvokeCommand(&session->session_handle, SM3_HMAC_FINAL, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InvokeCommand SM3_HMAC_FINAL failed with code 0x%x origin 0x%x",
            res, err_origin);
        goto ERR;
    }
    *result_len = 32;  
    return 0;
ERR:
    *result_len = 0;
    return res;

}

int crypto_agent_encrypt_dbshield_struct(
    crypto_agent agent, int index,
    unsigned char* client_id, size_t id_len,
    void* data, size_t data_len,
    const char* context, size_t context_len, 
    void* result, size_t* result_len)
{
    *result_len = 0;
    return 1;
}

int crypto_agent_decrypt_dbshield_struct(
    crypto_agent agent, int index,
    unsigned char* client_id, size_t id_len,
    unsigned char pubkey_data, size_t pubkey_len, 
    unsigned char key_data, size_t key_data_len,
    unsigned char data, size_t data_len,
    unsigned char context, size_t context_len,
    unsigned char plain, size_t* plain_len)
{
    *plain_len = 0;
    return 1;
}