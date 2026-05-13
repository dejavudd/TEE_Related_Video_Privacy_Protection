#ifndef __CRYPTO_AGENT_API_H__
#define __CRYPTO_AGENT_API_H__

#include "stdlib.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef void* crypto_agent;

crypto_agent crypto_agent_create(int max_count);
int crypto_agent_destroy(crypto_agent agent);
int crypto_agent_encrypt_dbshield_block(
    crypto_agent agent, int index, 
    unsigned char* client_id, size_t id_len,
    unsigned char* data, size_t data_len,
    unsigned char* context, size_t context_len,
    unsigned char* result, size_t* result_len);

int crypto_agent_decrypt_dbshield_block(
    crypto_agent agent, int index,
    unsigned char* client_id, size_t id_len,
    unsigned char* key_data, size_t key_data_len,
    unsigned char* iv_init,
    unsigned char* data, size_t data_len,
    unsigned char* context, size_t context_len,
    unsigned char* plain, size_t* plain_len);

int crypto_agent_hmac(crypto_agent agent, int index,
    unsigned char* client_id, size_t id_len,
    unsigned char* data, size_t data_len,
    unsigned char* result, size_t* result_len);

int crypto_agent_encrypt_dbshield_struct(
    crypto_agent agent, int index,
    unsigned char* client_id, size_t id_len,
    void* data, size_t data_len,
    const char* context, size_t context_len, 
    void* result, size_t* result_len);

int crypto_agent_decrypt_dbshield_struct(
    crypto_agent agent,  int index,
    unsigned char* client_id, size_t id_len,
    unsigned char pubkey_data, size_t pubkey_len, 
    unsigned char key_data, size_t key_data_len,
    unsigned char data, size_t data_len,
    unsigned char context, size_t context_len,
    unsigned char plain, size_t* plain_len);
#ifdef __cplusplus
}
#endif

#endif /* */
