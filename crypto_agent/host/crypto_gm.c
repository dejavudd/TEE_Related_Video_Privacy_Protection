#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <signal.h>

#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <ctype.h>

#include <tee_client_api.h>
#include <teec_trace.h>
#include <getopt.h>
#include "ta_crypto_agent.h"

#define   FLAG_INIT      (1<<0)
#define   FLAG_LOAD      (1<<1)
#define   FLAG_TEST      (1<<2)
#define   SYM_FLAG       (1<<3)
#define   ASYM_FLAG      (1<<4)
#define   FLAG_IMPORT    (1<<5)
#define   FLAG_EXPORT    (1<<6)
#define   FLAG_SYM       (1<<7)
#define   FLAG_ASYM      (1<<8)

#define   PIN_VAL        (1)
#define   SYM_VAL        (2)
#define   ASYM_VAL       (3)
#define   PUBKEY_VAL     (4)

static struct option gm_options[] =
{
    {"init",    no_argument,       0, 'i'},
    {"load",    no_argument,       0, 'l'},
    {"test",    no_argument,       0, 't'},
    {"import",  no_argument, 0, 'd'},
    {"export",  no_argument, 0, 'e'},
    {"file",    required_argument, 0, 'f'},
    {"password", required_argument, 0, 'p'},
    {"pin",     required_argument, 0, PIN_VAL},
    {"sym",  no_argument, 0, SYM_VAL},
    {"asym",  no_argument, 0, ASYM_VAL},
    {"pubkey",  required_argument, 0, PUBKEY_VAL},
    {0, 0, 0, 0}
};

static void print_usage();
static int  init_crypto_agent(const char *pin);
static int  load_crypto_agent();
static int  import_key_sym(const char* sym_key, const char* pin, encrypted_key_data_t* encrypted_key);
static int  export_key_sym(const char* sym_key, const char* pin, encrypted_key_data_t* encrypted_key);
static int  import_key_asym(const char* pin, key_data_seal_box_t* key_box);
static int  export_key_asym(const char* pub_key, const char* pin, key_data_seal_box_t* key_box);

static int  test_ecnryption(const char* pin);

void print_usage() {
}

static void print_hex(const char* tag, uint8_t* buf, size_t len) {
    printf("%s:0x", tag);

    for (int i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }

    printf("\n");
}

static void scanf_hex(const char* hex, uint8_t* buf, size_t len) {
    if (strlen(hex) != len * 2) {
        return;
    }

    char* lower_hex = (char *)malloc(strlen(hex) + 1);
    memset(lower_hex, 0, strlen(hex) + 1);

    for (int i = 0; i < strlen(hex); i++) {
        lower_hex[i] = tolower(hex[i]);
    }

    for (int i = 0; i < len; i++) {
        unsigned int val = 0;
        sscanf(lower_hex + 2*i, "%02x", &val);
        buf[i] = (val & 0xFF);
    }

    free(lower_hex);
}

int init_crypto_agent(const char *pin) {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_CRYPTO_AGENT_UUID;
    uint32_t err_origin;
    //uint8_t  master_key[16] = {0};
    //uint8_t  hmac_key[64] = {0};
    uint8_t    pin_temp[16] = {0};
    uint8_t    pubkey[64] = {0};

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
            res, err_origin);

    /*
     * Execute a function in the TA by invoking it, in this case
     * we're incrementing a number.
     *
     * The value of command ID part and how the parameters are
     * interpreted is part of the interface provided by the TA.
     */

    /*
     * Prepare the argument. Pass a value in the first parameter,
     * the remaining three parameters are unused.
     */
    memcpy(pin_temp, pin, strlen(pin));
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = pin_temp;
    op.params[0].tmpref.size = 16;
    op.params[1].tmpref.buffer = pubkey;
    op.params[1].tmpref.size = 64;    
    res = TEEC_InvokeCommand(&sess, MASTER_KEY_INIT, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
            res, err_origin);
    /*
     * We're done with the TA, close the session and
     * destroy the context.
     *
     * The TA will print "Goodbye!" in the log when the
     * session is closed.
     */

    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);
    
    print_hex("PubKey", pubkey, 64);
    
    return 0;
}

int load_crypto_agent() {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_CRYPTO_AGENT_UUID;
    uint32_t err_origin;
    //uint8_t  master_key[16] = {0};
    uint8_t  pubkey[64] = {0};

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
            res, err_origin);

    /*
     * Execute a function in the TA by invoking it, in this case
     * we're incrementing a number.
     *
     * The value of command ID part and how the parameters are
     * interpreted is part of the interface provided by the TA.
     */

    /*
     * Prepare the argument. Pass a value in the first parameter,
     * the remaining three parameters are unused.
     */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = pubkey;
    op.params[0].tmpref.size = 64;   
    res = TEEC_InvokeCommand(&sess, MASTER_KEY_LOAD, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
            res, err_origin);
    /*
     * We're done with the TA, close the session and
     * destroy the context.
     *
     * The TA will print "Goodbye!" in the log when the
     * session is closed.
     */

    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);
    
    print_hex("PubKey", pubkey, 64);

    return 0;
}

int import_key_sym(const char* sym_key, const char* pin, encrypted_key_data_t* encrypted_key) {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_CRYPTO_AGENT_UUID;
    uint32_t err_origin;
    //uint8_t  master_key[16] = {0};
    uint8_t  pubkey[64] = {0};
    uint8_t  key_arr[16] = {0};
    uint8_t  pin_temp[16] = {0};
    
    if (strlen(sym_key) != 32) {
        return 1;
    }
    
    scanf_hex(sym_key, key_arr, 16);
    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
            res, err_origin);

    /*
     * Execute a function in the TA by invoking it, in this case
     * we're incrementing a number.
     *
     * The value of command ID part and how the parameters are
     * interpreted is part of the interface provided by the TA.
     */

    /*
     * Prepare the argument. Pass a value in the first parameter,
     * the remaining three parameters are unused.
     */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                     TEEC_NONE,
                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = pubkey;
    op.params[0].tmpref.size = 64;   
    res = TEEC_InvokeCommand(&sess, MASTER_KEY_LOAD, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
            res, err_origin);
    /*
     * We're done with the TA, close the session and
     * destroy the context.
     *
     * The TA will print "Goodbye!" in the log when the
     * session is closed.
     */

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                     TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_OUTPUT);
    
    memcpy(pin_temp, pin, strlen(pin));
    op.params[0].tmpref.buffer = pin_temp;
    op.params[0].tmpref.size = 16;   
    op.params[1].tmpref.buffer = key_arr;
    op.params[1].tmpref.size = 16; 
    op.params[2].tmpref.buffer = encrypted_key;
    op.params[2].tmpref.size = sizeof(encrypted_key_data_t); 

    res = TEEC_InvokeCommand(&sess, IMPORT_KEY_ENCRYPT_SYMMETRIC, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
            res, err_origin);

    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);
    
    return 0;

}

int export_key_sym(const char* sym_key, const char* pin, encrypted_key_data_t* encrypted_key) {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_CRYPTO_AGENT_UUID;
    uint32_t err_origin;
    //uint8_t  master_key[16] = {0};
    uint8_t  pubkey[64] = {0};
    uint8_t  key_arr[16] = {0};
    uint8_t  pin_temp[16] = {0};
    
    if (strlen(sym_key) != 32) {
        return 1;
    }
    
    scanf_hex(sym_key, key_arr, 16);
    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
            res, err_origin);

    /*
     * Execute a function in the TA by invoking it, in this case
     * we're incrementing a number.
     *
     * The value of command ID part and how the parameters are
     * interpreted is part of the interface provided by the TA.
     */

    /*
     * Prepare the argument. Pass a value in the first parameter,
     * the remaining three parameters are unused.
     */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                     TEEC_NONE,
                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = pubkey;
    op.params[0].tmpref.size = 64;   
    res = TEEC_InvokeCommand(&sess, MASTER_KEY_LOAD, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
            res, err_origin);
    /*
     * We're done with the TA, close the session and
     * destroy the context.
     *
     * The TA will print "Goodbye!" in the log when the
     * session is closed.
     */

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                     TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
    
    memcpy(pin_temp, pin, strlen(pin));
    op.params[0].tmpref.buffer = pin_temp;
    op.params[0].tmpref.size = 16;   
    op.params[1].tmpref.buffer = key_arr;
    op.params[1].tmpref.size = 16; 
    op.params[2].tmpref.buffer = encrypted_key;
    op.params[2].tmpref.size = sizeof(encrypted_key_data_t); 

    res = TEEC_InvokeCommand(&sess, EXPORT_KEY_ENCRYPT_SYMMETRIC, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
            res, err_origin);

    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);
    
    return 0;
}

int import_key_asym(const char* pin, key_data_seal_box_t* key_box) {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_CRYPTO_AGENT_UUID;
    uint32_t err_origin;
    //uint8_t  master_key[16] = {0};
    uint8_t  pubkey[64] = {0};
    uint8_t  pin_temp[16] = {0};
    
    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession TEEC_LOGIN_PUBLIC failed with code 0x%x origin 0x%x",
            res, err_origin);

    /*
     * Execute a function in the TA by invoking it, in this case
     * we're incrementing a number.
     *
     * The value of command ID part and how the parameters are
     * interpreted is part of the interface provided by the TA.
     */

    /*
     * Prepare the argument. Pass a value in the first parameter,
     * the remaining three parameters are unused.
     */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                     TEEC_NONE,
                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = pubkey;
    op.params[0].tmpref.size = 64;   
    res = TEEC_InvokeCommand(&sess, MASTER_KEY_LOAD, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand MASTER_KEY_LOAD failed with code 0x%x origin 0x%x",
            res, err_origin);
    /*
     * We're done with the TA, close the session and
     * destroy the context.
     *
     * The TA will print "Goodbye!" in the log when the
     * session is closed.
     */

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                     TEEC_NONE, TEEC_VALUE_OUTPUT);
    
    memcpy(pin_temp, pin, strlen(pin));
    op.params[0].tmpref.buffer = pin_temp;
    op.params[0].tmpref.size = 16;   
    op.params[1].tmpref.buffer = key_box;
    op.params[1].tmpref.size = sizeof(key_data_seal_box_t); 
    
    res = TEEC_InvokeCommand(&sess, IMPORT_KEY_ENCRYPT_ASYMMETRIC, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("Debug step:%d\n", op.params[3].value.a);
        errx(1, "TEEC_InvokeCommand IMPORT_KEY_ENCRYPT_ASYMMETRIC failed with code 0x%x origin 0x%x",
            res, err_origin);
    }

    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);
    
    return 0;
}

int export_key_asym(const char* pub_key, const char* pin, key_data_seal_box_t* key_box) {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_CRYPTO_AGENT_UUID;
    uint32_t err_origin;
    //uint8_t  master_key[16] = {0};
    uint8_t  pubkey[64] = {0};
    uint8_t  encrypt_pub_key[64] = {0};
    uint8_t  pin_temp[16] = {0};
    
    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
            res, err_origin);

    /*
     * Execute a function in the TA by invoking it, in this case
     * we're incrementing a number.
     *
     * The value of command ID part and how the parameters are
     * interpreted is part of the interface provided by the TA.
     */

    /*
     * Prepare the argument. Pass a value in the first parameter,
     * the remaining three parameters are unused.
     */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                     TEEC_NONE,
                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = pubkey;
    op.params[0].tmpref.size = 64;   
    res = TEEC_InvokeCommand(&sess, MASTER_KEY_LOAD, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
            res, err_origin);
    /*
     * We're done with the TA, close the session and
     * destroy the context.
     *
     * The TA will print "Goodbye!" in the log when the
     * session is closed.
     */

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                     TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
    
    if (strlen(pub_key) != 128) {
        return 1;
    }
    
    scanf_hex(pub_key, encrypt_pub_key, 64);
    print_hex("PubKey", encrypt_pub_key, 64);

    memcpy(pin_temp, pin, strlen(pin));
    op.params[0].tmpref.buffer = pin_temp;
    op.params[0].tmpref.size = 16;   
    op.params[1].tmpref.buffer = encrypt_pub_key;
    op.params[1].tmpref.size = 64;
    op.params[2].tmpref.buffer = key_box;
    op.params[2].tmpref.size = sizeof(key_data_seal_box_t); 
    
    res = TEEC_InvokeCommand(&sess, EXPORT_KEY_ENCRYPT_ASYMMETRIC, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
            res, err_origin);

    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);
    
    return 0;
}

int test_ecnryption(const char* pin) {
    char text[32] = "Anyong Database Encryption test";

    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_CRYPTO_AGENT_UUID;
    uint32_t err_origin;
    uint8_t  master_key[16] = {0};
    uint8_t  hmac_key[64] = {0};
    uint8_t  encrypted_key[16] = {0};
    uint8_t  iv[16] = {0};
    uint8_t  encrypted_text[32] = {0};
    uint8_t  decrypted_text[32] = {0};
    uint8_t  pubkey[64] = {0};
    uint8_t  pin_temp[16] = {0};
    uint8_t  hmac_temp[32] = {0};
    key_data_t  key_data;

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
            res, err_origin);

    /*
     * Execute a function in the TA by invoking it, in this case
     * we're incrementing a number.
     *
     * The value of command ID part and how the parameters are
     * interpreted is part of the interface provided by the TA.
     */

    /*
     * Prepare the argument. Pass a value in the first parameter,
     * the remaining three parameters are unused.
     */
    memset(&op, 0, sizeof(op));
    op.params[0].tmpref.buffer = pubkey;
    op.params[0].tmpref.size = 64;
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
                     TEEC_NONE, TEEC_NONE);
    res = TEEC_InvokeCommand(&sess, MASTER_KEY_LOAD, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand MASTER_KEY_LOAD failed with code 0x%x origin 0x%x",
            res, err_origin);

    memset(&op, 0, sizeof(op));
    memcpy(pin_temp, pin, strlen(pin));
    op.params[0].tmpref.buffer = pin_temp;
    op.params[0].tmpref.size = 16;   
    op.params[1].tmpref.buffer = &key_data;
    op.params[1].tmpref.size = sizeof(key_data);
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                     TEEC_NONE, TEEC_NONE);
    res = TEEC_InvokeCommand(&sess, MASTER_KEY_DEBUG, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand MASTER_KEY_DEBUG failed with code 0x%x origin 0x%x",
            res, err_origin);
    print_hex("Master Key", key_data.sm4_key, 16);
    print_hex("HMac Key", key_data.hmac_key, 64);

    
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = encrypted_key;
    op.params[0].tmpref.size = 16;
    op.params[1].tmpref.buffer = iv;
    op.params[1].tmpref.size = 16;
    res = TEEC_InvokeCommand(&sess, SM4_CELL_ENCRYPT_INIT, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand SM4_CELL_ENCRYPT_INIT failed with code 0x%x origin 0x%x",
            res, err_origin);

    print_hex("EncryptedKey", encrypted_key, 16);
    print_hex("Init iv", iv, 16);
    
#if 1
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = text;
    op.params[0].tmpref.size = 32;
    op.params[1].tmpref.buffer = encrypted_text;
    op.params[1].tmpref.size = 32;
    res = TEEC_InvokeCommand(&sess, SM4_CELL_DO_CIPHER, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand SM4_CELL_DO_CIPHER failed with code 0x%x origin 0x%x",
            res, err_origin);
    
    print_hex("EncryptedText", encrypted_text, 32);


    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
                     TEEC_NONE, TEEC_NONE);
    res = TEEC_InvokeCommand(&sess, SM4_CELL_CIPHER_FINISH, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand SM4_CELL_CIPHER_FINISH failed with code 0x%x origin 0x%x",
            res, err_origin);
    

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = encrypted_key;
    op.params[0].tmpref.size = 16;
    op.params[1].tmpref.buffer = iv;
    op.params[1].tmpref.size = 16;
    res = TEEC_InvokeCommand(&sess, SM4_CELL_DECRYPT_INIT, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand SM4_CELL_DECRYPT_INIT failed with code 0x%x origin 0x%x",
            res, err_origin);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = encrypted_text;
    op.params[0].tmpref.size = 32;
    op.params[1].tmpref.buffer = decrypted_text;
    op.params[1].tmpref.size = 32;
    res = TEEC_InvokeCommand(&sess, SM4_CELL_DO_CIPHER, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand SM4_CELL_DO_CIPHER failed with code 0x%x origin 0x%x",
            res, err_origin);
    
    print_hex("DecryptedText", decrypted_text, 32);


    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
                     TEEC_NONE, TEEC_NONE);
    res = TEEC_InvokeCommand(&sess, SM4_CELL_CIPHER_FINISH, &op,
                 &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand SM4_CELL_CIPHER_FINISH failed with code 0x%x origin 0x%x",
            res, err_origin);
    

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
                     TEEC_NONE, TEEC_NONE);
    res = TEEC_InvokeCommand(&session->session_handle, SM3_HMAC_INIT, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InvokeCommand SM3_HMAC_INIT failed with code 0x%x origin 0x%x",
            res, err_origin);
    }
    
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
                    TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = "Hello";
    op.params[0].tmpref.size = 5;
    res = TEEC_InvokeCommand(&session->session_handle, SM3_HMAC_UPDATE, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InvokeCommand SM3_HMAC_UPDATE failed with code 0x%x origin 0x%x",
            res, err_origin);
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
                    TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = hmac_temp;
    op.params[0].tmpref.size = 32;
    res = TEEC_InvokeCommand(&session->session_handle, SM3_HMAC_FINAL, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InvokeCommand SM3_HMAC_FINAL failed with code 0x%x origin 0x%x",
            res, err_origin);
    }

    print_hex("Hmac value", hmac_temp, 32);


    /*
     * We're done with the TA, close the session and
     * destroy the context.
     *
     * The TA will print "Goodbye!" in the log when the
     * session is closed.
     */
#endif
    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);

    return 0;
}

int main(int argc, char** argv) 
{
    /* getopt_long stores the option index here. */
    int option_index = 0;
    int flag = 0;
    const char* password = NULL;
    const char* pubkey = NULL;
    const char* file_path = NULL;
    const char* pin = NULL;
    
    while (1) 
    {
        int c = getopt_long (argc, argv, "iltp:def:",
                        gm_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c)
        {
        case 0:
            print_usage();
            return 1;

        case 'i':
            flag |= FLAG_INIT;
            break;
        
        case 'l':
            flag |= FLAG_LOAD;
            break;

        case 't':
            flag |= FLAG_TEST;
            break;

        case 'f':
            file_path = optarg;
            break;

        case 'p':
            password = optarg;
            break;

        case PUBKEY_VAL:
            pubkey = optarg;
            break;

        case PIN_VAL:
            pin = optarg;
            break;

        case 'd':
            flag |= FLAG_IMPORT;
            break;

        case 'e':
            flag |= FLAG_EXPORT;
            break;

        case SYM_VAL:
            flag |= FLAG_SYM;
            break;

        case ASYM_VAL:
            flag |= FLAG_ASYM;
            break;
        
        case '?':
            break;

        default:
            print_usage();
            return 1;
        }
    }

    if ((flag & FLAG_INIT) != 0) {
        if (pin == NULL || (strlen(pin) < 6 || strlen(pin) > 16)) {
            printf("pin invalid\n");
            return 0;
        }

        init_crypto_agent(pin);
    } else if ((flag & FLAG_LOAD) != 0) {
        load_crypto_agent();
    } else if ((flag & FLAG_IMPORT) != 0) {
        if (pin == NULL || (strlen(pin) < 6 || strlen(pin) > 16)) {
            printf("pin invalid\n");
            return 0;
        }

        if (((flag & FLAG_ASYM) == 0 && (flag & FLAG_SYM) == 0) || 
            ((flag & FLAG_ASYM) != 0 && (flag & FLAG_SYM) != 0)) {
            printf("Need import key symmetric or asymmetric\n");
            return 0;
        }

        if (file_path == NULL) {
            printf("Need key file path\n");
            return 0;
        }

        if (flag & FLAG_ASYM) {
            key_data_seal_box_t key_box;
            memset(&key_box, 0, sizeof(key_data_seal_box_t));

            FILE* fp = fopen(file_path, "rb");
            if (fp == NULL) {
                printf("key box file:%s not found\n", file_path);
                return 0;
            }

            int size = fread(&key_box, 1, sizeof(key_data_seal_box_t), fp);
            if (size != sizeof(key_data_seal_box_t)) {
                printf("invalid key box file:%s.\n", file_path);
                fclose(fp);
                return 0;
            }
            fclose(fp);
            import_key_asym(pin, &key_box);
        } else if (flag & FLAG_SYM) {
            if (password == NULL) {
                printf("Need symmertic key\n");
                return 0;
            }
            encrypted_key_data_t encrypted_key;
            memset(&encrypted_key, 0, sizeof(encrypted_key_data_t));

            FILE* fp = fopen(file_path, "rb");
            if (fp == NULL) {
                printf("encrypted key file:%s not found\n", file_path);
                return 0;
            }

            int size = fread(&encrypted_key, 1, sizeof(encrypted_key_data_t), fp);
            if (size != sizeof(encrypted_key_data_t)) {
                printf("invalid encrypted key file:%s.\n", file_path);
                fclose(fp);
                return 0;
            }
            fclose(fp);
            import_key_sym(password, pin, &encrypted_key);
        } else {
        }
    } else if ((flag & FLAG_EXPORT) != 0) {
        if (pin == NULL || (strlen(pin) < 6 || strlen(pin) > 16)) {
            printf("pin invalid\n");
            return 0;
        }

        if (((flag & FLAG_ASYM) == 0 && (flag & FLAG_SYM) == 0) || 
            ((flag & FLAG_ASYM) != 0 && (flag & FLAG_SYM) != 0)) {
            printf("Need export key symmetric or asymmetric\n");
            return 0;
        }

        if (file_path == NULL) {
            printf("Need key file path\n");
            return 0;
        }

        if (flag & FLAG_ASYM) {
            if (pubkey == NULL) {
                printf("Need pubkey\n");
                return 0;
            }

            key_data_seal_box_t key_box;
            memset(&key_box, 0, sizeof(key_data_seal_box_t));
            export_key_asym(pubkey, pin, &key_box);
            
            FILE* fp = fopen(file_path, "wb");
            if (fp == NULL) {
                printf("encrypted key file:%s open failed\n", file_path);
                return 0;
            }

            int size = fwrite(&key_box, 1, sizeof(key_data_seal_box_t), fp);
            if (size != sizeof(key_data_seal_box_t)) {
                printf("write encrypted key file:%s failed.\n", file_path);
                fclose(fp);
                return 0;
            }
            fclose(fp);
        } else if (flag & FLAG_SYM) {
            if (password == NULL) {
                printf("Need symmertic key\n");
                return 0;
            }
            encrypted_key_data_t encrypted_key;
            memset(&encrypted_key, 0, sizeof(encrypted_key_data_t));

            export_key_sym(password, pin, &encrypted_key);

            FILE* fp = fopen(file_path, "wb");
            if (fp == NULL) {
                printf("encrypted key file:%s open failed\n", file_path);
                return 0;
            }

            int size = fwrite(&encrypted_key, 1, sizeof(encrypted_key_data_t), fp);
            if (size != sizeof(encrypted_key_data_t)) {
                printf("write encrypted key file:%s failed.\n", file_path);
                fclose(fp);
                return 0;
            }
            fclose(fp);
        } else {
        }
    } else if ((flag & FLAG_TEST) != 0) {
        if (pin == NULL || (strlen(pin) < 6 || strlen(pin) > 16)) {
            printf("pin invalid\n");
            return 0;
        }
        test_ecnryption(pin);
    }

    return 0;
}
