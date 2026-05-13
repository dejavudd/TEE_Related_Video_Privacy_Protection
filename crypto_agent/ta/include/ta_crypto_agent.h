/*
 * Copyright (c) 2014, Linaro Limited
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
#ifndef TA_CRYPTO_AGENT_H
#define TA_CRYPTO_AGENT_H

/*
 * This UUID is generated with uuidgen
   the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
/* 24029442-44cd-4960-b4d3-33f7ec14b649 */
#define TA_CRYPTO_AGENT_UUID { 0x24029442, 0x44cd, 0x4960, \
				  { 0xb4, 0xd3, 0x33, 0xf7, 0xec, 0x14, 0xb6, 0x49} }

/* The TAFs ID implemented in this TA */
enum {
	SM4_CELL_ENCRYPT_INIT = 1,
	SM4_CELL_DECRYPT_INIT,
	SM4_CELL_DO_CIPHER,
	SM4_CELL_CIPHER_FINISH,
	SM3_INIT,
	SM3_UPDATE,
	SM3_FINAL,
	SM3_HMAC_INIT,
	SM3_HMAC_UPDATE,
	SM3_HMAC_FINAL,
	MASTER_KEY_LOAD,
	MASTER_KEY_INIT,
	EXPORT_KEY_ENCRYPT_SYMMETRIC,
	IMPORT_KEY_ENCRYPT_SYMMETRIC,
	EXPORT_KEY_ENCRYPT_ASYMMETRIC,
	IMPORT_KEY_ENCRYPT_ASYMMETRIC,
	MASTER_KEY_DEBUG = 0x1000,
};

typedef struct key_data_tag {
	uint8_t   sm4_key[16];
	uint8_t   hmac_key[64];
} key_data_t;

typedef struct encrypted_key_data_tag {
	uint8_t    version[16];
	uint8_t    iv[16];
	key_data_t key_data;
} encrypted_key_data_t;


typedef struct key_data_seal_box_tag {
	uint32_t   seal_key_len;
    uint8_t    seal_key[132];
	encrypted_key_data_t encrypted_key;
} key_data_seal_box_t;


#endif /*TA_CRYPTO_AGENT_H*/
