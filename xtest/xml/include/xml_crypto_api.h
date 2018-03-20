/*
 * Copyright (c) 2017-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 * Copyright (c) 2014, STMicroelectronics International N.V.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef XML_CRYPTO_API_H_
#define XML_CRYPTO_API_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include "tee_client_api.h"
#include "xtest_test.h"
#include "xml_common_api.h"
#include "xtest_ta_defines.h"
#include "xml_ds_crypto_common_api.h"
#include "xml_crypto_attributes.h"

#define BIT_CHANGE(a, b) ((a) ^= (1 << (b)))

#define CRYPTO_INIT(b) \
	(b).buffer = NULL; \
	(b).size = 0;

#define CRYPTO_MALLOC(b, s) \
	(b).size = (s); \
	(b).buffer = malloc((s))

#define CRYPTO_FREE(b) { \
		if ((b).buffer != NULL) { \
			(b).size = 0; \
			free((b).buffer); \
			(b).buffer = NULL; \
		} }

/* First free the buffer in case CRYPTO_FREE has not already been called */
#define CRYPTO_SAFE_MALLOC(b, s) \
	CRYPTO_FREE(b); \
	CRYPTO_MALLOC(b, s)

/*Missing TEE Error codes*/
#define TEE_ERROR_TOO_SHORT_BUFFER  TEE_ERROR_SHORT_BUFFER

/*Other defines*/
#define TEE_USAGE_NONE      0

static uint32_t big_size = BIG_SIZE;
uint32_t DS_BIG_SIZE = 16384;

/*ALL_TEE_TAG_LENGTH_FOR_AES*/
#define AES_104_bits                104
#define AES_112_bits                112
#define AES_120_bits                120
#define AES_128_bits                128
#define AES_32_bits                 32
#define AES_48_bits                 48
#define AES_64_bits                 64
#define AES_80_bits                 80
#define AES_96_bits                 96

/* Redefine list of Supported ECC Curves encoded as Big Endian as required in
 * the GP test suite specification for Invoke_Crypto_InitObjectWithKeysExt in
 * packages/Crypto/html/TEE_Crypto_API_operationsDescriptions.html.
 *
 * When a parameter IN_AttributeID_x designates a value attribute (i.e. bit 29
 * is set to 1, the bits being numbered from 0 (least-significant)), the value
 * of the corresponding parameter IN_Attrib_Value_x has to be written on 4
 * bytes in a most significant byte first representation (big-endian).
 *
 * Additionally, Invoke_Crypto_InitObjectWithKeysExt expects a const void *
 * parameter.
 */
#undef TEE_ECC_CURVE_NIST_P192
#undef TEE_ECC_CURVE_NIST_P224
#undef TEE_ECC_CURVE_NIST_P256
#undef TEE_ECC_CURVE_NIST_P384
#undef TEE_ECC_CURVE_NIST_P521

static uint8_t TEE_ECC_CURVE_NIST_P192[] = { 0x00, 0x00, 0x00, 0x01 };
static uint8_t TEE_ECC_CURVE_NIST_P224[] = { 0x00, 0x00, 0x00, 0x02 };
static uint8_t TEE_ECC_CURVE_NIST_P256[] = { 0x00, 0x00, 0x00, 0x03 };
static uint8_t TEE_ECC_CURVE_NIST_P384[] = { 0x00, 0x00, 0x00, 0x04 };
static uint8_t TEE_ECC_CURVE_NIST_P521[] = { 0x00, 0x00, 0x00, 0x05 };

static TEEC_SharedMemory *SHARE_MEM05;
static TEEC_SharedMemory *SHARE_MEM06;
static TEE_OperationHandle *OPERATION_HANDLE_01;
static TEE_OperationHandle *OPERATION_HANDLE_02;
static TEE_OperationHandle *OPERATION_HANDLE_INVALID;

/*ALL_CRYPTO_AAD_VALUES*/
static const uint8_t AAD1_VALUE[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
};

/*ALL_CRYPTO_AAD_LENGTHS*/
#define AAD1_LENGTH     8
#define NULL_LENGTH     0

/*ALL_TEE_CRYPTO_INITIALISATION_VECTOR_VALUES*/
static const uint8_t NONCE2_VALUE_AES_GCM[] = {
	0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
};
static const uint8_t NONCE1_VALUE_AES_CCM[] = {
	0x00, 0x8D, 0x49, 0x3B, 0x30, 0xAE, 0x8B, 0x3C, 0x96, 0x96, 0x76, 0x6C,
	0xFA
};

/*ALL_TEE_CRYPTO_INITIALISATION_VECTOR_LENGTHS*/
#define NONCE2_LENGTH_AES_GCM       12
#define NONCE1_LENGTH_AES_CCM       13

/*ALL_CRYPTO_DATA_VALUE*/
static const uint8_t DATA_ALL_ZEROES[256]; // automatically set to 0;
static const uint8_t DATA_FOR_CRYPTO1[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F,
	0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09,
	0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04,
	0x03, 0x02, 0x01, 0x00,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F,
	0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09,
	0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04,
	0x03, 0x02, 0x01, 0x00
};
static const uint8_t DATA_FOR_CRYPTO1_PART1[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F,
	0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09
};
static const uint8_t DATA_FOR_CRYPTO1_PART2[] = {
	0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04,
	0x03, 0x02, 0x01, 0x00,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F
};
static const uint8_t DATA_FOR_CRYPTO1_PART3[] = {
	0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09,
	0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04,
	0x03, 0x02, 0x01, 0x00
};

static const uint8_t DATA_FOR_CRYPTO2_LENGTH_NOT_MULTIPLE_OF_128_BITS[] = {
	0x00, 0x01, 0x02, 0x03
};
static const uint8_t DATA_FOR_CRYPTO3_LENGTH_NOT_MULTIPLE_OF_64_BITS[] = {
	0x00, 0x01, 0x02, 0x03
};

/*ALL_CRYPTO_DATA_LENGTH*/
#define LENGTH_DATA_FOR_CRYPTO1         96
#define LENGTH_DATA_FOR_CRYPTO1_PART1   32
#define LENGTH_DATA_FOR_CRYPTO1_PART2   32
#define LENGTH_DATA_FOR_CRYPTO1_PART3   32
#define LENGTH_DATA_FOR_CRYPTO2 	4
#define LENGTH_DATA_FOR_CRYPTO3 	4
#define RSAES_PKCS1_OAEP_MGF1_SHA1_ENC_INVALID_LENGTH_MOD_2048 	 215
#define RSAES_PKCS1_OAEP_MGF1_SHA224_ENC_INVALID_LENGTH_MOD_2048 	 199
#define RSAES_PKCS1_OAEP_MGF1_SHA256_ENC_INVALID_LENGTH_MOD_2048 	 191
#define RSAES_PKCS1_OAEP_MGF1_SHA384_ENC_INVALID_LENGTH_MOD_2048 	 159
#define RSAES_PKCS1_OAEP_MGF1_SHA512_ENC_INVALID_LENGTH_MOD_2048 	 127
#define RSAES_PKCS1_V1_5_ENC_INVALID_LENGTH_MOD_2048 	 246

/*ALL_TEE_CRYPTO_INITIALISATION_VECTOR_VALUES*/
static const uint8_t IV1_VALUE_64bits_DES_DES3[] = {
	0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef
};
static const uint8_t IV2_VALUE_128bits_AES[] = {
	0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78,
	0x90, 0xab, 0xcd, 0xef
};
static const uint8_t IV_INVALID_LENGTH_VALUE[] = {
	0x01, 0x02, 0x03, 0x04, 0x05
};

/*ALL_TEE_CRYPTO_INITIALISATION_VECTOR_LENGTHS*/
#define IV_LENGTH_NULL                  0
#define IV_INVALID_LENGTH               5
#define IV1_LENGTH_64bits_DES_DES3      8
#define IV2_LENGTH_128bits_AES          16

static const uint8_t *TEE_ATTR_VALUE_NONE;

/*ALL_TEE_BUFFER_CASES*/
#define INPUT_BUFFER_NORMAL 	 5
#define INPUT_BUFFER_TOO_SHORT 	 4
#define OUTPUT_BUFFER_NORMAL 	 1
#define OUTPUT_BUFFER_TOO_SHORT 	 2
#define TAG_BUFFER_TOO_SHORT 	 3

#define Invoke_Crypto_InitObjectWithKeysExt Invoke_Crypto_InitObjectWithKeys

enum signature_validity {
	INVALID_SIGNATURE = 0,
	VALID_SIGNATURE
};

enum mac_validity {
	INVALID_MAC = 0,
	VALID_MAC
};

struct crypto_buffer {
	uint8_t *buffer;
	uint32_t size;
};

/*Saved in Invoke_Crypto_AllocateOperation*/
struct crypto_op {
	uint32_t algo;
	uint32_t mode;
	uint32_t obj_size;
};
struct crypto_op saved_alloc;

/*Saved in Invoke_Crypto_InitObjectWithKeys*/
struct key_val {
	TEE_ObjectHandle obh;
	uint32_t obj_type;
	uint32_t obj_size;
	struct crypto_buffer key;
};
struct key_val saved_key_vals;

struct obh_val {
	TEE_OperationHandle oph;
	TEE_ObjectHandle obh;
};

/*Saved in Invoke_Crypto_SetOperationKey and Invoke_Crypto_SetOperationKey2*/
struct obh_val2 {
	TEE_OperationHandle oph;
	TEE_ObjectHandle obh1;
	TEE_ObjectHandle obh2;
};
struct obh_val2 saved_obh;

/*Saved in Invoke_Crypto_GetOperationInfo*/
struct op_info_single {
	uint32_t algo;
	uint32_t op_class;
	uint32_t op_mode;
	uint32_t dgst_length;
	uint32_t max_key_size;
	uint32_t key_size;
	uint32_t required_key_usage;
	uint32_t handle_state;
};
struct op_info_single saved_op_info_single;

/*Saved in Invoke_Crypto_GetOperationInfoMultiple*/
struct op_info {
	uint32_t algo;
	uint32_t op_class;
	uint32_t op_mode;
	uint32_t dgst_length;
	uint32_t max_key_size;
	uint32_t handle_state;
	uint32_t op_state;
	uint32_t key_num;
	struct crypto_buffer key;
};
struct op_info saved_op_info;

/*saved by Invoke_Crypto_AEUpdateAAD*/
struct crypto_buffer saved_aad_value;

/*Saved in Invoke_Crypto_AEEncryptFinal*/
struct crypto_buffer ae_encrypt_tag;

/*Saved in Invoke_Crypto_AEUpdate_for_encryption*/
struct crypto_buffer buffer_encrypted_chunks[4];

/*Saved in Invoke_Crypto_AEUpdate_for_Decryption*/
struct crypto_buffer buffer_decrypted_chunks[4];

/*filled with data in Invoke_Crypto_AsymmetricEncrypt*/
struct crypto_buffer buffer_asym_encrypted;

/*saved by Invoke_Crypto_AEInit*/
struct crypto_buffer saved_in_nonce;

/*Saved in Invoke_Crypto_DeriveKey*/
struct obh_val saved_derive;

/*Saved in Invoke_Crypto_GenerateRandom*/
struct crypto_buffer saved_random;

/*Saved in Invoke_Crypto_DigestDoFinal*/
struct crypto_buffer saved_digest;

/*Saved in Invoke_Crypto_MACInit*/
struct crypto_buffer saved_mac_iv;

/*Saved in Invoke_Crypto_CipherInit*/
struct crypto_buffer saved_cipher_iv;

/*Saved in Invoke_Crypto_CipherUpdate*/
struct crypto_buffer saved_cipher_update;


TEEC_UUID UUID_TTA_testingInternalAPI_crypto = {
	0x534D4152, 0x5443, 0x534C,
	{ 0x54, 0x43, 0x52, 0x59, 0x50, 0x54, 0x4F, 0x31 }
};

/* CRYPTO API HELPERS */
uint32_t swap_uint32( uint32_t val );

static void crypto_init(void)
{
	saved_obh.oph = 0;
	saved_obh.obh1 = 0;
	saved_obh.obh2 = 0;
	saved_alloc.algo = 0;
	saved_alloc.mode = 0;
	saved_alloc.obj_size = 0;
	saved_key_vals.obh = 0;
	saved_key_vals.obj_size = 0;
	saved_key_vals.obj_type = 0;
	saved_op_info.algo = 0;
	saved_op_info.op_class = 0;
	saved_op_info.op_mode = 0;
	saved_op_info.dgst_length = 0;
	saved_op_info.max_key_size = 0;
	saved_op_info.handle_state = 0;
	saved_op_info.op_state = 0;
	saved_op_info.key_num = 0;
	CRYPTO_INIT(saved_op_info.key);
	saved_op_info_single.algo = 0;
	saved_op_info_single.op_class = 0;
	saved_op_info_single.op_mode = 0;
	saved_op_info_single.dgst_length = 0;
	saved_op_info_single.max_key_size = 0;
	saved_op_info_single.key_size = 0;
	saved_op_info_single.required_key_usage = 0;
	saved_op_info_single.handle_state = 0;
	CRYPTO_INIT(saved_key_vals.key);
	CRYPTO_INIT(saved_aad_value);
	CRYPTO_INIT(ae_encrypt_tag);
	/*4 chunks*/
	CRYPTO_INIT(buffer_encrypted_chunks[0]);
	CRYPTO_INIT(buffer_encrypted_chunks[1]);
	CRYPTO_INIT(buffer_encrypted_chunks[2]);
	CRYPTO_INIT(buffer_encrypted_chunks[3]);
	/*4 chunks*/
	CRYPTO_INIT(buffer_decrypted_chunks[0]);
	CRYPTO_INIT(buffer_decrypted_chunks[1]);
	CRYPTO_INIT(buffer_decrypted_chunks[2]);
	CRYPTO_INIT(buffer_decrypted_chunks[3]);
	CRYPTO_INIT(buffer_asym_encrypted);
	CRYPTO_INIT(saved_in_nonce);
	saved_derive.oph = 0;
	saved_derive.obh = 0;
	CRYPTO_INIT(saved_random);
	CRYPTO_INIT(saved_digest);
	CRYPTO_INIT(saved_mac_iv);
	CRYPTO_INIT(saved_cipher_iv);
	CRYPTO_INIT(saved_cipher_update);
}

static void crypto_reset(void)
{
	saved_obh.oph = 0;
	saved_obh.obh1 = 0;
	saved_obh.obh2 = 0;
	saved_alloc.algo = 0;
	saved_alloc.mode = 0;
	saved_alloc.obj_size = 0;
	saved_key_vals.obh = 0;
	saved_key_vals.obj_size = 0;
	saved_key_vals.obj_type = 0;
	saved_op_info.algo = 0;
	saved_op_info.op_class = 0;
	saved_op_info.op_mode = 0;
	saved_op_info.dgst_length = 0;
	saved_op_info.max_key_size = 0;
	saved_op_info.handle_state = 0;
	saved_op_info.op_state = 0;
	saved_op_info.key_num = 0;
	CRYPTO_FREE(saved_op_info.key);
	saved_op_info_single.algo = 0;
	saved_op_info_single.op_class = 0;
	saved_op_info_single.op_mode = 0;
	saved_op_info_single.dgst_length = 0;
	saved_op_info_single.max_key_size = 0;
	saved_op_info_single.key_size = 0;
	saved_op_info_single.required_key_usage = 0;
	saved_op_info_single.handle_state = 0;
	CRYPTO_FREE(saved_key_vals.key);

	CRYPTO_FREE(saved_aad_value);
	CRYPTO_FREE(ae_encrypt_tag);
	/*4 chunks*/
	CRYPTO_FREE(buffer_encrypted_chunks[0]);
	CRYPTO_FREE(buffer_encrypted_chunks[1]);
	CRYPTO_FREE(buffer_encrypted_chunks[2]);
	CRYPTO_FREE(buffer_encrypted_chunks[3]);
	/*4 chunks*/
	CRYPTO_FREE(buffer_decrypted_chunks[0]);
	CRYPTO_FREE(buffer_decrypted_chunks[1]);
	CRYPTO_FREE(buffer_decrypted_chunks[2]);
	CRYPTO_FREE(buffer_decrypted_chunks[3]);
	CRYPTO_FREE(buffer_asym_encrypted);
	CRYPTO_FREE(saved_in_nonce);
	saved_derive.oph = 0;
	saved_derive.obh = 0;
	CRYPTO_FREE(saved_random);
	CRYPTO_FREE(saved_digest);
	CRYPTO_FREE(saved_mac_iv);
	CRYPTO_FREE(saved_cipher_iv);
	CRYPTO_FREE(saved_cipher_update);
}

/**
 * Writes 4 byte to @p *data_pp and increases
 * @p *data_pp by 4 byte. The bytes are written
 * in Big Endian Order.
 */
static void put_uint32_be(void **data_pp, uint32_t v)
{
	uint8_t *d = *(uint8_t **)data_pp;
	uint8_t *v_p = (uint8_t *)&v;

	d[3] = v_p[0];
	d[2] = v_p[1];
	d[1] = v_p[2];
	d[0] = v_p[3];
	*((uint8_t **)data_pp) += sizeof(uint32_t);
}

static TEEC_Result calculate_digest(ADBG_Case_t *c, TEEC_Session *s,
				    const void *data, const size_t data_length,
				    struct crypto_buffer *digest);

static TEEC_Result sign_digest(ADBG_Case_t *c, TEEC_Session *s,
			       const struct crypto_buffer *in_dgst,
			       struct crypto_buffer *out_dgst);

static bool verify_digest(ADBG_Case_t *c, TEEC_Session *s,
			  const struct crypto_buffer *in_sdgst);

static TEEC_Result mac_compute_final(ADBG_Case_t *c, TEEC_Session *s,
				     const void *full_data,
				     const size_t fdata_length,
				     struct crypto_buffer *mac);

static TEEC_Result cipher_do_final(ADBG_Case_t *c, TEEC_Session *s,
				   const void *full_data,
				   const size_t fdata_length,
				   struct crypto_buffer *cipher);

static void collapse_crypto_buffers(struct crypto_buffer *in_buffer,
				    struct crypto_buffer *out_buffer)
{
	int id;
	uint8_t *tmp;

	out_buffer->size = 0;

	for (id = 0; id < 4; id++)
		out_buffer->size += in_buffer[id].size;

	out_buffer->buffer = malloc(out_buffer->size);
	tmp = out_buffer->buffer;

	for (id = 0; id < 4; id++) {
		if (in_buffer[id].buffer) {
			memcpy(tmp, in_buffer[id].buffer, in_buffer[id].size);
			tmp += in_buffer[id].size;
		}
	}
}

/*Invoke Crypto Commands Implementations*/
/*CMD_Crypto_AllocateOperation*/
static TEEC_Result Invoke_Crypto_AllocateOperation(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id,
	const uint32_t algo, const uint32_t mode,
	const size_t obj_size1, const size_t obj_size2,
	TEE_OperationHandle *oph)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t max_obj_size = ((obj_size1 < obj_size2) ? obj_size2 : obj_size1);
	(void)c;

	op.params[0].value.a = algo;
	op.params[0].value.b = mode;
	op.params[1].value.a = max_obj_size;
	op.params[3].value.a = (uint32_t)*oph;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_VALUE_INPUT);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Store this information about mode and algorithm
	 * in order to do cryptographic operation later
	 */
	if (res == TEEC_SUCCESS) {
		saved_alloc.algo = algo;
		saved_alloc.mode = mode;
		saved_alloc.obj_size = max_obj_size;
	}

	return res;
}

/*CMD_Crypto_GetOperationInfo*/
static TEEC_Result Invoke_Crypto_GetOperationInfo(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	op.params[0].value.a = (uint32_t)*oph;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_OUTPUT,
					 TEEC_VALUE_OUTPUT, TEEC_VALUE_OUTPUT);

	res =  TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);
	if (res == TEEC_SUCCESS) {
		saved_op_info_single.algo = op.params[0].value.a;
		saved_op_info_single.op_class = op.params[0].value.b;
		saved_op_info_single.op_mode = op.params[1].value.a;
		saved_op_info_single.dgst_length = op.params[1].value.b;
		saved_op_info_single.max_key_size = op.params[2].value.a;
		saved_op_info_single.key_size = op.params[2].value.b;
		saved_op_info_single.required_key_usage = op.params[3].value.a;
		saved_op_info_single.handle_state = op.params[3].value.b;

	}

	return res;
}

static void Check_OperationInfo(ADBG_Case_t *c,
	uint32_t cAlgo, uint32_t cOpClass, uint32_t cOpMode,
	uint32_t cDgstLength, uint32_t cMaxKeySize1, uint32_t cMaxKeySize2,
	uint32_t cKeySize, uint32_t cUsage, uint32_t cHandleState)
{
	uint32_t maxKeySize = ((cMaxKeySize1 < cMaxKeySize2) ? cMaxKeySize2 : cMaxKeySize1);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cAlgo, ==,
		saved_op_info_single.algo);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cOpClass, ==,
		saved_op_info_single.op_class);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cOpMode, ==,
		saved_op_info_single.op_mode);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cDgstLength, ==,
		saved_op_info_single.dgst_length);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, maxKeySize, ==,
		saved_op_info_single.max_key_size);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cKeySize, ==,
		saved_op_info_single.key_size);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cUsage, ==,
		saved_op_info_single.required_key_usage);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cHandleState, ==,
		saved_op_info_single.handle_state);
}

/* CMD_Crypto_TTAEnsureIntermediateBufferSize */
static TEEC_Result Invoke_Crypto_EnsureIntermediateBufferSize(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, uint32_t size)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	op.params[0].value.a = size;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);
}

#ifdef WITH_GP_TESTS
/*CMD_Crypto_GetOperationInfoMultiple*/
static TEEC_Result Invoke_Crypto_GetOperationInfoMultiple(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph, uint32_t max_key_num)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	uint32_t i;

	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM01, 64,
			       TEEC_MEM_OUTPUT, mem01_exit);

	op.params[0].value.a = (uint32_t)*oph;
	op.params[0].value.b = max_key_num;

	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		uint32_t *extract = (uint32_t *)op.params[1].memref.parent->buffer;
		uint32_t *keys = NULL;
		uint32_t key_size;

		saved_op_info.algo = swap_uint32(*extract++);
		saved_op_info.op_class = swap_uint32(*extract++);
		saved_op_info.op_mode = swap_uint32(*extract++);
		saved_op_info.dgst_length = swap_uint32(*extract++);
		saved_op_info.max_key_size = swap_uint32(*extract++);
		saved_op_info.handle_state = swap_uint32(*extract++);
		saved_op_info.op_state = swap_uint32(*extract++);
		saved_op_info.key_num = swap_uint32(*extract++);

		key_size = 2 * saved_op_info.key_num * sizeof(uint32_t);
		CRYPTO_SAFE_MALLOC(saved_op_info.key, key_size);

		ADBG_EXPECT_NOT_NULL(c, (void *)saved_op_info.key.buffer);
		keys = (void *)saved_op_info.key.buffer;

		for(i = 0; i < saved_op_info.key_num; i++) {
			*keys++ = swap_uint32(*extract++); // keySize
			*keys++ = swap_uint32(*extract++); // requiredKeyUsage
		}
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM01);

mem01_exit:
	return res;
}

static void Check_0_OperationInfoMultiple(ADBG_Case_t *c,
	uint32_t cAlgo, uint32_t cOpClass, uint32_t cOpMode,
	uint32_t cDgstLength, uint32_t cMaxKeySize1, uint32_t cMaxKeySize2,
	uint32_t cHandleState, uint32_t cOpState, uint32_t cKeyNum)
{
	uint32_t maxKeySize = ((cMaxKeySize1 < cMaxKeySize2) ? cMaxKeySize2 : cMaxKeySize1);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cAlgo, ==,
		saved_op_info.algo);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cOpClass, ==,
		saved_op_info.op_class);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cOpMode, ==,
		saved_op_info.op_mode);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cDgstLength, ==,
		saved_op_info.dgst_length);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, maxKeySize, ==,
		saved_op_info.max_key_size);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cHandleState, ==,
		saved_op_info.handle_state);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cOpState, ==,
		saved_op_info.op_state);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cKeyNum, ==,
		saved_op_info.key_num);
}

static void Check_1_OperationInfoKey(ADBG_Case_t *c,
	uint32_t key_index, uint32_t key_size, uint32_t key_usage)
{
	uint32_t *saved_key_info = (void *)(saved_op_info.key.buffer + key_index * 2 * sizeof(uint32_t));
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, *saved_key_info, ==, key_size);
	saved_key_info++;
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, *saved_key_info, ==, key_usage);
}
#endif

/*CMD_Crypto_ResetOperation*/
static TEEC_Result Invoke_Crypto_ResetOperation(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	op.params[0].value.a = (uint32_t)*oph;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	return res;
}

/*CMD_Crypto_FreeAllKeysAndOperations*/
static TEEC_Result Invoke_Crypto_FreeAllKeysAndOperations(
	ADBG_Case_t *c,
	TEEC_Session *s,
	uint32_t cmd_id,
	TEE_OperationHandle *oph)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	op.params[0].value.a = (uint32_t)*oph;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	return res;
}

/*CMD_Crypto_InitObjectWithKeys*/
static TEEC_Result Invoke_Crypto_InitObjectWithKeys(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, const uint32_t obj_type, const uint32_t obj_size,
	const uint32_t attributeId_1, const void *attribValue_1,
	const uint32_t attribSize_1,
	const uint32_t attributeId_2, const void *attribValue_2,
	const uint32_t attribSize_2,
	const uint32_t attributeId_3, const void *attribValue_3,
	const uint32_t attribSize_3,
	const uint32_t attributeId_4, const void *attribValue_4,
	const uint32_t attribSize_4,
	const uint32_t attributeId_5, const void *attribValue_5,
	const uint32_t attribSize_5,
	TEE_ObjectHandle *obh)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	void *tmp_buf1 = NULL;
	uint8_t *tmp_buf2 = NULL;
	int tmp_offset = 0;
	(void)c;

	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM01, big_size,
			       TEEC_MEM_INPUT, mem01_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM02, DS_BIG_SIZE,
			       TEEC_MEM_INPUT, mem02_exit);

	/* Serialize the data in format:
	 * SHARE_MEM01 = (uint32_t)attr_id1|(uint32_t)attr_val1_offset
	 * in SHARE_MEM02|(uint32_t)attr_val1_length
	 * Add 0 for all three if attr_idX = TEE_ATTR_NONE
	 */
	/* Serialize the data in format:
	 * SHARE_MEM02 = attr_val1|attr_val2|attr_val3|attr_val4|attr_val5.
	 * Do not add anything if attr_valX == TEE_ATTR_VALUE_NONE.
	 */

	tmp_buf1 = SHARE_MEM01->buffer;
	tmp_buf2 = (uint8_t *)SHARE_MEM02->buffer;
	put_uint32_be(&tmp_buf1, attributeId_1);

	if (TEE_ATTR_NONE != attributeId_1) {
		put_uint32_be(&tmp_buf1, tmp_offset);
		put_uint32_be(&tmp_buf1, attribSize_1);
		memcpy(tmp_buf2, attribValue_1, (size_t)attribSize_1);
		tmp_buf2 += attribSize_1;
		tmp_offset += attribSize_1;
	} else {
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
	}

	put_uint32_be(&tmp_buf1, attributeId_2);

	if (TEE_ATTR_NONE != attributeId_2) {
		put_uint32_be(&tmp_buf1, tmp_offset);
		put_uint32_be(&tmp_buf1, attribSize_2);
		memcpy(tmp_buf2, attribValue_2, (size_t)attribSize_2);
		tmp_buf2 += attribSize_2;
		tmp_offset += attribSize_2;
	} else {
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
	}

	put_uint32_be(&tmp_buf1, attributeId_3);

	if (TEE_ATTR_NONE != attributeId_3) {
		put_uint32_be(&tmp_buf1, tmp_offset);
		put_uint32_be(&tmp_buf1, attribSize_3);
		memcpy(tmp_buf2, attribValue_3, (size_t)attribSize_3);
		tmp_buf2 += attribSize_3;
		tmp_offset += attribSize_3;
	} else {
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
	}

	put_uint32_be(&tmp_buf1, attributeId_4);

	if (TEE_ATTR_NONE != attributeId_4) {
		put_uint32_be(&tmp_buf1, tmp_offset);
		put_uint32_be(&tmp_buf1, attribSize_4);
		memcpy(tmp_buf2, attribValue_4, (size_t)attribSize_4);
		tmp_buf2 += attribSize_4;
		tmp_offset += attribSize_4;
	} else {
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
	}

	put_uint32_be(&tmp_buf1, attributeId_5);

	if (TEE_ATTR_NONE != attributeId_5) {
		put_uint32_be(&tmp_buf1, tmp_offset);
		put_uint32_be(&tmp_buf1, attribSize_5);
		memcpy(tmp_buf2, attribValue_5, (size_t)attribSize_5);
		tmp_buf2 += attribSize_5;
		tmp_offset += attribSize_5;
	} else {
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
	}

	op.params[0].value.a = obj_type;
	op.params[0].value.b = obj_size;
	/* 5 attributes
	 * 12 bytes = 4 attr_id + 4 attr_offset + 4 attr_length
	 */
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01, 60);
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02, tmp_offset);
	op.params[3].value.a = (uint32_t)*obh;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_VALUE_INPUT);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Store the key values associated with ObjectHandle in
	 * order to perform cryptographic computation later
	 */
	if (res == TEEC_SUCCESS) {
		saved_key_vals.obj_type = obj_type;
		saved_key_vals.obj_size = obj_size;
		saved_key_vals.obh = *obh;

		CRYPTO_SAFE_MALLOC(saved_key_vals.key, tmp_offset);
		memcpy(saved_key_vals.key.buffer, SHARE_MEM02->buffer,
		       tmp_offset);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_Crypto_SetOperationKey*/
static TEEC_Result Invoke_Crypto_SetOperationKey(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph, TEE_ObjectHandle *obh)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	op.params[0].value.a = (uint32_t)*oph;
	op.params[0].value.b = (uint32_t)*obh;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* store the information about which key object handle are associated
	 * with Operation Handle in order to perform cryptographic
	 * computation later
	 */
	if (res == TEEC_SUCCESS) {
		saved_obh.oph = *oph;
		saved_obh.obh1 = *obh;
		saved_obh.obh2 = TEE_HANDLE_NULL;
	}

	return res;
}

/*CMD_Crypto_SetOperationKey2*/
static TEEC_Result Invoke_Crypto_SetOperationKey2(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	TEE_ObjectHandle *obh1, TEE_ObjectHandle *obh2)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	op.params[0].value.a = (uint32_t)*oph;
	op.params[0].value.b = (uint32_t)*obh1;
	op.params[1].value.a = (uint32_t)*obh2;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Store the information about which key object handles are associated
	 * with Operation Handle in order to perform cryptographic
	 * computation later
	 */
	if (res == TEEC_SUCCESS) {
		saved_obh.oph = *oph;
		saved_obh.obh1 = *obh1;
		saved_obh.obh2 = *obh2;
	}

	return res;
}

/*CMD_Crypto_DeriveKey*/
static TEEC_Result Invoke_Crypto_DeriveKey(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	struct attr_list_node *attributeList,
	TEE_ObjectHandle *obh)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	op.params[0].value.a = (uint32_t)*oph;
	op.params[0].value.b = (uint32_t)*obh;
	op.params[1].value.a = ATTR_NONE;
	op.params[1].value.b = ATTR_NONE;

	if (!is_attr_list_empty(attributeList)) {
		op.params[1].value.a = attributeList->attr_idx;
		if (attributeList->next)
			op.params[1].value.b = attributeList->next->attr_idx;
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Save the fact that the object has been derived for later
	 * cryptographic computation
	 */
	if (res == TEEC_SUCCESS) {
		saved_derive.oph = *oph;
		saved_derive.obh = *obh;
	}

	return res;
}

/*CMD_Crypto_AEInit*/
static TEEC_Result Invoke_Crypto_AEInit(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *nonce_val, const size_t nonce_length,
	const size_t in_tag_len, const size_t in_aad_len,
	const size_t in_payload_len)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01, nonce_length,
					TEEC_MEM_INPUT, nonce_length,
					nonce_val, mem01_exit);

	op.params[0].value.a = (uint32_t)*oph;
	op.params[0].value.b = in_tag_len;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);
	op.params[2].value.a = in_aad_len;
	op.params[2].value.b = in_payload_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Save the $IN_nonce$ for later computation of encryptedData
	 */
	if (res == TEEC_SUCCESS) {
		CRYPTO_SAFE_MALLOC(saved_in_nonce, nonce_length);
		memcpy(saved_in_nonce.buffer, nonce_val, nonce_length);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_Crypto_AEUpdate*/
static TEEC_Result Invoke_Crypto_AEUpdate_for_encryption(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length,
	const uint32_t case_buf, const uint32_t chunk_id)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;

	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM02, DS_BIG_SIZE,
			       TEEC_MEM_OUTPUT, mem02_exit);

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);
	/*if $IN_caseBuffer$ = OUTPUT_BUFFER_TOO_SHORT(2)
		then Param[3].memref.size=1  */
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1);
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size);
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Store the buffer from "shm2" in
	 * "buffer_encrypted_chunks[$IN_chunkNumber$]"
	 * which will be reused for the
	 * Invoke_Crypto_TEE_AEUpdate_for_decryption function
	 */
	if (res == TEEC_SUCCESS) {
		CRYPTO_SAFE_MALLOC(buffer_encrypted_chunks[chunk_id],
			op.params[3].memref.size);
		memcpy(buffer_encrypted_chunks[chunk_id].buffer,
		       SHARE_MEM02->buffer,
		       buffer_encrypted_chunks[chunk_id].size);
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
					     op.params[3].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}
/*CMD_Crypto_AEUpdate*/

static TEEC_Result Invoke_Crypto_AEUpdate_for_decryption(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length,
	const uint32_t case_buf, const uint32_t chunk_id)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)part_data;
	(void)c;

	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01,
					buffer_encrypted_chunks[chunk_id].size,
					TEEC_MEM_INPUT,
					buffer_encrypted_chunks[chunk_id].size,
					buffer_encrypted_chunks[chunk_id].
						buffer, mem01_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM02, partd_length,
			       TEEC_MEM_OUTPUT, mem02_exit);

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01, partd_length);
	/*if $IN_caseBuffer$ = OUTPUT_BUFFER_TOO_SHORT(2)
		then Param[3].memref.size=1*/
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1);
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size);
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Save the buffer from "SharedMem2" into
	 * "buffer_decrypted_chunks[$IN_chunkNumber$]"
	 * in order to collapse all buffers returned for
	 * AEUpdate_for_decryption,
	 * which will be used in AEDecryptFinal
	 */
	if (res == TEEC_SUCCESS) {
		CRYPTO_SAFE_MALLOC(buffer_decrypted_chunks[chunk_id],
				op.params[3].memref.size);
		memcpy(buffer_decrypted_chunks[chunk_id].buffer,
		       SHARE_MEM02->buffer,
		       buffer_decrypted_chunks[chunk_id].size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_Crypto_AEUpdateAAD*/
static TEEC_Result Invoke_Crypto_AEUpdateAAD(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *aad_data, const size_t aad_length)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01, aad_length,
					TEEC_MEM_INPUT, aad_length,
					aad_data, mem01_exit);

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Save the $IN_AAD_Value$ for AAD for later cryptographic computation
	 */
	if (res == TEEC_SUCCESS) {
		CRYPTO_SAFE_MALLOC(saved_aad_value, aad_length);
		memcpy(saved_aad_value.buffer, aad_data, aad_length);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_Crypto_AEEncryptFinal*/
static TEEC_Result Invoke_Crypto_AEEncryptFinal(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length,
	const void *full_data, const size_t fdata_length,
	uint32_t case_buf, uint32_t chunk_id)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_partd_size, initial_fdata_size;
	(void)full_data;

	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM02, fdata_length,
			       TEEC_MEM_OUTPUT, mem02_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM03, partd_length,
			       TEEC_MEM_OUTPUT, mem03_exit);

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);
	switch (case_buf) {
	case OUTPUT_BUFFER_TOO_SHORT:
		/*if $IN_caseBuffer$ =
			OUTPUT_BUFFER_TOO_SHORT(2) then Param[3].memref.size=1*/
		SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM03,
						      SHARE_MEM03->size);
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1);
		break;
	case TAG_BUFFER_TOO_SHORT:
		/*if $IN_caseBuffer$ =
			TAG_BUFFER_TOO_SHORT then Param[2].memref.size = 1*/
		SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM03, 1);
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size);
		break;
	case OUTPUT_BUFFER_NORMAL:
	default:
		SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM03,
						      SHARE_MEM03->size);
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size);
		break;
	}
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_partd_size = op.params[2].memref.size;
	initial_fdata_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		/* Store the buffer from "shm2" in
		 * "buffer_encrypted_chunks[$IN_chunkNumber$]"
		 * which will be reused for
		 * the Invoke_Crypto_TEE_AEDecryptFinal function
		 */
		CRYPTO_SAFE_MALLOC(buffer_encrypted_chunks[chunk_id],
				op.params[3].memref.size);
		memcpy(buffer_encrypted_chunks[chunk_id].buffer,
		       SHARE_MEM02->buffer,
		       buffer_encrypted_chunks[chunk_id].size);

		/* Store the tag from "SharedMem3" which will be reused for the
		 * Invoke_Crypto_TEE_AEDecryptFinal function
		 */
		CRYPTO_SAFE_MALLOC(ae_encrypt_tag,
				op.params[2].memref.size);
		memcpy(ae_encrypt_tag.buffer, SHARE_MEM03->buffer,
		       ae_encrypt_tag.size);
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		if (initial_partd_size == op.params[2].memref.size)
			ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_fdata_size, <,
						     op.params[3].memref.size);
		else
			ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_partd_size, <,
						     op.params[2].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM03);
mem03_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_Crypto_AEDecryptFinal*/
static TEEC_Result Invoke_Crypto_AEDecryptFinal(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length,
	const void *full_data, const size_t fdata_length,
	const uint32_t case_buf, const enum mac_validity mac_case,
	const uint32_t chunk_id)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;
	(void)part_data;

	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01,
					buffer_encrypted_chunks[chunk_id].size,
					TEEC_MEM_INPUT,
					buffer_encrypted_chunks[chunk_id].size,
					buffer_encrypted_chunks[chunk_id].
						buffer, mem01_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM02, partd_length,
			       TEEC_MEM_OUTPUT, mem02_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM03, ae_encrypt_tag.size,
			       TEEC_MEM_INPUT, mem03_exit);
	/* Fill "SharedMem3" with the tag previously
	 * saved in Invoke_Crypto_AEEncryptFinal
	 * (with an error (one bit changed) if $IN_caseMac$ = INVALID_MAC)
	 */
	if (ae_encrypt_tag.buffer != NULL) {
		memcpy(SHARE_MEM03->buffer, ae_encrypt_tag.buffer,
		       ae_encrypt_tag.size);

		if (mac_case == INVALID_MAC)
			BIT_CHANGE(*(uint32_t *)SHARE_MEM03->buffer, 4);
	}

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM03,
					      SHARE_MEM03->size);
	/*if $IN_caseBuffer$ = OUTPUT_BUFFER_TOO_SHORT(2)
		then Param[3].memref.size=1*/
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1);
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size);
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		/* Save the buffer from "SharedMem2" to
		 * "buffer_decrypted_chunks[$IN_chunkNumber$]"
		 */
		CRYPTO_SAFE_MALLOC(buffer_decrypted_chunks[chunk_id],
				op.params[3].memref.size);
		memcpy(buffer_decrypted_chunks[chunk_id].buffer,
		       SHARE_MEM02->buffer,
		       buffer_decrypted_chunks[chunk_id].size);

		/* Compare the data in clear $IN_fullDataValue$ and with
		 * collapsed buffers from table
		 * "buffer_decrypted_chunks" and check they are equals
		 */
		struct crypto_buffer collapsed;
		CRYPTO_INIT(collapsed);
		collapse_crypto_buffers(buffer_decrypted_chunks, &collapsed);
		ADBG_EXPECT_BUFFER(c, full_data, fdata_length, collapsed.buffer,
				   collapsed.size);
		CRYPTO_FREE(collapsed);
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
					     op.params[3].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM03);
mem03_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_Crypto_GenerateRandom*/
static TEEC_Result Invoke_Crypto_GenerateRandom(ADBG_Case_t *c, TEEC_Session *s,
						const uint32_t cmd_id)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM01, big_size,
			       TEEC_MEM_OUTPUT, mem01_exit);

	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM01,
					      SHARE_MEM01->size);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Check that the buffer shm1 is not empty
	 * + Check that this random value is
	 * different of a previous call of this command
	 */
	if (res == TEEC_SUCCESS) {
		if (ADBG_EXPECT_COMPARE_SIGNED(c, 0, !=,
					       op.params[3].memref.size)) {
			if (saved_random.buffer != NULL) {
				(void)ADBG_EXPECT_COMPARE_SIGNED(c, 0, !=,
					memcmp(SHARE_MEM01->buffer,
						saved_random.buffer,
						op.params[3].memref.size));
			}

			CRYPTO_SAFE_MALLOC(saved_random, op.params[3].memref.size);
			memcpy(saved_random.buffer, SHARE_MEM01->buffer,
			       saved_random.size);
		}
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_Crypto_DigestUpdate*/
static TEEC_Result Invoke_Crypto_DigestUpdate(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit);

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_Crypto_DigestDoFinal*/
static TEEC_Result Invoke_Crypto_DigestDoFinal(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length,
	const void *full_data, const size_t fdata_length,
	const uint32_t case_buf)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;

	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM02, fdata_length,
			       TEEC_MEM_OUTPUT, mem02_exit);

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1);
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size);
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		/* Compute the hash of $IN_fullDataValue$
		 * and compare it to "shm2"
		 */
		struct crypto_buffer tmp_dgst;
		CRYPTO_INIT(tmp_dgst);
		ADBG_EXPECT_TEEC_SUCCESS(c, res =
						 calculate_digest(c, s,
								  full_data,
								  fdata_length,
								  &tmp_dgst));
		ADBG_EXPECT_BUFFER(c, tmp_dgst.buffer, tmp_dgst.size,
				   SHARE_MEM02->buffer, tmp_dgst.size);
		CRYPTO_FREE(tmp_dgst);

		/* Store the Digest value which can be reused for a next call to
		 * TEE_AsymmetricSignDigest or TEE_AsymmetricVerifyDigest
		 */
		CRYPTO_SAFE_MALLOC(saved_digest,
				op.params[3].memref.size);
		memcpy(saved_digest.buffer, SHARE_MEM02->buffer,
		       saved_digest.size);
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
					     op.params[3].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_Crypto_AsymmetricSignDigest*/
static TEEC_Result Invoke_Crypto_AsymmetricSignDigest(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *full_data, const size_t fdata_length, uint32_t case_buf)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;
	(void)full_data;
	(void)fdata_length;

	/* Fill SharedMem1 with the previously stored Digest
		value after TEE_DigestDoFinal */
	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01, saved_digest.size,
					TEEC_MEM_INPUT,
					saved_digest.size, saved_digest.buffer, mem01_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM02, 512,
			       TEEC_MEM_OUTPUT, mem02_exit);

	op.params[0].value.a = (uint32_t)*oph;

	/*if $IN_caseBuffer$ = INPUT_BUFFER_TOO_SHORT then set
		Param[1].memref.size to the size of "SharedMem1" minus one.*/
	if (case_buf == INPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
						      SHARE_MEM01->size - 1);
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
						      SHARE_MEM01->size);
	}

	/*if $IN_caseBuffer$ = OUTPUT_BUFFER_TOO_SHORT(2)
		then Param[3].memref.size=1*/
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1);
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size);
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		/* Compute a Verify_Signature of the signature
		 * store under "SharedMem2"
		 */
		struct crypto_buffer s_dgst;
		CRYPTO_INIT(s_dgst);
		CRYPTO_MALLOC(s_dgst, op.params[3].memref.size);
		memcpy(s_dgst.buffer, SHARE_MEM02->buffer, s_dgst.size);
		ADBG_EXPECT(c, true, verify_digest(c, s, &s_dgst));
		CRYPTO_FREE(s_dgst);
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
					     op.params[3].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_Crypto_AsymmetricVerifyDigest*/
static TEEC_Result Invoke_Crypto_AsymmetricVerifyDigest(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *full_data, const size_t fdata_length,
	const uint32_t case_digest, const uint32_t valid_sig)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)full_data;
	(void)fdata_length;
	struct crypto_buffer signed_dgst;

	CRYPTO_INIT(signed_dgst);
	/* ignore failure as some test cases intentionally cause failure */
	(void)sign_digest(c, s, &saved_digest, &signed_dgst);

	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01, saved_digest.size,
					TEEC_MEM_INPUT,
					saved_digest.size, saved_digest.buffer, mem01_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM02, 512,
			       TEEC_MEM_INPUT, mem02_exit);

	/* Fill "SharedMem2" with the valid computed signature based on
	 * the previously stored Digest value after TEE_DigestDoFinal
	 */
	if ((signed_dgst.buffer != NULL) &&
			(signed_dgst.size <= SHARE_MEM02->size)) {
		memcpy(SHARE_MEM02->buffer, signed_dgst.buffer,
		       signed_dgst.size);
		SHARE_MEM02->size = signed_dgst.size;

		if (valid_sig != VALID_SIGNATURE) {
			/*make it invalid*/
			BIT_CHANGE(*(uint32_t *)SHARE_MEM02->buffer, 4);
		}
	}
	CRYPTO_FREE(signed_dgst);

	op.params[0].value.a = (uint32_t)*oph;

	/*if $IN_caseBuffer$ = INPUT_BUFFER_TOO_SHORT then set
		Param[1].memref.size to the size of "SharedMem1" minus one.*/
	if (case_digest == INPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
						      SHARE_MEM01->size - 1);
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
						      SHARE_MEM01->size);
	}

	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
					      SHARE_MEM02->size);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_MEMREF_PARTIAL_INPUT);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_Crypto_AsymmetricEncrypt*/
static TEEC_Result Invoke_Crypto_AsymmetricEncrypt(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const uint8_t *full_data, const size_t fdata_length, uint32_t case_buf)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;

	/* Fill SharedMem1 with full_data */
	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01, fdata_length,
					TEEC_MEM_INPUT, fdata_length,
					full_data, mem01_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM02, 512,
			       TEEC_MEM_OUTPUT, mem02_exit);

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);
	/*if $IN_caseBuffer$ = OUTPUT_BUFFER_TOO_SHORT(2)
		then Param[3].memref.size=1*/
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1);
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size);
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		/* Check that "SharedMem2" is not empty
		 * Store the value from "SharedMem2" to a
		 * "buffer_asym_encrypted",
		 * which will be reused in Invoke_Crypto_AsymmetricDecrypt
		 */
		if (ADBG_EXPECT_COMPARE_SIGNED(c, 0, !=,
					       op.params[3].memref.size)) {
			CRYPTO_SAFE_MALLOC(buffer_asym_encrypted,
					op.params[3].memref.size);
			memcpy(buffer_asym_encrypted.buffer,
			       SHARE_MEM02->buffer, buffer_asym_encrypted.size);
		}
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
					     op.params[3].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_Crypto_AsymmetricDecrypt*/
static TEEC_Result Invoke_Crypto_AsymmetricDecrypt(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *full_data, const size_t fdata_length, uint32_t case_buf,
	uint32_t nopad)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;
	char *expected_res;
	size_t expected_size;

	/* Fill SharedMem1 with buffer_asym_encrypted */
	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01,
					buffer_asym_encrypted.size,
					TEEC_MEM_INPUT,
					buffer_asym_encrypted.size,
					buffer_asym_encrypted.buffer, mem01_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM02, 512,
			       TEEC_MEM_OUTPUT, mem02_exit);

	op.params[0].value.a = (uint32_t)*oph;

	/*if $IN_caseBuffer$ = INPUT_BUFFER_TOO_SHORT then set
		Param[1].memref.size to the size of "SharedMem1" minus one.*/
	if (case_buf == INPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
						      SHARE_MEM01->size - 1);
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
						      SHARE_MEM01->size);
	}

	/*if $IN_caseBuffer$ = OUTPUT_BUFFER_TOO_SHORT(2)
		then Param[3].memref.size=1*/
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1);
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size);
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	expected_res = (char *)full_data;
	expected_size =  fdata_length;
	if (nopad) {
		/*
		 * According to GP 1.1, no pad encrypting TEE_ALG_RSA_NOPAD
		 * follows "PKCS #1 (RSA primitive)", as stated in
		 * ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf
		 * Page 10, it is stated that RSA primitives RSAEP and RSADP
		 * outputs "an integer between 0 and n-1". Hence the
		 * leading 0s must not be taken into account when checking
		 * the reference
		 */
		while (expected_size && expected_res[0] == 0) {
			expected_size--;
			expected_res++;
		}
	}

	if (res == TEEC_SUCCESS) {
		/* Compare the clear data in
		 * $IN_fullDataValue$ with "SharedMem2"
		 * and check they are equal
		 */
		ADBG_EXPECT_BUFFER(c, expected_res, expected_size,
				   SHARE_MEM02->buffer,
				   op.params[3].memref.size);
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
					     op.params[3].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_Crypto_CopyOperation*/
static TEEC_Result Invoke_Crypto_CopyOperation(
	ADBG_Case_t *c, TEEC_Session *s, const uint32_t cmd_id,
	TEE_OperationHandle *dst_oph, TEE_OperationHandle *src_oph)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	op.params[0].value.a = (uint32_t)*dst_oph;
	op.params[0].value.b = (uint32_t)*src_oph;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	return res;
}

/*CMD_Crypto_MACInit*/
static TEEC_Result Invoke_Crypto_MACInit(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *iv, const size_t iv_len)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM06, iv_len,
					TEEC_MEM_INPUT, iv_len, iv, mem06_exit);

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM06, iv_len);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* save the $IN_InitialisationVector$ for
	 * later computation of encryptedData
	 */
	if (iv_len != 0) {
		CRYPTO_SAFE_MALLOC(saved_mac_iv, iv_len);
		memcpy(saved_mac_iv.buffer, iv, iv_len);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM06);
mem06_exit:
	return res;
}

/*CMD_Crypto_MACUpdate*/
static TEEC_Result Invoke_Crypto_MACUpdate(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit);

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_Crypto_MACCompareFinal*/
static TEEC_Result Invoke_Crypto_MACCompareFinal(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length,
	const void *full_data, const size_t fdata_length,
	enum mac_validity mac_case)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	/* Fill SharedMem1 with part_data */
	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM02, fdata_length,
			       TEEC_MEM_INPUT, mem02_exit);

	/* Fill SharedMem2 with valid computed MAC of full_data */
	struct crypto_buffer mac;

	CRYPTO_INIT(mac);
	mac_compute_final(c, s, full_data, fdata_length, &mac);

	if ((mac.buffer != NULL) && (mac.size <= SHARE_MEM02->size)) {
		memcpy(SHARE_MEM02->buffer, mac.buffer, mac.size);
		SHARE_MEM02->size = mac.size;

		if (mac_case != VALID_MAC) {
			/* change one bit from the valid
				MAC to make it invalid. */
			BIT_CHANGE(*(uint32_t *)SHARE_MEM02->buffer, 4);
		}
	}
	CRYPTO_FREE(mac);

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_Crypto_MACComputeFinal*/
static TEEC_Result Invoke_Crypto_MACComputeFinal(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length,
	const void *full_data, const size_t fdata_length, uint32_t case_buf)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;

	/* Fill SharedMem1 with part_data */
	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM02, fdata_length,
			       TEEC_MEM_OUTPUT, mem02_exit);

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1);
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size);
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Compute the MAC of $IN_fullDataValue$ and
		compare it to "SharedMem2" */
	if (res == TEEC_SUCCESS) {
		struct crypto_buffer tmp_mac;
		CRYPTO_INIT(tmp_mac);
		ADBG_EXPECT_TEEC_SUCCESS(c, res =
						 mac_compute_final(c, s,
								   full_data,
								   fdata_length,
								   &tmp_mac));

		if (res != TEEC_SUCCESS)
			goto exit;

		ADBG_EXPECT_COMPARE_SIGNED(c, 0, ==,
					   memcmp(SHARE_MEM02->buffer,
						  tmp_mac.buffer,
						  op.params[3].memref.size));
		CRYPTO_FREE(tmp_mac);
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
					     op.params[3].memref.size);
	}

exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_Crypto_CipherInit*/
static TEEC_Result Invoke_Crypto_CipherInit(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *iv, const size_t iv_len)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01, iv_len,
					TEEC_MEM_INPUT, iv_len, iv, mem01_exit);

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		/* Save the $IN_InitialisationVector$ for later
		 * computation of encryptedData
		 */
		if (iv != NULL) {
			CRYPTO_SAFE_MALLOC(saved_cipher_iv, iv_len);
			memcpy(saved_cipher_iv.buffer, iv, iv_len);
		}
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	CRYPTO_FREE(saved_cipher_update);
	return res;
}
/*CMD_Crypto_CipherUpdate*/
static TEEC_Result Invoke_Crypto_CipherUpdate(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, uint32_t partd_length,
	uint32_t case_buf)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;

	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM02, partd_length,
			       TEEC_MEM_OUTPUT, mem02_exit);

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);
	/*if $IN_caseBuffer$ = OUTPUT_BUFFER_TOO_SHORT(2)
		then Param[3].memref.size=1*/
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1);
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size);
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		/* Save the buffer returned in "SharedMem2" in order
		 * to collapse all buffers returned for CipherUpdate,
		 * which will be used in CipherDoFinal
		 */
		if (op.params[3].memref.size != 0) {
			void *tmp = realloc(saved_cipher_update.buffer,
					    saved_cipher_update.size +
					    op.params[3].memref.size);
			saved_cipher_update.buffer = tmp;
			memcpy(
				saved_cipher_update.buffer +
				saved_cipher_update.size, SHARE_MEM02->buffer,
				op.params[3].memref.size);
			saved_cipher_update.size += op.params[3].memref.size;
		}
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
					     op.params[3].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_Crypto_CipherDoFinal*/
static TEEC_Result Invoke_Crypto_CipherDoFinal(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length,
	const void *full_data, const size_t fulld_length, uint32_t case_buf)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;

	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit);
	/* used fulld_length instead of partd_length as
		described in the Adaptation layer specification.*/
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM02, fulld_length,
			       TEEC_MEM_OUTPUT, mem02_exit);

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);
	/*if $IN_caseBuffer$ = OUTPUT_BUFFER_TOO_SHORT(2)
		then Param[3].memref.size=1*/
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1);
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size);
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		/* Append the buffer returned in "SharedMem2"
		 * to the previously buffers
		 * returned for CipherUpdate => "collapsed_buffers"
		 */
		if (op.params[3].memref.size != 0) {
			void *tmp = realloc(saved_cipher_update.buffer,
					    saved_cipher_update.size +
					    op.params[3].memref.size);
			saved_cipher_update.buffer = tmp;
			memcpy(
				saved_cipher_update.buffer +
				saved_cipher_update.size, SHARE_MEM02->buffer,
				op.params[3].memref.size);
			saved_cipher_update.size += op.params[3].memref.size;
		}

		/* Compute the ciphered data of
		 * $IN_fullDataValue$ and compare it
		 * to "collapsed_buffers"
		 */
		struct crypto_buffer full_ciphered_data;
		CRYPTO_INIT(full_ciphered_data);
		ADBG_EXPECT_TEEC_SUCCESS(c, res =
						 cipher_do_final(c, s,
							full_data,
							fulld_length,
							&
							full_ciphered_data));

		if (res == TEEC_SUCCESS) {
			ADBG_EXPECT_BUFFER(c, full_ciphered_data.buffer,
					   full_ciphered_data.size,
					   saved_cipher_update.buffer,
					   saved_cipher_update.size);
		} else if (res == TEEC_ERROR_SHORT_BUFFER) {
			ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
						     op.params[3].memref.size);
		}

		CRYPTO_FREE(full_ciphered_data);
		CRYPTO_FREE(saved_cipher_update);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result calculate_digest(
	ADBG_Case_t *c, TEEC_Session *s,
	const void *data, const size_t data_length,
	struct crypto_buffer *digest)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEE_OperationHandle op1 = (TEE_OperationHandle)3;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	res = Invoke_Crypto_AllocateOperation(c, s, CMD_Crypto_AllocateOperation,
					      saved_alloc.algo, TEE_MODE_DIGEST,
					      saved_alloc.obj_size, 0, &op1);

	if (res != TEEC_SUCCESS)
		goto exit;

	/*CMD_Crypto_DigestDoFinal*/
	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM04, data_length,
					TEEC_MEM_INPUT, data_length,
					data, mem04_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM05, data_length,
			       TEEC_MEM_OUTPUT, mem05_exit);

	op.params[0].value.a = (uint32_t)op1;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM04,
					      SHARE_MEM04->size);
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM05,
					      SHARE_MEM05->size);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(s, CMD_Crypto_DigestDoFinal, &op, &ret_orig);

	if (SHARE_MEM05->size != 0 && res == TEEC_SUCCESS) {
		CRYPTO_SAFE_MALLOC(*digest, op.params[3].memref.size);
		memcpy(digest->buffer, SHARE_MEM05->buffer,
		       op.params[3].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM05);
mem05_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM04);
mem04_exit:
	Invoke_Crypto_FreeAllKeysAndOperations(c, s, CMD_Crypto_FreeAllKeysAndOperations, &op1);
exit:
	return res;
}

static TEEC_Result make_keypair_from_publickey(
	ADBG_Case_t *c, TEEC_Session *s, TEE_ObjectHandle *keypair)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;

	if (*keypair != saved_key_vals.obh)
		return res;

	/* validate the saved key type */
	switch (saved_alloc.algo) {
	case TEE_ALG_DSA_SHA1:
	case TEE_ALG_DSA_SHA224:
	case TEE_ALG_DSA_SHA256:
		if (saved_key_vals.obj_type == TEE_TYPE_DSA_KEYPAIR)
			return TEEC_SUCCESS;
		ADBG_EXPECT(c, TEE_TYPE_DSA_PUBLIC_KEY, saved_key_vals.obj_type);
		break;
	case TEE_ALG_ECDSA_P192:
	case TEE_ALG_ECDSA_P224:
	case TEE_ALG_ECDSA_P256:
	case TEE_ALG_ECDSA_P384:
	case TEE_ALG_ECDSA_P521:
		if (saved_key_vals.obj_type == TEE_TYPE_ECDSA_KEYPAIR)
			return TEEC_SUCCESS;
		ADBG_EXPECT(c, TEE_TYPE_ECDSA_PUBLIC_KEY, saved_key_vals.obj_type);
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		if (saved_key_vals.obj_type == TEE_TYPE_RSA_KEYPAIR)
			return TEEC_SUCCESS;
		ADBG_EXPECT(c, TEE_TYPE_RSA_PUBLIC_KEY, saved_key_vals.obj_type);
		break;
	default:
		/* Unsupported public key algorithm */
		res = TEEC_ERROR_NOT_SUPPORTED;
		return res;
	}

	/* create a key pair matched to the public key */
	switch (saved_alloc.algo) {
	case TEE_ALG_DSA_SHA1:
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_Crypto_InitObjectWithKeys(c, s, CMD_Crypto_InitObjectWithKeys, TEE_TYPE_DSA_KEYPAIR, SIZE_DSA_SHA1_KEYPAIR_768, TEE_ATTR_DSA_PRIME, TEE_ATTR_DSA_PRIME_768_VALUE01, sizeof(TEE_ATTR_DSA_PRIME_768_VALUE01), TEE_ATTR_DSA_SUBPRIME, TEE_ATTR_DSA_SUBPRIME_160_VALUE01, sizeof(TEE_ATTR_DSA_SUBPRIME_160_VALUE01), TEE_ATTR_DSA_BASE, TEE_ATTR_DSA_BASE_768_VALUE01, sizeof(TEE_ATTR_DSA_BASE_768_VALUE01), TEE_ATTR_DSA_PRIVATE_VALUE, TEE_ATTR_DSA_PRIVATE_VALUE_160_VALUE01, sizeof(TEE_ATTR_DSA_PRIVATE_VALUE_160_VALUE01), TEE_ATTR_DSA_PUBLIC_VALUE, TEE_ATTR_DSA_PUBLIC_VALUE_768_VALUE01, sizeof(TEE_ATTR_DSA_PUBLIC_VALUE_768_VALUE01), keypair));
		break;
	case TEE_ALG_DSA_SHA224:
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_Crypto_InitObjectWithKeys(c, s, CMD_Crypto_InitObjectWithKeys, TEE_TYPE_DSA_KEYPAIR, SIZE_DSA_SHA224_KEYPAIR_2048, TEE_ATTR_DSA_PRIME, TEE_ATTR_DSA_PRIME_2048_VALUE01, sizeof(TEE_ATTR_DSA_PRIME_2048_VALUE01), TEE_ATTR_DSA_SUBPRIME, TEE_ATTR_DSA_SUBPRIME_224_VALUE01, sizeof(TEE_ATTR_DSA_SUBPRIME_224_VALUE01), TEE_ATTR_DSA_BASE, TEE_ATTR_DSA_BASE_2048_VALUE01, sizeof(TEE_ATTR_DSA_BASE_2048_VALUE01), TEE_ATTR_DSA_PRIVATE_VALUE, TEE_ATTR_DSA_PRIVATE_VALUE_224_VALUE01, sizeof(TEE_ATTR_DSA_PRIVATE_VALUE_224_VALUE01), TEE_ATTR_DSA_PUBLIC_VALUE, TEE_ATTR_DSA_PUBLIC_VALUE_2048_VALUE01, sizeof(TEE_ATTR_DSA_PUBLIC_VALUE_2048_VALUE01), keypair));
		break;
	case TEE_ALG_DSA_SHA256:
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_Crypto_InitObjectWithKeys(c, s, CMD_Crypto_InitObjectWithKeys, TEE_TYPE_DSA_KEYPAIR, SIZE_DSA_SHA256_KEYPAIR_3072, TEE_ATTR_DSA_PRIME, TEE_ATTR_DSA_PRIME_3072_VALUE01, sizeof(TEE_ATTR_DSA_PRIME_3072_VALUE01), TEE_ATTR_DSA_SUBPRIME, TEE_ATTR_DSA_SUBPRIME_256_VALUE01, sizeof(TEE_ATTR_DSA_SUBPRIME_256_VALUE01), TEE_ATTR_DSA_BASE, TEE_ATTR_DSA_BASE_3072_VALUE01, sizeof(TEE_ATTR_DSA_BASE_3072_VALUE01), TEE_ATTR_DSA_PRIVATE_VALUE, TEE_ATTR_DSA_PRIVATE_VALUE_256_VALUE01, sizeof(TEE_ATTR_DSA_PRIVATE_VALUE_256_VALUE01), TEE_ATTR_DSA_PUBLIC_VALUE, TEE_ATTR_DSA_PUBLIC_VALUE_3072_VALUE01, sizeof(TEE_ATTR_DSA_PUBLIC_VALUE_3072_VALUE01), keypair));
		break;
	case TEE_ALG_ECDSA_P192:
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_Crypto_InitObjectWithKeysExt(c, s, CMD_Crypto_InitObjectWithKeysExt, TEE_TYPE_ECDSA_KEYPAIR, SIZE_ECDSA_P192, TEE_ATTR_ECC_PRIVATE_VALUE, TEE_ATTR_ECC_PRIVATE_VALUE_ECDSA_P192_VALUE01, sizeof(TEE_ATTR_ECC_PRIVATE_VALUE_ECDSA_P192_VALUE01), TEE_ATTR_ECC_PUBLIC_VALUE_X, TEE_ATTR_ECC_PUBLIC_VALUE_X_ECDSA_P192_VALUE01, sizeof(TEE_ATTR_ECC_PUBLIC_VALUE_X_ECDSA_P192_VALUE01), TEE_ATTR_ECC_PUBLIC_VALUE_Y, TEE_ATTR_ECC_PUBLIC_VALUE_Y_ECDSA_P192_VALUE01, sizeof(TEE_ATTR_ECC_PUBLIC_VALUE_Y_ECDSA_P192_VALUE01), TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P192, sizeof(TEE_ECC_CURVE_NIST_P192), TEE_ATTR_NONE, TEE_ATTR_VALUE_NONE, sizeof(TEE_ATTR_VALUE_NONE), keypair));
		break;
	case TEE_ALG_ECDSA_P224:
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_Crypto_InitObjectWithKeysExt(c, s, CMD_Crypto_InitObjectWithKeysExt, TEE_TYPE_ECDSA_KEYPAIR, SIZE_ECDSA_P224, TEE_ATTR_ECC_PRIVATE_VALUE, TEE_ATTR_ECC_PRIVATE_VALUE_ECDSA_P224_VALUE01, sizeof(TEE_ATTR_ECC_PRIVATE_VALUE_ECDSA_P224_VALUE01), TEE_ATTR_ECC_PUBLIC_VALUE_X, TEE_ATTR_ECC_PUBLIC_VALUE_X_ECDSA_P224_VALUE01, sizeof(TEE_ATTR_ECC_PUBLIC_VALUE_X_ECDSA_P224_VALUE01), TEE_ATTR_ECC_PUBLIC_VALUE_Y, TEE_ATTR_ECC_PUBLIC_VALUE_Y_ECDSA_P224_VALUE01, sizeof(TEE_ATTR_ECC_PUBLIC_VALUE_Y_ECDSA_P224_VALUE01), TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P224, sizeof(TEE_ECC_CURVE_NIST_P224), TEE_ATTR_NONE, TEE_ATTR_VALUE_NONE, sizeof(TEE_ATTR_VALUE_NONE), keypair));
		break;
	case TEE_ALG_ECDSA_P256:
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_Crypto_InitObjectWithKeysExt(c, s, CMD_Crypto_InitObjectWithKeysExt, TEE_TYPE_ECDSA_KEYPAIR, SIZE_ECDSA_P256, TEE_ATTR_ECC_PRIVATE_VALUE, TEE_ATTR_ECC_PRIVATE_VALUE_ECDSA_P256_VALUE01, sizeof(TEE_ATTR_ECC_PRIVATE_VALUE_ECDSA_P256_VALUE01), TEE_ATTR_ECC_PUBLIC_VALUE_X, TEE_ATTR_ECC_PUBLIC_VALUE_X_ECDSA_P256_VALUE01, sizeof(TEE_ATTR_ECC_PUBLIC_VALUE_X_ECDSA_P256_VALUE01), TEE_ATTR_ECC_PUBLIC_VALUE_Y, TEE_ATTR_ECC_PUBLIC_VALUE_Y_ECDSA_P256_VALUE01, sizeof(TEE_ATTR_ECC_PUBLIC_VALUE_Y_ECDSA_P256_VALUE01), TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, sizeof(TEE_ECC_CURVE_NIST_P256), TEE_ATTR_NONE, TEE_ATTR_VALUE_NONE, sizeof(TEE_ATTR_VALUE_NONE), keypair));
		break;
	case TEE_ALG_ECDSA_P384:
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_Crypto_InitObjectWithKeysExt(c, s, CMD_Crypto_InitObjectWithKeysExt, TEE_TYPE_ECDSA_KEYPAIR, SIZE_ECDSA_P384, TEE_ATTR_ECC_PRIVATE_VALUE, TEE_ATTR_ECC_PRIVATE_VALUE_ECDSA_P384_VALUE01, sizeof(TEE_ATTR_ECC_PRIVATE_VALUE_ECDSA_P384_VALUE01), TEE_ATTR_ECC_PUBLIC_VALUE_X, TEE_ATTR_ECC_PUBLIC_VALUE_X_ECDSA_P384_VALUE01, sizeof(TEE_ATTR_ECC_PUBLIC_VALUE_X_ECDSA_P384_VALUE01), TEE_ATTR_ECC_PUBLIC_VALUE_Y, TEE_ATTR_ECC_PUBLIC_VALUE_Y_ECDSA_P384_VALUE01, sizeof(TEE_ATTR_ECC_PUBLIC_VALUE_Y_ECDSA_P384_VALUE01), TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P384, sizeof(TEE_ECC_CURVE_NIST_P384), TEE_ATTR_NONE, TEE_ATTR_VALUE_NONE, sizeof(TEE_ATTR_VALUE_NONE), keypair));
		break;
	case TEE_ALG_ECDSA_P521:
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_Crypto_InitObjectWithKeysExt(c, s, CMD_Crypto_InitObjectWithKeysExt, TEE_TYPE_ECDSA_KEYPAIR, SIZE_ECDSA_P521, TEE_ATTR_ECC_PRIVATE_VALUE, TEE_ATTR_ECC_PRIVATE_VALUE_ECDSA_P521_VALUE01, sizeof(TEE_ATTR_ECC_PRIVATE_VALUE_ECDSA_P521_VALUE01), TEE_ATTR_ECC_PUBLIC_VALUE_X, TEE_ATTR_ECC_PUBLIC_VALUE_X_ECDSA_P521_VALUE01, sizeof(TEE_ATTR_ECC_PUBLIC_VALUE_X_ECDSA_P521_VALUE01), TEE_ATTR_ECC_PUBLIC_VALUE_Y, TEE_ATTR_ECC_PUBLIC_VALUE_Y_ECDSA_P521_VALUE01, sizeof(TEE_ATTR_ECC_PUBLIC_VALUE_Y_ECDSA_P521_VALUE01), TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P521, sizeof(TEE_ECC_CURVE_NIST_P521), TEE_ATTR_NONE, TEE_ATTR_VALUE_NONE, sizeof(TEE_ATTR_VALUE_NONE), keypair));
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_Crypto_InitObjectWithKeys(c, s, CMD_Crypto_InitObjectWithKeys, TEE_TYPE_RSA_KEYPAIR, SIZE_RSA_KEYPAIR_2048, TEE_ATTR_RSA_MODULUS, TEE_ATTR_RSA_MODULUS_VALUE01, sizeof(TEE_ATTR_RSA_MODULUS_VALUE01), TEE_ATTR_RSA_PUBLIC_EXPONENT, TEE_ATTR_RSA_PUBLIC_EXPONENT_VALUE01, sizeof(TEE_ATTR_RSA_PUBLIC_EXPONENT_VALUE01), TEE_ATTR_RSA_PRIVATE_EXPONENT, TEE_ATTR_RSA_PRIVATE_EXPONENT_VALUE01, sizeof(TEE_ATTR_RSA_PRIVATE_EXPONENT_VALUE01), TEE_ATTR_NONE, TEE_ATTR_VALUE_NONE, sizeof(TEE_ATTR_VALUE_NONE), TEE_ATTR_NONE, TEE_ATTR_VALUE_NONE, sizeof(TEE_ATTR_VALUE_NONE), keypair));
		break;
	default:
		/* Unsupported public key algorithm */
		res = TEEC_ERROR_NOT_SUPPORTED;
		return res;
	}
	return TEEC_SUCCESS;
}

static TEEC_Result sign_digest(
	ADBG_Case_t *c, TEEC_Session *s,
	const struct crypto_buffer *in_dgst, struct crypto_buffer *out_dgst)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEE_OperationHandle op1 = (TEE_OperationHandle)3;
	uint32_t saved_mode;
	uint32_t ret_orig;

	/* call before Invoke_Crypto_AllocateOperation w/ TEE_MODE_SIGN */
	res = make_keypair_from_publickey(c, s, &saved_obh.obh1);
	if (res != TEEC_SUCCESS)
		goto exit;

	/* preserve original saved_alloc mode */
	saved_mode = saved_alloc.mode;

	res = Invoke_Crypto_AllocateOperation(c, s, CMD_Crypto_AllocateOperation,
					      saved_alloc.algo, TEE_MODE_SIGN,
					      saved_alloc.obj_size, 0, &op1);

	/* restore original saved_alloc mode */
	saved_alloc.mode = saved_mode;

	if (res != TEEC_SUCCESS)
		goto exit;

	if (saved_obh.obh2 != TEE_HANDLE_NULL) {
		res = Invoke_Crypto_SetOperationKey2(c, s, CMD_Crypto_SetOperationKey2,
						     &op1, &saved_obh.obh1,
						     &saved_obh.obh2);

		if (res != TEEC_SUCCESS)
			goto exit;

	} else if (saved_obh.obh1 != TEE_HANDLE_NULL) {
		res = Invoke_Crypto_SetOperationKey(c, s, CMD_Crypto_SetOperationKey,
						    &op1, &saved_obh.obh1);

		if (res != TEEC_SUCCESS)
			goto exit;

	}

	/*CMD_Crypto_AsymmetricSignDigest*/
	/* Fill SharedMem1 with the previously stored
		Digest value after TEE_DigestDoFinal*/
	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM04, 512,
					TEEC_MEM_INPUT,
					in_dgst->size, in_dgst->buffer, mem04_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM05, 512,
			       TEEC_MEM_OUTPUT, mem05_exit);

	op.params[0].value.a = (uint32_t)op1;
	if (in_dgst->size != 0) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM04,
						      in_dgst->size);
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM04,
						      SHARE_MEM04->size);
	}
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM05,
					      SHARE_MEM05->size);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(s, CMD_Crypto_AsymmetricSignDigest, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		CRYPTO_SAFE_MALLOC(*out_dgst, op.params[3].memref.size);
		memcpy(out_dgst->buffer, SHARE_MEM05->buffer, out_dgst->size);
	}

exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM05);
mem05_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM04);
mem04_exit:
	/* The TA is expected to free all operations, not just the handle that
	 * is passed in, when CMD_Crypto_FreeAllKeysAndOperations is invoked.
	 * This interferes with the test itself by removing a handle the test
	 * has not yet had a chance to use, therefore comment out this action.
	 */
	//Invoke_Crypto_FreeAllKeysAndOperations(c, s, CMD_Crypto_FreeAllKeysAndOperations, &op1);
	return res;
}

static bool verify_digest(
	ADBG_Case_t *c, TEEC_Session *s,
	const struct crypto_buffer *in_sdgst)
{
	TEEC_Result res;
	bool is_valid = false;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEE_OperationHandle op1 = (TEE_OperationHandle)3;
	uint32_t ret_orig;

	res = Invoke_Crypto_AllocateOperation(c, s, CMD_Crypto_AllocateOperation,
					      saved_alloc.algo, TEE_MODE_VERIFY,
					      saved_alloc.obj_size, 0, &op1);

	if (res != TEEC_SUCCESS)
		goto exit;

	if (saved_obh.obh2 != TEE_HANDLE_NULL) {
		res = Invoke_Crypto_SetOperationKey2(c, s, CMD_Crypto_SetOperationKey2,
						     &op1, &saved_obh.obh1,
						     &saved_obh.obh2);

		if (res != TEEC_SUCCESS)
			goto exit;

	} else if (saved_obh.obh1 != TEE_HANDLE_NULL) {
		res = Invoke_Crypto_SetOperationKey(c, s, CMD_Crypto_SetOperationKey,
						    &op1, &saved_obh.obh1);

		if (res != TEEC_SUCCESS)
			goto exit;

	}

	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM04, 512,
					TEEC_MEM_INPUT,
					saved_digest.size, saved_digest.buffer, mem04_exit);
	/* Fill "SharedMem2" with signature based on the previously
		stored Digest value after TEE_DigestDoFinal */
	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM05, 512,
					TEEC_MEM_INPUT,
					in_sdgst->size, in_sdgst->buffer, mem05_exit);

	op.params[0].value.a = (uint32_t)op1;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM04,
					      saved_digest.size);
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM05, in_sdgst->size);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_MEMREF_PARTIAL_INPUT);

	res = TEEC_InvokeCommand(s, CMD_Crypto_AsymmetricVerifyDigest, &op, &ret_orig);

	if (res == TEEC_SUCCESS)
		is_valid = true;

	TEEC_ReleaseSharedMemory(SHARE_MEM05);
mem05_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM04);
mem04_exit:
	Invoke_Crypto_FreeAllKeysAndOperations(c, s, CMD_Crypto_FreeAllKeysAndOperations, &op1);
exit:
	return is_valid;
}

static TEEC_Result mac_compute_final(
	ADBG_Case_t *c, TEEC_Session *s,
	const void *full_data, const size_t fdata_length,
	struct crypto_buffer *mac)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEE_OperationHandle op1 = (TEE_OperationHandle)3;
	uint32_t ret_orig;

	res = Invoke_Crypto_AllocateOperation(c, s, CMD_Crypto_AllocateOperation,
					      saved_alloc.algo, TEE_MODE_MAC,
					      saved_alloc.obj_size, 0, &op1);

	if (res != TEEC_SUCCESS)
		goto exit;

	if (saved_obh.obh2 != TEE_HANDLE_NULL) {
		res = Invoke_Crypto_SetOperationKey2(c, s, CMD_Crypto_SetOperationKey2,
						     &op1, &saved_obh.obh1,
						     &saved_obh.obh2);

		if (res != TEEC_SUCCESS)
			goto exit;

	} else if (saved_obh.obh1 != TEE_HANDLE_NULL) {
		res = Invoke_Crypto_SetOperationKey(c, s, CMD_Crypto_SetOperationKey,
						    &op1, &saved_obh.obh1);

		if (res != TEEC_SUCCESS)
			goto exit;
	}

	res = Invoke_Crypto_MACInit(c, s, CMD_Crypto_MACInit, &op1,
				    saved_mac_iv.buffer, saved_mac_iv.size);

	if (res != TEEC_SUCCESS)
		goto exit;

	/* CMD_Crypto_MACComputeFinal */
	/* Fill SharedMem1 with full_data */
	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM04, fdata_length,
					TEEC_MEM_INPUT, fdata_length,
					full_data, mem04_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM05, fdata_length,
			       TEEC_MEM_OUTPUT, mem05_exit);

	op.params[0].value.a = (uint32_t)op1;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM04,
					      SHARE_MEM04->size);
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM05,
					      SHARE_MEM05->size);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(s, CMD_Crypto_MACComputeFinal, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		ADBG_EXPECT_POINTER(c, NULL, mac->buffer);
		CRYPTO_MALLOC(*mac, op.params[3].memref.size);
		memcpy(mac->buffer, SHARE_MEM05->buffer, mac->size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM05);
mem05_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM04);
mem04_exit:
	/* The TA is expected to free all operations, not just the handle that
	 * is passed in, when CMD_Crypto_FreeAllKeysAndOperations is invoked.
	 * This interferes with the test itself by removing a handle the test
	 * has not yet had a chance to use, therefore comment out this action.
	 */
	//Invoke_Crypto_FreeAllKeysAndOperations(c, s, CMD_Crypto_FreeAllKeysAndOperations, &op1);
exit:
	return res;
}

static TEEC_Result cipher_do_final(
	ADBG_Case_t *c, TEEC_Session *s,
	const void *full_data, const size_t fdata_length,
	struct crypto_buffer *cipher)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEE_OperationHandle op1 = (TEE_OperationHandle)3;
	uint32_t ret_orig;

	res = Invoke_Crypto_AllocateOperation(c, s, CMD_Crypto_AllocateOperation,
					      saved_alloc.algo,
					      TEE_MODE_ENCRYPT,
					      saved_alloc.obj_size, 0, &op1);

	if (res != TEEC_SUCCESS)
		goto crypto_alloc;

	if (saved_obh.obh2 != TEE_HANDLE_NULL) {
		res = Invoke_Crypto_SetOperationKey2(c, s, CMD_Crypto_SetOperationKey2,
						     &op1, &saved_obh.obh1,
						     &saved_obh.obh2);

		if (res != TEEC_SUCCESS)
			goto exit;

	} else if (saved_obh.obh1 != TEE_HANDLE_NULL) {
		res = Invoke_Crypto_SetOperationKey(c, s, CMD_Crypto_SetOperationKey,
						    &op1, &saved_obh.obh1);

		if (res != TEEC_SUCCESS)
			goto exit;

	}

	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM04, fdata_length,
					TEEC_MEM_INPUT,
					saved_cipher_iv.size,
					saved_cipher_iv.buffer,
					mem04_exit);

	op.params[0].value.a = (uint32_t)op1;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM04,
					      saved_cipher_iv.size);

	op.params[1].memref.offset = 0;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(s, CMD_Crypto_CipherInit, &op, &ret_orig);

	if (res != TEEC_SUCCESS)
		goto mem05_exit;

	TEEC_ReleaseSharedMemory(SHARE_MEM04);

	/* CMD_Crypto_CipherDoFinal */
	/* Fill SharedMem1 with full_data */
	ALLOCATE_AND_FILL_SHARED_MEMORY(s->ctx, SHARE_MEM04, fdata_length,
					TEEC_MEM_INPUT, fdata_length,
					full_data, mem04_exit);
	ALLOCATE_SHARED_MEMORY(s->ctx, SHARE_MEM05, fdata_length,
			       TEEC_MEM_OUTPUT, mem05_exit);

	op.params[0].value.a = (uint32_t)op1;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM04,
					      SHARE_MEM04->size);
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM05,
					      SHARE_MEM05->size);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(s, CMD_Crypto_CipherDoFinal, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		CRYPTO_SAFE_MALLOC(*cipher, op.params[3].memref.size);
		memcpy(cipher->buffer, SHARE_MEM05->buffer, cipher->size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM05);
mem05_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM04);
mem04_exit:
exit:
	Invoke_Crypto_FreeAllKeysAndOperations(c, s, CMD_Crypto_FreeAllKeysAndOperations, &op1);
crypto_alloc:
	return res;
}

uint32_t swap_uint32( uint32_t val )
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

#endif /* XML_CRYPTO_API_H_ */
