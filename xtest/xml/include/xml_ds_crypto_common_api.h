/*
 * Copyright (c) 2017-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
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

#ifndef XML_DS_CRYPTO_COMMON_API_H_
#define XML_DS_CRYPTO_COMMON_API_H_

#include "xml_common_api.h"
#include "tee_client_api.h"

#define DS_CRYPTO_INIT(b) \
	b.buffer = NULL; \
	b.size = 0;

#define DS_CRYPTO_MALLOC(b, s) \
	b.size = s; \
	b.buffer = malloc(s);

#define DS_CRYPTO_FREE(b) { \
	if (b.buffer != NULL) { \
		b.size = 0; \
		free(b.buffer); \
		b.buffer = NULL; \
	} }

#define Invoke_CloseObject Invoke_Simple_Function_Object_Handle
#define Invoke_FreeTransientObject Invoke_Simple_Function_Object_Handle
#define Invoke_ResetTransientObject Invoke_Simple_Function_Object_Handle

#define Invoke_RestrictObjectUsage Invoke_RestrictObjectUsage1
/* ALL_BUFFER_OFFSETS */
#define OFFSET_0 	 0
#define OFFSET_1 	 1
#define OFFSET_DOUBLE_MAX_INT32 	 0xFFFFFFFE
#define OFFSET_HIGH 	 900
#define OFFSET_HIGH_PLUS_HIGH 	 OFFSET_HIGH + OFFSET_HIGH
#define OFFSET_INITIAL_DATA_SIZE 	 1024
#define OFFSET_INITIAL_DATA_SIZE_PLUS_LOW 	 OFFSET_INITIAL_DATA_SIZE + OFFSET_LOW
#define OFFSET_LOW 	 300
#define OFFSET_LOW_PLUS_HIGH 	 OFFSET_LOW + OFFSET_HIGH
#define OFFSET_LOW_PLUS_LOW 	 OFFSET_LOW + OFFSET_LOW
#define OFFSET_MAX_INT32 	 0x7FFFFFFF
#define OFFSET_NEG_1 	 -1
#define TEE_DATA_MAX_POSITION 	 0xFFFFFFFF

/* ALL_BUFFER_SIZES */
#define AE_TAG_BUFFER_SIZE_32 	 32
#define BIG_ATTRIBUTE_BUFFER_SIZE 	 512
#define BUFFER01_SIZE 	 300
#define BUFFER01_SIZE_EXTENDED_01 	 BUFFER01_SIZE + OFFSET_LOW
#define BUFFER01_SIZE_EXTENDED_02 	 BUFFER01_SIZE + (OFFSET_LOW_PLUS_HIGH - INITIAL_DATA_SIZE)
#define BUFFER_BIG_SIZE 	 BIG_SIZE
#define BUFFER_SIZE_TOO_SMALL 	 10
// #define FUZZ_INITIAL_DATA_LEN_ERROR 	 0x00000011, 0x00000020, 0x7FFFFFFF, 0x80000000, 0x80000001, 0xFFFFFFFF
// #define FUZZ_INITIAL_DATA_LEN_SUCCESS 	 0x00000000, 0x00000001, 0x00000008, 0x0000000F
#define INITIAL_DATA_LEN_FOR_FUZZING 	 16
#define INITIAL_DATA_SIZE 	 1024
#define LARGER_THAN_INITIAL 	 1500
#define SHORTER_THAN_INITIAL 	 500
#define SIZE_0 	 0
#define SIZE_1 	 1

/* ALL_TTA_STORED_ATTRIBUTES */
#define ATTRIBUTE_01 	 0
#define ATTRIBUTE_02 	 1
#define ATTRIBUTE_03 	 2
#define ATTRIBUTE_04 	 3
#define ATTRIBUTE_05 	 4
#define ATTRIBUTE_06 	 5
#define ATTR_NONE 	 0xFFFFFFFF

/* ALL_TTA_STORED_BUFFERS */
#define BUFFER_01 	 0
#define BUFFER_02 	 1
#define BUFFER_03 	 2
#define BUFFER_04 	 3
#define BUFFER_05 	 4
#define BUFFER_06 	 5

/*ALL_OBJECT_SIZES*/
#define KEY_SIZE_TOO_LARGE 	 4096
#define SIZE_AES_192 	 192
#define SIZE_AES_256 	 256
#define SIZE_DES3_128 	 128
#define SIZE_DES3_192 	 192
#define SIZE_DES_64 	 64
#define SIZE_DH_KEYPAIR_1024 	 1024
#define SIZE_DIGEST_MD5_16 	 16
#define SIZE_DIGEST_SHA1_20 	 20
#define SIZE_DIGEST_SHA224_28 	 28
#define SIZE_DIGEST_SHA256_32 	 32
#define SIZE_DIGEST_SHA384_48 	 48
#define SIZE_DIGEST_SHA512_64 	 64
#define SIZE_DSA_SHA1_KEYPAIR_768 	 768
#define SIZE_DSA_SHA1_PUBLIC_KEY_768 	 768
#define SIZE_DSA_SHA224_KEYPAIR_2048 	 2048
#define SIZE_DSA_SHA224_PUBLIC_KEY_2048 	 2048
#define SIZE_DSA_SHA256_KEYPAIR_2048 	 2048
#define SIZE_DSA_SHA256_KEYPAIR_3072 	 3072
#define SIZE_DSA_SHA256_PUBLIC_KEY_2048 	 2048
#define SIZE_DSA_SHA256_PUBLIC_KEY_3072 	 3072
#define SIZE_ECDH_P192 	 192
#define SIZE_ECDH_P224 	 224
#define SIZE_ECDH_P256 	 256
#define SIZE_ECDH_P384 	 384
#define SIZE_ECDH_P521 	 521
#define SIZE_ECDSA_P192 	 192
#define SIZE_ECDSA_P224 	 224
#define SIZE_ECDSA_P256 	 256
#define SIZE_ECDSA_P384 	 384
#define SIZE_ECDSA_P521 	 521
#define SIZE_GENERIC_SECRET_2048 	 2048
#define SIZE_HMAC_MD5_256 	 256
#define SIZE_HMAC_SHA1_256 	 256
#define SIZE_HMAC_SHA224_256 	 256
#define SIZE_HMAC_SHA256_512 	 512
#define SIZE_HMAC_SHA384_512 	 512
#define SIZE_HMAC_SHA512_512 	 512
#define SIZE_RSA_KEYPAIR_1024 	 1024
#define SIZE_RSA_KEYPAIR_2048 	 2048
#define SIZE_RSA_PUBLIC_KEY_2048 	 2048
#define SIZE_ZERO 	 0
#define WRONG_ECC_SIZE 	 10
#define WRONG_SIZE 	 5

/* ALL_TTA_STORED_OBJECT_ENUMERATORS */
#define INVALID_HANDLE 	 0xFFFFFF01
#define BUFF_NULL 	 0xFFFFFF00
#define OBJECT_ENUM_01 	 0

#define iHandleFlagsNone 0

#define iObjectDataFlagsNone 0

#define iObjectUsageAllBitsOne 	 0xFFFFFFFF
#define iObjectUsageNone 	 0
#define iObjectUsageUnknown 0x01010101

/* ALL_TEE_OBJECT_INFOS */
#define OBJECT_INFO_01 	 1

#define clear_usage_flag(c, objectUsage, flag) (objectUsage &= (~flag))
#define clear_handle_flag clear_usage_flag
#define set_usage_flag(c, objectUsage, flag) (objectUsage |= flag)
#define set_handle_flag set_usage_flag
#define set_data_flag set_usage_flag

static TEEC_SharedMemory *SHARE_MEM01;
static TEEC_SharedMemory *SHARE_MEM02;
static TEEC_SharedMemory *SHARE_MEM03;
static TEEC_SharedMemory *SHARE_MEM04;
static TEEC_Session *SESSION01;
static TEEC_Session *SESSION02;
static TEEC_Context *CONTEXT01;
static TEEC_Context *CONTEXT02;
static TEE_ObjectHandle *OBJECT_HANDLE_NULL;
static TEE_ObjectHandle *OBJECT_HANDLE_01;
static TEE_ObjectHandle *OBJECT_HANDLE_02;
static TEE_ObjectHandle *OBJECT_HANDLE_INVALID;

static uint32_t iHandleFlags1;
static uint32_t iHandleFlags2;
static uint32_t iObjectUsage1;

struct data_buffer {
	uint8_t *buffer;
	uint32_t size;
};

/* Saved in Invoke_GetObjectBufferAttribute */
struct data_buffer obj_data_attr;
static bool attr_big_num;

struct attr_list_node {
	uint32_t attr_idx;
    struct attr_list_node *next;
};

static struct attr_list_node *iAttributeListEmpty = NULL;
static struct attr_list_node *iAttributeList1;

static void ds_crypto_common_init(void)
{
	iHandleFlags1 = 0;
	iHandleFlags2 = 0;
	iObjectUsage1 = 0;

	attr_big_num = 0;
	DS_CRYPTO_INIT(obj_data_attr);

	iAttributeList1 = iAttributeListEmpty;
}

static void ds_crypto_common_reset(void)
{
	iHandleFlags1 = 0;
	iHandleFlags2 = 0;
	iObjectUsage1 = 0;

	attr_big_num = 0;
	DS_CRYPTO_FREE(obj_data_attr);

	if (iAttributeList1) {
		struct attr_list_node *rm_attr;
		do {
			rm_attr = iAttributeList1;
			iAttributeList1 = iAttributeList1->next;
			rm_attr->attr_idx = 0;
			rm_attr->next = NULL;
			free(rm_attr);
		} while (iAttributeList1);
	}
}

/* Check if the attribute is bignum using attribute ID */
static bool is_attr_bignum(uint32_t Id)
{
	bool ret = 0;

	ret = (bool)((Id == TEE_ATTR_RSA_MODULUS) || (Id == TEE_ATTR_RSA_PUBLIC_EXPONENT) ||
				 (Id == TEE_ATTR_RSA_PRIVATE_EXPONENT) || (Id == TEE_ATTR_RSA_PRIME1) ||
				 (Id == TEE_ATTR_RSA_PRIME2) || (Id == TEE_ATTR_RSA_EXPONENT1) ||
				 (Id == TEE_ATTR_RSA_EXPONENT2) ||
				 (Id == TEE_ATTR_RSA_COEFFICIENT) || (Id == TEE_ATTR_DSA_PRIME) ||
				 (Id == TEE_ATTR_DSA_SUBPRIME) || (Id == TEE_ATTR_DSA_BASE) ||
				 (Id == TEE_ATTR_DSA_PUBLIC_VALUE) || (Id == TEE_ATTR_DSA_PRIVATE_VALUE) ||
				 (Id == TEE_ATTR_DH_PRIME) || (Id == TEE_ATTR_DH_SUBPRIME) ||
				 (Id == TEE_ATTR_DH_BASE) || (Id == TEE_ATTR_DH_PUBLIC_VALUE) ||
				 (Id == TEE_ATTR_DH_PRIVATE_VALUE) || (Id == TEE_ATTR_ECC_PUBLIC_VALUE_X) ||
				 (Id == TEE_ATTR_ECC_PUBLIC_VALUE_Y) || (Id == TEE_ATTR_ECC_PRIVATE_VALUE));
	return ret;
}

static bool is_attr_list_empty(struct attr_list_node *attributeList)
{
	if (attributeList)
		return 0;
	return 1;
}

#define add_attribute(c, attributeList, ATTRIBUTE) \
do { \
	struct attr_list_node *new_attr = \
		(struct attr_list_node *)malloc(sizeof(struct attr_list_node)); \
	if (new_attr) {\
		new_attr->attr_idx = ATTRIBUTE; \
		new_attr->next = NULL; \
		if (is_attr_list_empty(attributeList)) { \
			attributeList = new_attr; \
		} else { \
			struct attr_list_node *last_elem = attributeList; \
			while (last_elem->next) \
				last_elem = last_elem->next; \
			last_elem->next = new_attr; \
		} \
	} \
} while (0)

/* From Data Storage API */

/* Function expanded for additional size parameter for more precise allocation. */
static TEEC_Result Invoke_StoreAttributeBuffer(
	ADBG_Case_t *c,
	TEEC_Session *s,
	uint32_t cmd_id,
	uint32_t tta_buffer_id,
	const uint8_t *value,
	uint32_t size)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(s->ctx, SHARE_MEM01,
					size,
					TEEC_MEM_INPUT, value, store_attr_exit);

	op.params[0].value.a = tta_buffer_id;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
store_attr_exit:
	return res;
}

static TEEC_Result Invoke_InitRefAttribute(
	ADBG_Case_t *c,
	TEEC_Session *s,
	uint32_t cmd_id,
	uint32_t tta_attr_id,
	uint32_t attr_id,
	uint32_t tta_buffer_id)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	op.params[0].value.a = tta_attr_id;
	op.params[0].value.b = attr_id;

	op.params[1].value.a = tta_buffer_id;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);
}
/* Macro expanded by additional size parameter. */
#define Macro_StoreRefAttribute(c, sess, attribute, buffer, attributeID, value, size) \
	({ \
		TEEC_Result __ret = Invoke_StoreAttributeBuffer(c, sess, CMD_DS_StoreBuffer, \
				buffer, value, size); \
		if (!__ret) \
			__ret =  Invoke_InitRefAttribute(c, sess, \
				CMD_DS_InitRefAttribute, attribute, attributeID, buffer); \
		__ret; \
	})

static TEEC_Result Invoke_RestrictObjectUsage1(
	ADBG_Case_t *c,
	TEEC_Session *s,
	uint32_t cmd_id,
	TEE_ObjectHandle *obh,
	uint32_t obu)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	op.params[0].value.a = (uint32_t)*obh;
	op.params[0].value.b = obu;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);
}

static TEEC_Result Invoke_AllocateTransientObject(
	ADBG_Case_t *c,
	TEEC_Session *s,
	uint32_t cmd_id,
	uint32_t obj_type,
	uint32_t max_key_size,
	TEE_ObjectHandle *obh)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	op.params[0].value.a = (uint32_t)*obh;

	op.params[1].value.a = obj_type;
	op.params[1].value.b = max_key_size;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);
}

static TEEC_Result Invoke_Simple_Function_Object_Handle(
	ADBG_Case_t *c,
	TEEC_Session *s,
	uint32_t cmd_id,
	TEE_ObjectHandle *obh)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	op.params[0].value.a = (uint32_t)*obh;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);
}

static TEEC_Result Invoke_GetObjectBufferAttribute(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	TEE_ObjectHandle *obh, uint32_t attrId,
	bool bufferIsNull, uint32_t buffSize)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	if (!bufferIsNull)
		ALLOCATE_SHARED_MEMORY(sess->ctx, SHARE_MEM01, buffSize,
				       TEEC_MEM_OUTPUT, mem01_exit);

	op.params[0].value.a = (uint32_t)*obh;
	op.params[0].value.b = attrId;

	if (bufferIsNull) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, NULL, 0);
		op.paramTypes = TEEC_PARAM_TYPES(
			TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
			TEEC_NONE);
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
						      SHARE_MEM01->size);
		op.paramTypes = TEEC_PARAM_TYPES(
			TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE,
			TEEC_NONE);
	}

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (res == TEE_SUCCESS) {
		DS_CRYPTO_FREE(obj_data_attr);
		DS_CRYPTO_MALLOC(obj_data_attr, op.params[1].memref.size);
		memcpy((void *)obj_data_attr.buffer, op.params[1].memref.parent->buffer,
			obj_data_attr.size);

		attr_big_num = is_attr_bignum(attrId);
	}

	if (!bufferIsNull)
		TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static void Check_ObjectBufferAttribute(ADBG_Case_t *c, const uint8_t *attr_val)
{
	uint8_t *strip_attr_val = (uint8_t *)attr_val;
	uint8_t *strip_data = (uint8_t *)obj_data_attr.buffer;
	uint32_t data_size = obj_data_attr.size;

	if (attr_big_num) {
		/* Strip leading zero bytes form expected value */
		while(!(*strip_attr_val)) {
			strip_attr_val++;
		}
		/* Strip leading zero bytes form buffer content and adjust size. */
		while(!(*strip_data)) {
			strip_data++;
			data_size--;
		}
	}

	(void)ADBG_EXPECT_EQUAL(c, strip_attr_val, strip_data, data_size);
}

#endif // XML_DS_CRYPTO_COMMON_API_H_
