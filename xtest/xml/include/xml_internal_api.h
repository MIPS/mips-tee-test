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

#ifndef XML_INTERNAL_API_H_
#define XML_INTERNAL_API_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef USER_SPACE
#include <pthread.h>
#include <unistd.h>
#endif

#include <sys/types.h>
#include "tee_client_api.h"
#include "xml_common_api.h"

#define Invoke_MaskUnmaskCancellations Invoke_Simple_Function
#define Invoke_ProcessTAInvoke_Payload_Value Invoke_Simple_Function
#define Invoke_ProcessTAInvoke_Payload_Value_In_Out Invoke_Simple_Function
#define Invoke_ProcessTAInvoke_Payload_Memref Invoke_Simple_Function

#define Invoke_GetPropertyAsBool_withoutEnum Invoke_GetPropertyAsXXX_withoutEnum
#define Invoke_GetPropertyAsU32_withoutEnum Invoke_GetPropertyAsXXX_withoutEnum
#define Invoke_GetPropertyAsUUID_withoutEnum Invoke_GetPropertyAsXXX_withoutEnum
#define Invoke_GetPropertyAsIdentity_withoutEnum \
	Invoke_GetPropertyAsXXX_withoutEnum
#define Invoke_GetPropertyAsBinaryBlock_withoutEnum \
	Invoke_GetPropertyAsXXX_withoutEnum
#define Invoke_GetPropertyAsString_withoutEnum \
	Invoke_GetPropertyAsXXX_withoutEnum

#define Invoke_GetPropertyAsXXXX_fromEnum Invoke_StartPropertyEnumerator

#define Invoke_FreePropertyEnumerator Invoke_ResetPropertyEnumerator
#define Invoke_GetNextProperty_enumNotStarted Invoke_ResetPropertyEnumerator

#define TA_SESSION01                    0
#define TA_SESSION02                    1

#define TEE_ORIGIN_NOT_TRUSTED_APP 0x00000005

#define SIZE_ZERO 0

#define TEE_ERROR_TOO_SHORT_BUFFER TEE_ERROR_SHORT_BUFFER

#ifdef USER_SPACE
/* Test data defines */
//static pthread_t THREAD01_DEFAULT;
static pthread_t THREAD02;
#endif

static TEEC_SharedMemory *SHARE_MEM01;
static TEEC_SharedMemory *SHARE_MEM02;
static TEEC_Session *SESSION01;
static TEEC_Session *SESSION02;
/* Requires 2 sessions as we are opeing
	multiple sessions at the same time */
static TEEC_Context *CONTEXT01;
static TEEC_Context *CONTEXT02;
static TEEC_Operation *OPERATION01;

static uint32_t big_size = BIG_SIZE;

char *NO_DATA;
uint32_t *ENUMERATOR1;

#define ANY_OWNER_NOT_SET 0
#define ANY_OWNER_SET TEE_MEMORY_ACCESS_ANY_OWNER
#define ANY_OWNER_SET_ACCESS_READ (TEE_MEMORY_ACCESS_ANY_OWNER | \
				   TEE_MEMORY_ACCESS_READ)
#define ANY_OWNER_SET_ACCESS_WRITE (TEE_MEMORY_ACCESS_ANY_OWNER | \
				    TEE_MEMORY_ACCESS_WRITE)
#define ANY_OWNER_SET_ACCESS_READ_WRITE (TEE_MEMORY_ACCESS_ANY_OWNER | \
					 TEE_MEMORY_ACCESS_READ | \
					 TEE_MEMORY_ACCESS_WRITE)

#define SMALL_SIZE 0xA

#define CMD_TEE_GetInstanceData 0x00000101
#define CMD_TEE_SetInstanceData 0x00000102
#define CMD_TEE_GetPropertyAsU32_withoutEnum 0x00000020

#define NORMAL_SIZE_BUFFER 1
#define TOO_SHORT_BUFFER 0
#define CASE_NOT_NULL 1
#define CASE_NULL 0
#define CASE_BUFFER1_DIFFERS_FIRST 1
#define CASE_BUFFER2_DIFFERS_FIRST 2
#define CASE_EQUAL 0
#define CASE_ERROR_ICA2 3
#define CASE_PAYLOAD_VALUE 4
#define CASE_SUCCESS_ICA2 2
#define CASE_TARGET_DEAD_ICA2 1
#define CASE_CANCEL_TIMEOUT 2
#define CASE_ITEM_NOT_FOUND 3
#define CASE_SUCCESS 0
#define CASE_TARGET_BUSY 4
#define CASE_TARGET_DEAD 1
#define RESULT_EQUAL 0
#define RESULT_INTEGER_GREATER_THAN_ZERO 1
#define RESULT_INTEGER_LOWER_THAN_ZERO 2

#define HINT_ZERO 0
#define SIZE_OVER_MEMORY 0xFFFFFFFE

#define TEE_PROPSET_IMPLEMENTATION TEE_PROPSET_TEE_IMPLEMENTATION

static char VALUE_PREDEFINED_STRING[] = "this is a test string\0";
static char VALUE_PREDEFINED_U32[] = "48059\0";
static char VALUE_PREDEFINED_UUID[] = "534D4152-542D-4353-4C54-2D54412D3031\0";
static char VALUE_PREDEFINED_IDENTITY[] =
	"F0000000:534D4152-542D-4353-4C54-2D54412D3031\0";

static char *VALUE_NONE;
static char VALUE_PREDEFINED_BINARY_BLOCK[] =
	"VGhpcyBpcyBhIHRleHQgYmluYXJ5IGJsb2Nr\0";
static char VALUE_PREDEFINED_BOOLEAN[] = "true\0";

static uint8_t CHAR1[] = { 0x10 };
/* static uint8_t CHAR2[]={0xAA}; */

static char GPD_CLIENT_identity[] = "gpd.client.identity\0";
static char GPD_TA_appID[] = "gpd.ta.appID\0";
static char GPD_TA_dataSize[] = "gpd.ta.dataSize\0";
static char GPD_TA_instanceKeepAlive[] = "gpd.ta.instanceKeepAlive\0";
static char GPD_TA_multiSession[] = "gpd.ta.multiSession\0";
static char GPD_TA_singleInstance[] = "gpd.ta.singleInstance\0";
static char GPD_TA_stackSize[] = "gpd.ta.stackSize\0";
static char GPD_TEE_ARITH_maxBigIntSize[] = "gpd.tee.arith.maxBigIntSize\0";
static char GPD_TEE_SYSTEM_TIME_protectionLevel[] =
	"gpd.tee.systemTime.protectionLevel\0";
static char GPD_TEE_TA_PERSISTENT_TIME_protectionLevel[] =
	"gpd.tee.TAPersistentTime.protectionLevel\0";
static char GPD_TEE_apiversion[] = "gpd.tee.apiversion\0";
static char GPD_TEE_description[] = "gpd.tee.description\0";
static char GPD_TEE_deviceID[] = "gpd.tee.deviceID\0";
static char PROPERTY_NAME_NOT_VALID_ENCODING[] = "gpd.\t\n\r\0";
static char PROPERTY_NAME_UNKNOWN[] = "unknown\0";
static char SMC_TA_testuuid[] = "smc.ta.testuuid\0";
static char SMC_TA_testbinaryblock[] = "smc.ta.testbinaryblock\0";
static char SMC_TA_testbooltrue[] = "smc.ta.testbooltrue\0";
static char SMC_TA_testidentity[] = "smc.ta.testidentity\0";
static char SMC_TA_teststring[] = "smc.ta.teststring\0";
static char SMC_TA_testu32[] = "smc.ta.testu32\0";
static char STRING_SAMPLE_SIZE_4_CHAR[] = "TEE\0";


/** ALL_TEEC_UUID
 *
 * These constants are the UUID of existing
 * Trusted Applications
 */
/* "SMART-CSLT-TA-01" */
static TEEC_UUID UUID_TTA_testingInternalAPI_TrustedCoreFramework = {
	0x534D4152, 0x542D, 0x4353,
	{ 0x4C, 0x54, 0x2D, 0x54, 0x41, 0x2D, 0x30, 0x31 }
};
/* "SMARTCSLTATCFICA" */
/* Changed endians from the adaptation layer specification description */
static TEEC_UUID UUID_TTA_testingInternalAPI_TrustedCoreFramework_ICA = {
	0x534D4152, 0x5443, 0x534C,
	{ 0x54, 0x41, 0x54, 0x43, 0x46, 0x49, 0x43, 0x41 }
};
/* "SMARTCSLTTCFICA2" */
/* Changed endians from the adaptation layer specification description */
static TEEC_UUID UUID_TTA_testingInternalAPI_TrustedCoreFramework_ICA2 = {
	0x534D4152, 0x5443, 0x534C,
	{ 0x54, 0x54, 0x43, 0x46, 0x49, 0x43, 0x41, 0x32 }
};
/* "SMARTCSLMLTINSTC" */
static TEEC_UUID
	UUID_TTA_testingInternalAPI_TrustedCoreFramework_MultipleInstanceTA = {
	0x534D4152, 0x5443, 0x534C,
	{ 0x4D, 0x4C, 0x54, 0x49, 0x4E, 0x53, 0x54, 0x43 }
};
/* "SMARTCSLSGLINSTC" */
static TEEC_UUID
	UUID_TTA_testingInternalAPI_TrustedCoreFramework_SingleInstanceTA = {
	0x534D4152, 0x5443, 0x534C,
	{ 0x53, 0x47, 0x4C, 0x49, 0x4E, 0x53, 0x54, 0x43 }
};
/* "SMART-CUNK-NO-WN" */
static TEEC_UUID UUID_Unknown = {
	0x534D4152, 0x542D, 0x4355,
	{ 0x4E, 0x4B, 0x2D, 0x4E, 0x4F, 0x2D, 0x57, 0x4E }
};
static TEEC_UUID UUID_TTA_testingInternalAPI_TrustedCoreFramework_PanicAtCreation = {
	0x534D4152, 0x5443, 0x534C,
	{ 0x54, 0x43, 0x52, 0x50, 0x41, 0x4E, 0x49, 0x43 }
};
static TEEC_UUID UUID_TTA_testingInternalAPI_TrustedCoreFramework_PanicAtCloseSession = {
	0x534D4152, 0x5443, 0x534C,
	{ 0x43, 0x4C, 0x4F, 0x50, 0x41, 0x4E, 0x49, 0x43 }
};

#ifdef USER_SPACE
static void *cancellation_thread(void *arg)
{
	(void)usleep(500000);
	TEEC_RequestCancellation((TEEC_Operation *)arg);
	return NULL;
}

#define TEEC_createThread(a, b) \
	(void)ADBG_EXPECT(c, 0, \
			  pthread_create(&b, NULL, cancellation_thread, \
					 (void *)OPERATION01));

#define RequestCancellation(op) \
	(void)ADBG_EXPECT(c, 0, pthread_join(THREAD02, NULL));
#else
#define RequestCancellation(op) \
	IDENTIFIER_NOT_USED(op)
#endif

static TEEC_Result Invoke_Simple_Function(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_MemFill(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t memoryFillSize, uint8_t *charFill)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	op.params[0].value.a = memoryFillSize;
	op.params[1].value.a = *charFill;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_GetPropertyAsXXX_withoutEnum(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t propSet, char *name, uint32_t kindBuffer,
	char *expectedValue)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t nameLen = 0;
	uint32_t expectedValueLen = 0;

	if (name) {
		nameLen = strlen(name) + 1;
		ALLOCATE_AND_FILL_SHARED_MEMORY(sess->ctx, SHARE_MEM01, big_size,
						TEEC_MEM_INPUT, nameLen, name, mem01_exit);
	} else {
		ALLOCATE_SHARED_MEMORY(sess->ctx, SHARE_MEM01, 0,
				       TEEC_MEM_INPUT, mem01_exit);
		SHARE_MEM01->buffer = NULL;
	}

	if (kindBuffer == TOO_SHORT_BUFFER) {
		ALLOCATE_SHARED_MEMORY(sess->ctx, SHARE_MEM02, 1,
				       TEEC_MEM_OUTPUT, mem02_exit);
	} else {
		ALLOCATE_SHARED_MEMORY(sess->ctx, SHARE_MEM02, big_size,
				       TEEC_MEM_OUTPUT, mem02_exit);
	}

	op.params[0].value.a = (uint32_t)propSet;

	op.params[1].tmpref.buffer = SHARE_MEM01->buffer;
	op.params[1].tmpref.size = SHARE_MEM01->size;

	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size);

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (res != TEEC_SUCCESS)
		goto exit;

	if (expectedValue != VALUE_NONE) {
		expectedValueLen = strlen(expectedValue) + 1;
		(void)ADBG_EXPECT_COMPARE_SIGNED(c,
						 0, ==,
						 memcmp(op.params[2].memref.
							parent->buffer,
							expectedValue,
							expectedValueLen));
	}

exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
    if (name)
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_MemCompare(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t memorySize, uint32_t Case, uint32_t compareResult)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t outValue = 0;

	op.params[0].value.a = memorySize;
	op.params[1].value.a = Case;
	op.params[2].value.a = outValue;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
		TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (res != TEEC_SUCCESS)
		goto exit;

	if (compareResult == RESULT_EQUAL) {
		(void)ADBG_EXPECT_COMPARE_SIGNED(c, op.params[2].value.a, ==,
						 0);
	} else if (compareResult == RESULT_INTEGER_GREATER_THAN_ZERO) {
		(void)ADBG_EXPECT_COMPARE_SIGNED(c,
						 (int32_t)op.params[2].value.a,
						 >, 0);
	} else if (compareResult == RESULT_INTEGER_LOWER_THAN_ZERO) {
		(void)ADBG_EXPECT_COMPARE_SIGNED(c,
						 (int32_t)op.params[2].value.a,
						 <, 0);
	}

exit:
	return res;
}

static TEEC_Result Invoke_SetInstanceData(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId, char *data)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	ALLOCATE_AND_FILL_SHARED_MEMORY(sess->ctx, SHARE_MEM01, strlen(data) + 1,
					TEEC_MEM_INPUT,
					strlen(data) + 1, data, mem01_exit);

	SET_SHARED_MEMORY_OPERATION_PARAMETER(0, 0, SHARE_MEM01,
					      SHARE_MEM01->size);

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_GetInstanceData(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId, char *expectedData,
	uint32_t expectedDataSize)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	ALLOCATE_SHARED_MEMORY(sess->ctx, SHARE_MEM01, big_size,
			       TEEC_MEM_OUTPUT, mem01_exit);

	SET_SHARED_MEMORY_OPERATION_PARAMETER(0, 0, SHARE_MEM01,
					      SHARE_MEM01->size);

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (res != TEEC_SUCCESS)
		goto exit;

	if (res != TEE_ERROR_GENERIC) {
		(void)ADBG_EXPECT_COMPARE_SIGNED(c, op.params[0].memref.size,
						 ==, expectedDataSize);
		(void)ADBG_EXPECT_COMPARE_SIGNED(c,
						 0, ==,
						 memcmp(SHARE_MEM01->buffer,
							expectedData,
							expectedDataSize));
	}

exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static void copy_uuid_to_buffer(void *dst, TEEC_UUID *uuid)
{
	uint8_t *buf = (uint8_t *)dst;
	uint8_t *src = (uint8_t *)uuid;
	buf[0] = src[3];
	buf[1] = src[2];
	buf[2] = src[1];
	buf[3] = src[0];
	buf[4] = src[5];
	buf[5] = src[4];
	buf[6] = src[7];
	buf[7] = src[6];
	memcpy(buf + 8, src + 8, 8 * sizeof(uint8_t));
}

static TEEC_Result Invoke_ProcessInvokeTAOpenSession(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t TACmd, TEEC_UUID *UUID, uint32_t returnOrigin)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	res = AllocateSharedMemory(sess->ctx, SHARE_MEM01, big_size,
		TEEC_MEM_INPUT);
	if (res != TEEC_SUCCESS)
		goto mem01_exit;
	memset(SHARE_MEM01->buffer, 0, big_size);
	copy_uuid_to_buffer(SHARE_MEM01->buffer, UUID);

	op.params[0].value.a = TACmd;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01, 16);
	op.params[2].value.a = returnOrigin;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT, TEEC_VALUE_OUTPUT,
		TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (TEE_ORIGIN_NOT_TRUSTED_APP == returnOrigin) {
		(void)ADBG_EXPECT_COMPARE_SIGNED(c, op.params[2].value.a, !=,
						 TEE_ORIGIN_TRUSTED_APP);
	} else {
		(void)ADBG_EXPECT_COMPARE_SIGNED(c, op.params[2].value.a, ==,
						 returnOrigin);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_CheckMemoryAccessRight(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t memoryParamType, uint32_t memoryAccessFlags)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t memory_flag;
	(void)c;

	switch (memoryParamType) {
	case TEEC_MEMREF_TEMP_INPUT:
	case TEEC_MEMREF_PARTIAL_INPUT:
		memory_flag = TEEC_MEM_INPUT;
		break;
	case TEEC_MEMREF_TEMP_OUTPUT:
	case TEEC_MEMREF_PARTIAL_OUTPUT:
		memory_flag = TEEC_MEM_OUTPUT;
		break;
	case TEEC_MEMREF_TEMP_INOUT:
	case TEEC_MEMREF_PARTIAL_INOUT:
	case TEEC_MEMREF_WHOLE:
		memory_flag = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
		break;
	default:
		memory_flag = 0;
		break;
	}

	ALLOCATE_SHARED_MEMORY(sess->ctx, SHARE_MEM01, big_size,
					memory_flag, mem01_exit);

	op.params[0].value.a = memoryAccessFlags;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, memoryParamType, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_MemMove(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId, uint32_t memorySize)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	op.params[0].value.a = memorySize;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_AllocatePropertyEnumerator(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t *enumerator)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	op.params[0].value.a = 0;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (res != TEEC_SUCCESS)
		goto exit;

	*enumerator = op.params[0].value.a;
	/* (void)ADBG_EXPECT_COMPARE_SIGNED(
		c, op.params[0].value.a, == , enumerator); */

exit:
	return res;
}

static TEEC_Result Invoke_StartPropertyEnumerator(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId, uint32_t *enumerator,
	uint32_t propSet)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	op.params[0].value.a = *enumerator;
	op.params[1].value.a = (uint32_t)propSet;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_ResetPropertyEnumerator(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId, uint32_t *enumerator)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	op.params[0].value.a = *enumerator;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_GetPropertyName(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t *enumerator, char *propertyName, uint32_t kindBuffer)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t strLen = 0;

	if (kindBuffer == TOO_SHORT_BUFFER) {
		ALLOCATE_SHARED_MEMORY(sess->ctx, SHARE_MEM01, 1,
				       TEEC_MEM_OUTPUT, mem01_exit);
	} else {
		ALLOCATE_SHARED_MEMORY(sess->ctx, SHARE_MEM01, big_size,
				       TEEC_MEM_OUTPUT, mem01_exit);
	}

	op.params[0].value.a = *enumerator;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE,
		TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (res != TEEC_SUCCESS)
		goto exit;

	strLen = strlen(propertyName) + 1;

	(void)ADBG_EXPECT_COMPARE_SIGNED(c, op.params[1].memref.size, ==,
					 strLen);

	(void)ADBG_EXPECT_COMPARE_SIGNED(c,
					 0, ==,
					 memcmp(SHARE_MEM01->buffer,
						propertyName, strLen));

exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_Malloc(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t memorySize, uint32_t hint)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	op.params[0].value.a = memorySize;
	op.params[1].value.a = hint;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_Panic(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (res != TEEC_SUCCESS)
		goto exit;

	(void)ADBG_EXPECT_COMPARE_SIGNED(c, org, ==, TEE_ORIGIN_TEE);

exit:
	return res;
}

static TEEC_Result Invoke_Realloc(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t oldMemorySize, uint32_t newMemorySize)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	op.params[0].value.a = oldMemorySize;
	op.params[1].value.a = newMemorySize;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_Free(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId, uint32_t Case)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	op.params[0].value.a = Case;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_GetCancellationFlag_RequestedCancel(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	TEEC_Operation *operation)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	uint32_t org;
	(void)c;

	res = TEEC_InvokeCommand(sess, cmdId, operation, &org);

	return res;
}

static void Invoke_CloseTASession(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t ta_sess, TEEC_Result expected)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = ta_sess;

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);
	ADBG_EXPECT(c, expected, res);
	ADBG_EXPECT(c, TEEC_ORIGIN_TRUSTED_APP, org);
}

static void Invoke_ProcessTAInvoke_DeadErrorSuccess(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t ta_cmd, TEEC_UUID *uuid, uint32_t orig,
	TEEC_Result expected)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_SharedMemory *sh_mem_input;
	TEEC_Operation op;
	uint32_t org;

	sh_mem_input = malloc(sizeof(TEEC_SharedMemory));
	AllocateSharedMemory(sess->ctx, sh_mem_input, 16, TEEC_MEM_INPUT);
	TEEC_RegisterSharedMemory(sess->ctx, sh_mem_input);
	copy_uuid_to_buffer(sh_mem_input->buffer, uuid);

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_VALUE_OUTPUT, TEEC_NONE);
	op.params[0].value.a = ta_cmd;
	op.params[1].memref.parent = sh_mem_input;
	op.params[1].memref.size = 16;
	op.params[1].memref.offset = 0;
	op.params[2].value.a = orig;

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);
	ADBG_EXPECT(c, expected, res);
	if (orig == TEE_ORIGIN_NOT_TRUSTED_APP)
		ADBG_EXPECT_NOT(c, TEE_ORIGIN_TRUSTED_APP, op.params[2].value.a);
	else
		ADBG_EXPECT(c, orig, op.params[2].value.a);
	TEEC_ReleaseSharedMemory(sh_mem_input);
	free(sh_mem_input);
}

static uint32_t Invoke_OpenTASession(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t ta_sess, TEEC_UUID *uuid, uint32_t orig)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_SharedMemory *sh_mem_input;
	TEEC_Operation op;
	uint32_t org;

	sh_mem_input = malloc(sizeof(TEEC_SharedMemory));
	AllocateSharedMemory(sess->ctx, sh_mem_input, 16, TEEC_MEM_INPUT);
	TEEC_RegisterSharedMemory(sess->ctx, sh_mem_input);
	copy_uuid_to_buffer(sh_mem_input->buffer, uuid);

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_VALUE_OUTPUT, TEEC_NONE);
	op.params[0].value.a = ta_sess;
	op.params[1].memref.parent = sh_mem_input;
	op.params[1].memref.size = 16;
	op.params[1].memref.offset = 0;

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);
	ADBG_EXPECT(c, TEEC_ORIGIN_TRUSTED_APP, org);
	ADBG_EXPECT(c, TEEC_SUCCESS, res);
	ADBG_EXPECT(c, orig, op.params[2].value.b);
	TEEC_ReleaseSharedMemory(sh_mem_input);
	free(sh_mem_input);
	return op.params[2].value.a;
}

static TEEC_Result Invoke_InvokeTACommand(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t ta_sess, uint32_t ta_cmd, uint32_t orig)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op;
	uint32_t org;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
		TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = ta_sess;
	op.params[0].value.b = ta_cmd;

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);
	ADBG_EXPECT(c, orig, org);
	return res;
}
#endif /* XML_INTERNAL_API_H_ */
