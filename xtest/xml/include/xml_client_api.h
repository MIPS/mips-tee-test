/*
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

#ifndef XML_CLIENT_API_H_
#define XML_CLIENT_API_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include "tee_client_api.h"
#include "xml_common_api.h"
#ifdef USER_SPACE
#include <pthread.h>
#include <unistd.h>
#endif

#define OFFSET0 0
#define OFFSET_02 0x64

#ifdef USER_SPACE
/*Test data defines*/
static pthread_t THREAD02;
#endif

static TEEC_SharedMemory *SHARE_MEM01;
static TEEC_SharedMemory *SHARE_MEM02;
static TEEC_SharedMemory *SHARE_MEM03;
static TEEC_SharedMemory *SHARE_MEM04;
static TEEC_SharedMemory *SHARE_MEM_NULL_BUFFER;

static TEEC_TempMemoryReference *TEMP_MEM01;
static TEEC_TempMemoryReference *TEMP_MEM02;
static TEEC_TempMemoryReference *TEMP_MEM03;
static TEEC_TempMemoryReference *TEMP_MEM04;
static TEEC_TempMemoryReference *TEMP_MEM_NULL_BUFFER;

static TEEC_Session *SESSION01;
static TEEC_Session *SESSION02;
static TEEC_Context *CONTEXT01;
static TEEC_Context *CONTEXT02;
static TEEC_Operation *OPERATION01;
static TEEC_Operation *OPERATION02;
static TEEC_Operation *TMP_OPERATION;

/* Return ORIGIN */
static uint32_t ret_orig;

static uint32_t IGNORE = 0xFEFEFEFE;

static uint32_t VALUE01 = 0x01234567;
static uint32_t SIZE_OVER_MEMORY = 0xFFFFFFFE;
static uint32_t SIZE_VALUE01 = sizeof(VALUE01);
static uint32_t ZERO = 0;
static uint32_t ALLOC_SIZE_02 = 0x2800;
static uint32_t SIZE_02 = 0x2000;
static uint32_t SIZE_GREATER_THAN_SIZE_02 = 0x2328;
static uint32_t SIZE_LESSER_THAN_SIZE_02 = 0x1B58;
static uint32_t	BYTE_01 = 0x01;
static uint32_t	BYTE_02 = 0x02;
static uint32_t	BYTE_03 = 0x03;
static uint32_t	BYTE_04 = 0x04;

#define VALUE_A_IN_0		0x01234567u
#define VALUE_B_IN_0		0x89ABCDEFu
#define VALUE_A_OUT_0	0xABCD0248u
#define VALUE_B_OUT_0	0x1A2B3C4Du

#define VALUE_A_IN_1		0xF9E8D7C6u
#define VALUE_B_IN_1		0x1248DCBAu
#define VALUE_A_OUT_1	0x03579EF4u
#define VALUE_B_OUT_1	0x1439F7A2u

#define VALUE_A_IN_2		0xE01C083Du
#define VALUE_B_IN_2		0x5E816B61u
#define VALUE_A_OUT_2	0x344C64BCu
#define VALUE_B_OUT_2	0x6EC61CAEu

#define VALUE_A_IN_3		0xDCA65016u
#define VALUE_B_IN_3		0x4C899A96u
#define VALUE_A_OUT_3	0x3590BBD9u
#define VALUE_B_OUT_3	0xB2639F77u


#define INVALID_CONNECTION_METHODS 0x0A
#define COMMAND_TTA_Check_Expected_ParamTypes COMMAND_TTA_Check_ParamTypes

/* "ItIsNotTotosTEEs" */
const char *INVALID_NOT_EXISTING_TEE = "ItIsNotTotosTEEs\0";

/** ALL_TEEC_UUID
 *
 * These constants are the UUID of existing
 * Trusted Applications
 */
/* "SMARTCSLTERRTOOS" */
static TEEC_UUID UUID_TTA_answerErrorTo_OpenSession = {
	0x534D4152, 0x5443, 0x534C,
	{ 0x54, 0x45, 0x52, 0x52, 0x54, 0x4F, 0x4F, 0x53 }
};
/* "SMART-CSLT-TA-SU" */
static TEEC_UUID UUID_TTA_answerSuccessTo_OpenSession_Invoke = {
	0x534D4152, 0x542D, 0x4353,
	{ 0x4C, 0x54, 0x2D, 0x54, 0x41, 0x2D, 0x53, 0x55 }
};
/* "SMART-CUNK-NO-WN" */
static TEEC_UUID UUID_Unknown = {
	0x534D4152, 0x542D, 0x4355,
	{ 0x4E, 0x4B, 0x2D, 0x4E, 0x4F, 0x2D, 0x57, 0x4E }
};
static TEEC_UUID UUID_TTA_testingClientAPI_Parameters = {
	0x534D4152, 0x5443, 0x534C,
	{ 0x54, 0x43, 0x4C, 0x49, 0x50, 0x41, 0x52, 0x41 }
};
static TEEC_UUID UUID_TTA_testingClientAPI_Parameters_OpenSession = {
	0x534D4152, 0x5443, 0x534C,
	{ 0x54, 0x43, 0x4C, 0x49, 0x50, 0x4F, 0x50, 0x53 }
};
/* "SMART-CSLT-TA-ER" */
static TEEC_UUID UUID_TTA_answerErrorTo_Invoke = {
	0x534D4152, 0x542D, 0x4353,
	{ 0x4C, 0x54, 0x2D, 0x54, 0x41, 0x2D, 0x45, 0x52 }
};
/* "SMART-CSLT-TA-ST" */
static TEEC_UUID UUID_TTA_testingClientAPI = {
	0x534D4152, 0x542D, 0x4353,
	{ 0x4C, 0x54, 0x2D, 0x54, 0x41, 0x2D, 0x53, 0x54 }
};

/*Helper functions/macros*/
#define IDENTIFIER_NOT_USED(x) { if (sizeof(&x)) {} }

#ifdef USER_SPACE
struct thread_arg {
	void *th_arg;
	TEEC_Result res;
};

#define TEEC_createThread(th, func, arg) \
	struct thread_arg *thread_arg; \
	thread_arg = malloc(sizeof(struct thread_arg)); \
	thread_arg->th_arg = (void *)arg; \
	if (!ADBG_EXPECT(c, 0, pthread_create(&th, NULL, func, (void *)thread_arg))) \
		free(thread_arg);

static void *XML_cancellation_thread(void *arg)
{
	struct thread_arg *a = (struct thread_arg *)arg;
	TEEC_Operation *op = (TEEC_Operation *)(a->th_arg);
	(void)usleep(100000);
	TEEC_RequestCancellation(op);
	a->res = TEEC_SUCCESS;
	return NULL;
}

static void *XML_context_thread(void *arg)
{
	struct thread_arg *a = (struct thread_arg *)arg;
	TEEC_Context *ctx = (TEEC_Context *)(a->th_arg);
	a->res = TEEC_InitializeContext(NULL, ctx);
	if (!a->res)
		TEEC_FinalizeContext(ctx);
	return NULL;
}

#define RequestCancellation(th) \
	ADBG_EXPECT(c, 0, pthread_join(th, NULL)); \
	ADBG_EXPECT_TEEC_SUCCESS(c, thread_arg->res); \
	free(thread_arg);
#else
#define TEEC_createThread(th, func, arg)
#define RequestCancellation(th)
#endif

/*Registers the TEEC_SharedMemory to the TEE*/
static TEEC_Result RegisterSharedMemory(TEEC_Context *ctx,
					TEEC_SharedMemory *shm,
					uint32_t size, uint32_t flags)
{
	shm->flags = flags;
	shm->size = size;
	shm->buffer = malloc(size);
	return TEEC_RegisterSharedMemory(ctx, shm);
}

/*Allocates temporary memory area*/
static void AllocateTempMemory(TEEC_TempMemoryReference *temp_mem,
							   uint32_t size)
{
	temp_mem->buffer = malloc(size);
	temp_mem->size = size;
}

static void ReleaseTempMemory(TEEC_TempMemoryReference *temp_mem)
{
	if (temp_mem->buffer)
		free(temp_mem->buffer);
	temp_mem->size = 0;
}

/* Assigns a and b to the value parameter */
static void TEEC_prepare_OperationEachParameter_value(TEEC_Operation *op,
						      size_t n, uint32_t a,
						      uint32_t b)
{
	if (IGNORE != a)
		op->params[n].value.a = a;

	if (IGNORE != b)
		op->params[n].value.b = b;

}

/*Define TEEC_SharedMemory memory content.*/
#define TEEC_defineMemoryContent_sharedMemory(sh_mem, val, size_val) \
	memcpy(sh_mem->buffer, &val, size_val)

/*Define temp memory content.*/
#define TEEC_defineMemoryContent_tmpMemory(buf, val, size_val) \
	memcpy(buf, &(val), size_val)

#define INVOKE_REMEMBER_EXP_PARAM_TYPES(session, cmd, p0, p1, p2, p3, exp) \
	do { \
		memset(OPERATION01, 0x00, sizeof(TEEC_Operation)); \
		OPERATION01->paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, \
							   TEEC_NONE, \
							   TEEC_NONE, \
							   TEEC_NONE); \
		OPERATION01->params[0].value.a = \
			TEEC_PARAM_TYPES((p0), (p1), (p2), (p3)); \
		ADBG_EXPECT(c, exp, \
			    TEEC_InvokeCommand(session, cmd, OPERATION01, \
					       &ret_orig));  \
		ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP, \
					      ret_orig); \
	} while (0)

#define INVOKE_STORE_EXP_PARAM_TYPES(sess, cmd, p_num, p_type, sz_in, val_in, sz_out, val_out, exp_orig, exp_code) \
	do { \
		memset(TMP_OPERATION, 0x00, sizeof(TEEC_Operation)); \
		TMP_OPERATION->params[0].value.a = p_num; \
		TMP_OPERATION->params[0].value.b = p_type; \
		switch(p_type) { \
		case TEE_PARAM_TYPE_NONE: \
		case TEE_PARAM_TYPE_VALUE_INOUT: \
		case TEE_PARAM_TYPE_VALUE_INPUT: \
		case TEE_PARAM_TYPE_VALUE_OUTPUT: \
			TMP_OPERATION->paramTypes = TEEC_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, \
											 TEE_PARAM_TYPE_NONE, \
											 TEE_PARAM_TYPE_NONE, \
											 TEE_PARAM_TYPE_NONE); \
			break; \
		default: \
			TMP_OPERATION->paramTypes = TEEC_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, \
											 TEE_PARAM_TYPE_VALUE_INPUT, \
											 TEE_PARAM_TYPE_VALUE_INPUT, \
											 TEE_PARAM_TYPE_NONE); \
			TMP_OPERATION->params[1].value.a = sz_in; \
			TMP_OPERATION->params[1].value.b = val_in; \
			if (sz_out == IGNORE) \
				TMP_OPERATION->params[2].value.a = 0; \
			else \
				TMP_OPERATION->params[2].value.a = sz_out; \
			if (val_out == IGNORE) \
				TMP_OPERATION->params[2].value.b = 0; \
			else \
				TMP_OPERATION->params[2].value.b = val_out; \
			break; \
		} \
		XML_InvokeCommand(c, sess, cmd, TMP_OPERATION, exp_orig, exp_code); \
	} while (0)


/*Compares two memories and checks if their length and content is the same */
#define TEEC_checkMemoryContent_sharedMemory(op, param_num, shrm, exp_buf, \
					     exp_blen) \
	do { \
		if ((exp_buf) == IGNORE) { \
			ADBG_EXPECT((c), exp_blen, \
				    (op)->params[(param_num)].memref.size); \
		} else { \
			ADBG_EXPECT_COMPARE_POINTER((c), (shrm), ==, \
						    (op)->params[(param_num)].\
							memref.parent); \
			ADBG_EXPECT_BUFFER((c), &(exp_buf), (exp_blen), \
					   (shrm)->buffer, \
					   (op)->params[(param_num)].\
						memref.size); \
		} \
	} while (0)

/*
 * Compares the content of the memory cells in OP with the expected value
 * contained.
 */
#define TEEC_checkMemoryContent_tmpMemory(op, param_num, \
	buf, exp_buf, exp_blen) \
	do { \
		if ((exp_buf) == 0) { \
			ADBG_EXPECT((c), exp_blen, \
				    (op)->params[(param_num)].tmpref.size); \
		} else { \
			ADBG_EXPECT_COMPARE_POINTER((c), (buf), ==, \
						    (op)->params[(param_num)].\
							tmpref.buffer); \
			ADBG_EXPECT_BUFFER((c), &(exp_buf), (exp_blen), \
					   (buf), \
					   (op)->params[(param_num)].\
						memref.size); \
		} \
	} while (0)

/*
 * Compares the content of the memory cells in OP with the expected value
 * contained.
 */
#define TEEC_checkContent_Parameter_value(op, param_num, exp_a, exp_b) \
	do { \
		if (IGNORE != exp_a) \
			ADBG_EXPECT((c), exp_a, \
				    (op)->params[(param_num)].value.a); \
		if (IGNORE != exp_b) \
			ADBG_EXPECT((c), exp_b, \
				    (op)->params[(param_num)].value.b); \
	} while (0)

/*Invoke command using TEEC_InvokeCommand and check the returned value.*/
#define XML_InvokeCommand(c, session, cmd, operation, returnOrigin, expected) \
	do { \
		ADBG_EXPECT(c, expected, \
			    TEEC_InvokeCommand(session, cmd, operation, \
					       &ret_orig)); \
		if (returnOrigin != 0) \
			ADBG_EXPECT(c, (int)returnOrigin, ret_orig); \
	} while (0)

#ifdef WITH_GP_TESTS
/*
 * Required by Global Platform test suite for v2.0
 */

/* Assigns parent, offset and size to the memref parameter */
static void TEEC_prepare_OperationEachParameter_memref(TEEC_Operation *op,
	size_t n,
	TEEC_SharedMemory *parent, unsigned offset,
	unsigned size)
{
	op->params[n].memref.parent = parent;
	op->params[n].memref.offset = offset;
	op->params[n].memref.size = size;
}

/* Assigns buffer and size to the tmpref parameter */
static void TEEC_prepare_OperationEachParameter_tmpref(TEEC_Operation *op,
						       size_t n,
						       TEEC_TempMemoryReference *tmp_mem,
						       unsigned size)
{
	op->params[n].tmpref.buffer = tmp_mem->buffer;
	op->params[n].tmpref.size = size;
}

#define TEEC_initialize_memory(sh_mem, tmp_mem, offset, in_sz, val_01, val_02, val_03) \
do { \
	uint8_t *fill_ptr; \
	if ((uintptr_t)sh_mem != IGNORE) { \
		if (((TEEC_SharedMemory*)sh_mem)->buffer) { \
			fill_ptr = ((TEEC_SharedMemory*)sh_mem)->buffer; \
			memset(fill_ptr, val_01, offset); \
			memset(fill_ptr + offset, val_02, in_sz); \
			memset(fill_ptr + offset + in_sz, val_03, ((TEEC_SharedMemory*)sh_mem)->size - in_sz - offset); \
		} \
	} \
	if ((uintptr_t)tmp_mem != IGNORE) { \
		if (((TEEC_TempMemoryReference*)tmp_mem)->buffer) { \
			fill_ptr = ((TEEC_TempMemoryReference*)tmp_mem)->buffer; \
			memset(fill_ptr, val_01, offset); \
			memset(fill_ptr + offset, val_02, in_sz); \
			memset(fill_ptr + offset + in_sz, val_03, ((TEEC_TempMemoryReference*)tmp_mem)->size - in_sz - offset); \
		} \
	} \
} while(0);

#endif

#endif /* XML_CLIENT_API_H_ */
