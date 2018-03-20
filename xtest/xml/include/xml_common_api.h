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

#ifndef XML_COMMON_API_H_
#define XML_COMMON_API_H_

#include "tee_client_api.h"

#define BIG_SIZE 1024

/*Helper functions/macros*/
#define IDENTIFIER_NOT_USED(x) { if (sizeof(&x)) {} }

#define CLIENT_APP01  NULL
#define INITIAL_STATE 0
#define TEEC_UNDEFINED_ERROR 0xDEADDEAD
#define TEEC_ORIGIN_ANY_NOT_TRUSTED_APP  0x00000005

/* XML_VERIFY macro define.
 *
 * Use ADBG_EXPECT or ADBG_EXPECT_NOT depending on the
 * expected return value.
 *
 * ADBG_EXPECT() -> IF(EXP == GOT) RETURN TRUE
 * ADBG_EXPECT() -> IF(EXP != GOT) RETURN TRUE
 */
#define XML_VERIFY(c, exp, got) \
	do { \
		if (exp == TEEC_UNDEFINED_ERROR) \
			ADBG_EXPECT_NOT(c, exp, got); \
		else \
			ADBG_EXPECT(c, exp, got); \
	} while (0)

/* Initialize context using TEEC_InitializeContext and
	check the returned value. */
#define XML_InitializeContext(c, name, context, expected) \
	XML_VERIFY(c, expected, TEEC_InitializeContext(name, context))

/* Open session using TEEC_OpenSession and
	check the returned value and/or returned origin. */
#define XML_OpenSession(c, context, session, destination, connectionMethod, \
			connectionData, operation, returnOrigin, expected) \
	do { \
		uint32_t ret; \
		XML_VERIFY(c, expected, \
			   TEEC_OpenSession(context, session, destination, \
					    connectionMethod, connectionData, \
					    operation, &ret)); \
		if ((returnOrigin != 0) && \
		    ((int)returnOrigin != TEEC_ORIGIN_ANY_NOT_TRUSTED_APP)) \
			ADBG_EXPECT(c, (int)returnOrigin, ret); \
		else \
			ADBG_EXPECT_NOT(c, (int)returnOrigin, ret); \
	} while (0)

#define OPERATION_TEEC_PARAM_TYPES(op, p0, p1, p2, p3) \
	do { \
		op->paramTypes = TEEC_PARAM_TYPES(p0, p1, p2, p3); \
	} while (0)
/*dummy functions*/
#define TEEC_SetUp_TEE()        /*do nothing for now*/
#define TEEC_TearDown_TEE(a)    /*do nothing for now*/
#define TEEC_SelectApp(a, b)    /*do nothing for now*/

/* Allocates TEEC_SharedMemory inside of the TEE */
static TEEC_Result AllocateSharedMemory(TEEC_Context *ctx,
					TEEC_SharedMemory *shm, uint32_t size,
					uint32_t flags)
{
	shm->flags = flags;
	shm->size = size;
	return TEEC_AllocateSharedMemory(ctx, shm);
}

#define ALLOCATE_SHARED_MEMORY(context, sharedMemory, sharedMemorySize, \
			       memoryType, exit_label) \
do { \
	res = AllocateSharedMemory(context, sharedMemory, sharedMemorySize, \
				   memoryType); \
	if (res != TEEC_SUCCESS) { \
		goto exit_label; \
	} \
	memset(sharedMemory->buffer, 0, sharedMemorySize); \
} while (0)

#define ALLOCATE_AND_FILL_SHARED_MEMORY(context, sharedMemory, \
					sharedMemorySize, \
					memoryType, copySize, data, \
					exit_label) \
do { \
	res = AllocateSharedMemory(context, sharedMemory, sharedMemorySize, \
				   memoryType); \
	if (res != TEEC_SUCCESS) { \
		goto exit_label; \
	} \
	memset(sharedMemory->buffer, 0, sharedMemorySize); \
	if (data != NULL) { \
		memcpy(sharedMemory->buffer, data, copySize); \
	} \
} while (0)

#define ALLOCATE_AND_FILL_SHARED_MEMORY_6(a,b,c,d,e,f) \
		        ALLOCATE_AND_FILL_SHARED_MEMORY(a,b,c,d,c,e,f)

#define SET_SHARED_MEMORY_OPERATION_PARAMETER(parameterNumber, \
					      sharedMemoryOffset, \
					      sharedMemory, \
					      sharedMemorySize) \
do { \
	op.params[parameterNumber].memref.offset = sharedMemoryOffset; \
	op.params[parameterNumber].memref.size = sharedMemorySize; \
	op.params[parameterNumber].memref.parent = sharedMemory; \
} while (0)

#endif /* XML_COMMON_API_H_ */
