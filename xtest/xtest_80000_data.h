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

#ifndef XTEST_80000_DATA_H
#define XTEST_80000_DATA_H

#include <string.h>
#include "xml_common_api.h"

#define Invoke_GetPropertyAsXXXX_fromEnum Invoke_StartPropertyEnumerator

#define TEEC_OPERATION_INITIALIZER { 0 }
static uint32_t big_size = BIG_SIZE;

/* Extra tests. */
#define TA_PROPS_UUID { 0xacd1cbcc, 0x5fb2, 0x407b, \
                        { 0xb7, 0x55, 0x40, 0xe8, 0xbe, 0xbe, 0x33, 0x75 } };

#define CMD_TEE_AllocatePropertyEnumerator 0x00000060
#define CMD_TEE_StartPropertyEnumerator    0x00000065
#define CMD_TEE_ResetPropertyEnumerator    0x00000070
#define CMD_TEE_GetPropertyNameAndAdvance  0x00000081
#define TA_KEEP_ALIVE_CMD_INC              0x000000F1
#define CMD_TEE_TestPrivilegedSyscalls     0x000000F2

#define TA_SESSION01                    0
#define TA_SESSION02                    1

static TEEC_SharedMemory *SHARE_MEM01;
static TEEC_SharedMemory *SHARE_MEM02;
static TEEC_Session *SESSION01;
static TEEC_Context *CONTEXT01;
static TEEC_Operation *OPERATION01;

uint32_t *ENUMERATOR1;

/* "SMART-CSLT-TA-01" */
static TEEC_UUID UUID_TTA_testingInternalAPI_TrustedCoreFramework = {
	0x534D4152, 0x542D, 0x4353,
	{ 0x4C, 0x54, 0x2D, 0x54, 0x41, 0x2D, 0x30, 0x31 }
};

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

static TEEC_Result Invoke_GetPropertyNameDuplicate(ADBG_Case_t *c,
                                                   TEEC_Session *sess,
                                                   uint32_t cmdId,
                                                   uint32_t *enumerator,
                                                   char *propertyName)
{
    TEEC_Result res = TEE_SUCCESS;
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    uint32_t org;
    uint32_t strLen = 0;
    int help_cmp;
    int prop_cnt = 0;
    (void)c;

    ALLOCATE_SHARED_MEMORY(sess->ctx, SHARE_MEM01, big_size,
                           TEEC_MEM_OUTPUT, mem01_exit);
    op.params[0].value.a = *enumerator;
    SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
                                          SHARE_MEM01->size);

    op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT,
                                      TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE,
                                      TEEC_NONE);

    while ( res == TEE_SUCCESS) {
        res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

        if ((res != TEE_SUCCESS) && (res != TEE_ERROR_ITEM_NOT_FOUND))
            goto exit;

        strLen = strlen(propertyName) + 1;

        help_cmp = memcmp(SHARE_MEM01->buffer, propertyName, strLen);
        if (0 == help_cmp) {
            prop_cnt++;
        }
        /* Reset the parameter to fix size (The same buffer is used for
         * obtaining all the names).
         */
        SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
                                              SHARE_MEM01->size);
    }

    if (prop_cnt > 1) {
        printf("The property %s has a duplicate\n", propertyName);
        res = TEE_SUCCESS;
    }

exit:
    TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
    return res;
}

static TEEC_Result Invoke_GetAndPrintPropertyAsXXX_withoutEnum(
    ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
    uint32_t propSet, const char *name)
{
    TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    uint32_t org;
    uint32_t nameLen = 0;
    (void)c;

    if (name) {
        nameLen = strlen(name) + 1;
        ALLOCATE_AND_FILL_SHARED_MEMORY(sess->ctx, SHARE_MEM01, big_size,
                        TEEC_MEM_INPUT, nameLen, name, mem01_exit);
    } else {
        SHARE_MEM01->buffer = NULL;
        SHARE_MEM01->size = 0;
        SHARE_MEM01->flags = 0;
    }

    ALLOCATE_SHARED_MEMORY(sess->ctx, SHARE_MEM02, big_size,
                       TEEC_MEM_OUTPUT, mem02_exit);

    op.params[0].value.a = (uint32_t)propSet;
    SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01, nameLen);
    SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
                          SHARE_MEM02->size);

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT,
        TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE);

    res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

    if (res != TEEC_SUCCESS)
        goto exit;

    printf("Got propery %s value %s\n", name, (char*)op.params[2].memref.parent->buffer);

exit:
    TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
    if (name)
    TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
    return res;
}

#endif /* XTEST_80000_DATA_H */
