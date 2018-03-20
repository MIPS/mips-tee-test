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

#include <stdio.h>
#include <stdlib.h>
#include "xtest_test.h"
#include "xtest_helpers.h"
#include "xtest_ta_defines.h"
#include "xtest_80000_data.h"

#define TEST_PROPSET_BAD 0

static bool xtest_init = false;

static bool xtest_tee_init(ADBG_Case_t *c)
{
    if (xtest_init) {
        return true;
    }
    SHARE_MEM01 = malloc(sizeof(TEEC_SharedMemory));
    if (!ADBG_EXPECT_NOT_NULL(c, SHARE_MEM01)) {
        goto exit;
    }
    SHARE_MEM02 = malloc(sizeof(TEEC_SharedMemory));
    if (!ADBG_EXPECT_NOT_NULL(c, SHARE_MEM02)) {
        goto exit;
    }
    SESSION01 = malloc(sizeof(TEEC_Session));
    if (!ADBG_EXPECT_NOT_NULL(c, SESSION01)) {
        goto exit;
    }
    CONTEXT01 = malloc(sizeof(TEEC_Context));
    if (!ADBG_EXPECT_NOT_NULL(c, CONTEXT01)) {
        goto exit;
    }
    OPERATION01 = malloc(sizeof(TEEC_Operation));
    if (!ADBG_EXPECT_NOT_NULL(c, OPERATION01)) {
        goto exit;
    }
    ENUMERATOR1 = malloc(sizeof(uint32_t));
    if (!ADBG_EXPECT_NOT_NULL(c, ENUMERATOR1)) {
        goto exit;
    }

    xtest_init = true;

    return xtest_init;

exit:
    if (SHARE_MEM01) {
      free(SHARE_MEM01);
      SHARE_MEM01 = NULL;
    }
    if (SHARE_MEM02) {
      free(SHARE_MEM02);
      SHARE_MEM02 = NULL;
    }
    if (SESSION01) {
      free(SESSION01);
      SESSION01 = NULL;
    }
    if (CONTEXT01) {
      free(CONTEXT01);
      CONTEXT01 = NULL;
    }
    if (OPERATION01) {
      free(OPERATION01);
      OPERATION01 = NULL;
    }
    if (ENUMERATOR1) {
      free(ENUMERATOR1);
      ENUMERATOR1 = NULL;
    }

    xtest_init = false;
    return xtest_init;
}

static void xtest_tee_deinit(void)
{
    if (SHARE_MEM01) {
      free(SHARE_MEM01);
      SHARE_MEM01 = NULL;
    }
    if (SHARE_MEM02) {
      free(SHARE_MEM02);
      SHARE_MEM02 = NULL;
    }
    if (SESSION01) {
      free(SESSION01);
      SESSION01 = NULL;
    }
    if (CONTEXT01) {
      free(CONTEXT01);
      CONTEXT01 = NULL;
    }
    if (OPERATION01) {
      free(OPERATION01);
      OPERATION01 = NULL;
    }
    if (ENUMERATOR1) {
      free(ENUMERATOR1);
      ENUMERATOR1 = NULL;
    }

    xtest_init = false;
}

static void xtest_tee_test_80100(ADBG_Case_t *c)
{
    if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
        return ;
    TEEC_SetUp_TEE();
    TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
    XML_InitializeContext(c, _device, CONTEXT01, TEEC_SUCCESS);
    XML_OpenSession(c, CONTEXT01, SESSION01, &UUID_TTA_testingInternalAPI_TrustedCoreFramework, TEEC_LOGIN_PUBLIC, NULL, NULL, NULL, TEEC_SUCCESS);
    ADBG_EXPECT(c, TEE_ERROR_TARGET_DEAD, Invoke_GetPropertyAsXXXX_fromEnum(c, SESSION01, CMD_TEE_GetPropertyAsXXXX_fromEnum, ENUMERATOR1, TEE_PROPSET_CURRENT_CLIENT));
    TEEC_CloseSession(SESSION01);
    TEEC_FinalizeContext(CONTEXT01);
    TEEC_TearDown_TEE(INITIAL_STATE);
    xtest_tee_deinit();
}

static void xtest_tee_test_80101(ADBG_Case_t *c)
{
    if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
        return ;
    TEEC_SetUp_TEE();
    TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
    XML_InitializeContext(c, _device, CONTEXT01, TEEC_SUCCESS);
    XML_OpenSession(c, CONTEXT01, SESSION01, &UUID_TTA_testingInternalAPI_TrustedCoreFramework, TEEC_LOGIN_PUBLIC, NULL, NULL, NULL, TEEC_SUCCESS);
    ADBG_EXPECT(c, TEE_ERROR_TARGET_DEAD, Invoke_ResetPropertyEnumerator(c, SESSION01, CMD_TEE_ResetPropertyEnumerator, ENUMERATOR1));
    TEEC_CloseSession(SESSION01);
    TEEC_FinalizeContext(CONTEXT01);
    TEEC_TearDown_TEE(INITIAL_STATE);
    xtest_tee_deinit();
}

static void xtest_tee_test_80102(ADBG_Case_t *c)
{
    if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
        return ;
    TEEC_SetUp_TEE();
    TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
    XML_InitializeContext(c, _device, CONTEXT01, TEEC_SUCCESS);
    XML_OpenSession(c, CONTEXT01, SESSION01, &UUID_TTA_testingInternalAPI_TrustedCoreFramework, TEEC_LOGIN_PUBLIC, NULL, NULL, NULL, TEEC_SUCCESS);
    ADBG_EXPECT(c, TEE_ERROR_TARGET_DEAD, Invoke_StartPropertyEnumerator(c, SESSION01, CMD_TEE_ResetPropertyEnumerator, ENUMERATOR1, TEST_PROPSET_BAD));
    TEEC_CloseSession(SESSION01);
    TEEC_FinalizeContext(CONTEXT01);
    TEEC_TearDown_TEE(INITIAL_STATE);
    xtest_tee_deinit();
}

static void xtest_tee_test_80103(ADBG_Case_t *c)
{
    if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
        return ;
    TEEC_SetUp_TEE();
    TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
    XML_InitializeContext(c, _device, CONTEXT01, TEEC_SUCCESS);
    XML_OpenSession(c, CONTEXT01, SESSION01, &UUID_TTA_testingInternalAPI_TrustedCoreFramework, TEEC_LOGIN_PUBLIC, NULL, NULL, NULL, TEEC_SUCCESS);
    ADBG_EXPECT(c, TEE_ERROR_TARGET_DEAD, Invoke_GetPropertyAsXXXX_fromEnum(c, SESSION01, CMD_TEE_ResetPropertyEnumerator, ENUMERATOR1, TEST_PROPSET_BAD));
    TEEC_CloseSession(SESSION01);
    TEEC_FinalizeContext(CONTEXT01);
    TEEC_TearDown_TEE(INITIAL_STATE);
    xtest_tee_deinit();
}

static void xtest_tee_test_80104(ADBG_Case_t *c)
{
    int i;
    TEEC_Result res;
    uint32_t return_orig;
    uint32_t param_0_init = 21;
    const TEEC_UUID ta_keep_alive_uuid = TA_PROPS_UUID;

    if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
        return ;
    TEEC_SetUp_TEE();
    TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
    Do_ADBG_BeginSubCase(c, "Test keep alive property");
    for (i = 1; i < 4; i++) {
      /* uses TEEC_Context xtest_teec_ctx; instead of CONTEXT01 */
      res = xtest_teec_open_session(SESSION01, &ta_keep_alive_uuid, NULL, &return_orig);
      if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
        return;
      OPERATION_TEEC_PARAM_TYPES(OPERATION01, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
      OPERATION01->params[0].value.a = param_0_init;
      OPERATION01->params[0].value.b = 0;
      ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(SESSION01, TA_KEEP_ALIVE_CMD_INC, OPERATION01, &return_orig));
      ADBG_EXPECT(c, i * param_0_init, OPERATION01->params[0].value.b);
      TEEC_CloseSession(SESSION01);
    }
    Do_ADBG_EndSubCase(c, NULL);

    Do_ADBG_BeginSubCase(c, "Test keep alive property when there is an error in application.");
    OPERATION_TEEC_PARAM_TYPES(OPERATION01, TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    /* uses TEEC_Context xtest_teec_ctx; instead of CONTEXT01 */
    res = xtest_teec_open_session(SESSION01, &ta_keep_alive_uuid, OPERATION01, &return_orig);
    if (!ADBG_EXPECT_TEEC_RESULT(c,  TEE_ERROR_GENERIC, res))
      return;

    /* uses TEEC_Context xtest_teec_ctx; instead of CONTEXT01 */
    res = xtest_teec_open_session(SESSION01, &ta_keep_alive_uuid, NULL, &return_orig);
    if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
      return;
    OPERATION_TEEC_PARAM_TYPES(OPERATION01, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    OPERATION01->params[0].value.a = param_0_init;
    OPERATION01->params[0].value.b = 0;
    ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(SESSION01, TA_KEEP_ALIVE_CMD_INC, OPERATION01, &return_orig));
    ADBG_EXPECT(c, 4 * param_0_init, OPERATION01->params[0].value.b);
    TEEC_CloseSession(SESSION01);
    Do_ADBG_EndSubCase(c, NULL);

    TEEC_TearDown_TEE(INITIAL_STATE);
    xtest_tee_deinit();
}

static void xtest_tee_test_80105(ADBG_Case_t *c)
{
    TEEC_Result res;
    uint32_t return_orig;
    const TEEC_UUID ta_props_uuid = TA_PROPS_UUID;

    if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
        return ;
    TEEC_SetUp_TEE();
    TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
    /* uses TEEC_Context xtest_teec_ctx; instead of CONTEXT01 */
    res = xtest_teec_open_session(SESSION01, &ta_props_uuid, NULL, &return_orig);
    if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
      return;
    ADBG_EXPECT(c, TEEC_SUCCESS, Invoke_AllocatePropertyEnumerator(c, SESSION01, CMD_TEE_AllocatePropertyEnumerator, ENUMERATOR1));
    ADBG_EXPECT(c, TEEC_SUCCESS, Invoke_StartPropertyEnumerator(c, SESSION01, CMD_TEE_StartPropertyEnumerator, ENUMERATOR1, TEE_PROPSET_CURRENT_TA));
    ADBG_EXPECT(c, TEE_ERROR_ITEM_NOT_FOUND, Invoke_GetPropertyNameDuplicate(c, SESSION01, CMD_TEE_GetPropertyNameAndAdvance, ENUMERATOR1, (char *)"gpd.ta.instanceKeepAlive"));
    TEEC_CloseSession(SESSION01);
    TEEC_TearDown_TEE(INITIAL_STATE);
    xtest_tee_deinit();
}

static void xtest_tee_test_80106(ADBG_Case_t *c)
{
    TEEC_Result res;
    uint32_t return_orig;
    const TEEC_UUID ta_props_uuid = TA_PROPS_UUID;

    if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
        return ;
    TEEC_SetUp_TEE();
    TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);

    /* uses TEEC_Context xtest_teec_ctx; instead of CONTEXT01 */
    res = xtest_teec_open_session(SESSION01, &ta_props_uuid, NULL, &return_orig);
    if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
      return;
    OPERATION_TEEC_PARAM_TYPES(OPERATION01, TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    ADBG_EXPECT(c, TEEC_ERROR_NOT_SUPPORTED, TEEC_InvokeCommand(SESSION01, CMD_TEE_TestPrivilegedSyscalls, OPERATION01, &return_orig));
    TEEC_CloseSession(SESSION01);

    TEEC_TearDown_TEE(INITIAL_STATE);
    xtest_tee_deinit();
}

#define NUM_PROPS       14
#define MAX_NAME_LEN    100

const char impl_properties[NUM_PROPS][MAX_NAME_LEN] =
{ "gpd.tee.apiversion\0",
  "gpd.tee.description\0",
  "gpd.tee.deviceID\0",
  "gpd.tee.systemTime.protectionLevel\0",
  "gpd.tee.TAPersistentTime.protectionLevel\0",
  "gpd.tee.arith.maxBigIntSize\0",
  "gpd.tee.cryptography.ecc\0",
  "gpd.tee.trustedStorage.antiRollback.protectionLevel\0",
  "gpd.tee.trustedos.implementation.version\0",
  "gpd.tee.trustedos.implementation.binaryversion\0",
  "gpd.tee.trustedos.manufacturer\0",
  "gpd.tee.firmware.implementation.version\0",
  "gpd.tee.firmware.implementation.binaryversion\0",
  "gpd.tee.firmware.manufacturer\0"
};

static void xtest_tee_test_80107(ADBG_Case_t *c)
{
    int i;

    if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
        return ;
    TEEC_SetUp_TEE();
    TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
    XML_InitializeContext(c, _device, CONTEXT01, TEEC_SUCCESS);
    XML_OpenSession(c, CONTEXT01, SESSION01, &UUID_TTA_testingInternalAPI_TrustedCoreFramework, TEEC_LOGIN_PUBLIC, NULL, NULL, NULL, TEEC_SUCCESS);

    for (i = 0; i < NUM_PROPS; i++) {
        ADBG_EXPECT(c, TEE_SUCCESS,
            Invoke_GetAndPrintPropertyAsXXX_withoutEnum(c, SESSION01,
                CMD_TEE_GetPropertyAsString_withoutEnum,
                TEE_PROPSET_TEE_IMPLEMENTATION, impl_properties[i]));
    }
    TEEC_CloseSession(SESSION01);

    TEEC_FinalizeContext(CONTEXT01);
    TEEC_TearDown_TEE(INITIAL_STATE);
}

ADBG_CASE_DEFINE(XTEST_TEE_80100, xtest_tee_test_80100,
		/* Title */
		"Get property as XXX with enumerator not allocated",
		/* Short description */
		"Verify that trying to obtain property form enumerator"
		"before enumerator is allocated will result in TA panic",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_80101, xtest_tee_test_80101,
		/* Title */
		"Reset property with enumerator not allocated",
		/* Short description */
		"Verify that trying to reset enumerator before it"
		"is allocated will result in TA panic",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_80102, xtest_tee_test_80102,
		/* Title */
		"Start enumerator with erroneous property set ID",
		/* Short description */
		"Verify that trying to start enumerator with erroneous"
		"property set ID will result in TA panic",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_80103, xtest_tee_test_80103,
		/* Title */
		"Get property as XXX from enumerator with erroneous property set ID",
		/* Short description */
		"Verify that trying to obtain property form enumerator"
		"with erroneous property set ID will result in TA panic",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );
ADBG_CASE_DEFINE(XTEST_TEE_80104, xtest_tee_test_80104,
    /* Title */
    "Test keep alive property",
    /* Short description */
    "Verify that instance of keep alive TA will stay even"
    "after all the sessions opened on that instance are closed",
    /* Requirement IDs */
    "TEE-??",
    /* How to implement */
    "Description of how to implement ..."
     );
ADBG_CASE_DEFINE(XTEST_TEE_80105, xtest_tee_test_80105,
    /* Title */
    "Test duplicate property",
    /* Short description */
    "Verify that duplicate properties of TA are fitered out",
    /* Requirement IDs */
    "TEE-??",
    /* How to implement */
    "Description of how to implement ..."
     );
ADBG_CASE_DEFINE(XTEST_TEE_80106, xtest_tee_test_80106,
    /* Title */
    "Test privileged syscalls on normal TA",
    /* Short description */
    "Verify that privileged syscalls cannot be called from the normal TA",
    /* Requirement IDs */
    "TEE-??",
    /* How to implement */
    "Description of how to implement ..."
     );
ADBG_CASE_DEFINE(XTEST_TEE_80107, xtest_tee_test_80107,
    /* Title */
    "Print implementation defined properties",
    /* Short description */
    "Print out the TEE Implementation Properties, as there are no other means"
    "of testing",
    /* Requirement IDs */
    "TEE-??",
    /* How to implement */
    "Description of how to implement ..."
     );
