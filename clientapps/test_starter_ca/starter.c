/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stddef.h>
#include <stdio.h>
#include <tee_client_api.h>

/* UUID : {7b9c56be-e448-11e5-9730-9a79f06e9478} */
#define TA_TEST_SERVER_UUID { 0x7b9c56be, 0xe448, 0x11e5,  \
    { 0x97, 0x30, 0x9a, 0x79, 0xf0, 0x6e, 0x94, 0x78 } }

/* The CMD IDs implemented in TA_TEST_SERVER */
#define TA_HELLO_WORLD_CMD_INC_VALUE  0xbabadeda
#define TA_HELLO_WORLD_CMD_INC_MEMREF 0xbabadedb

/* UUID : {6c385b92-e514-11e5-9730-9a79f06e9478} */
#define TA_TEST_CLIENT_UUID { 0xf74df2bd, 0x58b6, 0x4503, \
    { 0x9a, 0xa1, 0xf6, 0x8f, 0xa8, 0xf3, 0x1a, 0xa9 } }

/* UUID : {087446df-056a-450f-a08a-8cf8821eacab} */
#define TA_TEST_CLIENT2_UUID { 0x087446df, 0x056a, 0x450f, \
    { 0xa0, 0x8a, 0x8c, 0xf8, 0x82, 0x1e, 0xac, 0xab } }

#define PREFIX_STR "TA Starter:   "
#define DPRINTF(...) printf(PREFIX_STR __VA_ARGS__)

TEEC_Context teetest_teec_ctx;

static void start_ta_test(void)
{
    TEEC_Result res = TEEC_SUCCESS;
    uint32_t ret_orig;
#define MAX_SESSIONS    2
    TEEC_Session sessions[MAX_SESSIONS];
    TEEC_UUID uuids[MAX_SESSIONS] = {
        TA_TEST_CLIENT_UUID,
        TA_TEST_CLIENT2_UUID,
    };
    int i;

    printf("%s ...\n", __func__);
    res = TEEC_InitializeContext(NULL, &teetest_teec_ctx);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed [%x]\n", res);
	goto err_out;
    }

    for (i = 0; i < MAX_SESSIONS; i++) {
        res = TEEC_OpenSession(&teetest_teec_ctx, &sessions[i], &uuids[i],
                    TEEC_LOGIN_PUBLIC, NULL, NULL, &ret_orig);

        if (res != TEEC_SUCCESS)
            printf("TEEC_OpenSession sessions[%d] returned %x. FAILED\n", i, res);
    }

    for (; --i >= 0; )
        TEEC_CloseSession(&sessions[i]);

    TEEC_FinalizeContext(&teetest_teec_ctx);
err_out:
    printf("%s done.\n", __func__);
}

static void call_ta_test_server(void)
{
    TEEC_Result res = TEEC_SUCCESS;
    uint32_t ret_orig;
    TEEC_Session session;
    TEEC_UUID server_uuid = TA_TEST_SERVER_UUID;
    TEEC_Operation op = { 0 };
    const uint32_t TEST_VALUE = 33;
    uint32_t value = TEST_VALUE;

    printf("%s ...\n", __func__);
    res = TEEC_InitializeContext(NULL, &teetest_teec_ctx);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed [%x]\n", res);
	goto err_out;
    }

    res = TEEC_OpenSession(&teetest_teec_ctx, &session, &server_uuid,
        TEEC_LOGIN_PUBLIC, NULL, NULL, &ret_orig);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_OpenSession session returned %x. FAILED\n", res);
	goto err_close_ctx;
    }

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE,
                    TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = &value;
    op.params[0].tmpref.size = sizeof(value);

    res = TEEC_InvokeCommand(&session, TA_HELLO_WORLD_CMD_INC_MEMREF,
                             &op, &ret_orig);
    if (res != TEEC_SUCCESS)
        printf("TEEC_InvokeCommand returned %x. FAILED\n", res);
    else
	printf("Server TA incremented value to %d. %s\n", value,
			(value == (TEST_VALUE + 1)) ? "PASSED" : "FAILED");

    TEEC_CloseSession(&session);
err_close_ctx:
    TEEC_FinalizeContext(&teetest_teec_ctx);
err_out:
    printf("%s done.\n", __func__);
}

int main(void)
{
    start_ta_test();
    call_ta_test_server();
    return 0;
}
