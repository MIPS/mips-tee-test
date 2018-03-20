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
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "xtest_test.h"
#include "xtest_helpers.h"
#include "xtest_ta_defines.h"
#include <tee_client_api_extensions.h>

static void sleep_ms(uint32_t ms)
{
	struct timespec ts;

	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000000;
	nanosleep(&ts, NULL);
}

static void xtest_tee_test_1100(ADBG_Case_t *c)
{
	TEEC_Result res;
#define MAX_SESSIONS    4
	TEEC_Session session[MAX_SESSIONS] = {{ 0 }};
	uint32_t ret_orig;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	int i;
	uint32_t param_0_init = 21;

	for (i = 0; i < MAX_SESSIONS; i++) {
		Do_ADBG_BeginSubCase(c, "Multi Instance memref mapping iteration %d", i);
		res = xtest_teec_open_session(&session[i],
				&multi_instance_memref_ta_uuid, NULL,
				&ret_orig);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			return;

		op.params[0].value.a = i * param_0_init;
		op.params[0].value.b = 0;
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
				 TEEC_NONE, TEEC_NONE);

		res = TEEC_InvokeCommand(&session[i], TA_MULTI_INSTANCE_MEMREF_CMD, &op, &ret_orig);
		ADBG_EXPECT_TEEC_SUCCESS(c, res);
		ADBG_EXPECT(c, i * param_0_init, op.params[0].value.b);
		Do_ADBG_EndSubCase(c, NULL);
	}

	for (; --i >= 0; )
		TEEC_CloseSession(&session[i]);

#undef MAX_SESSIONS
}

static void xtest_tee_test_1101(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session = { 0 };
	uint32_t ret_orig;

	Do_ADBG_BeginSubCase(c, "Load TA with bad manifest");
	res = xtest_teec_open_session(&session,
			&bad_manifest_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_BAD_PARAMETERS, res))
		return;

	if (res == TEEC_SUCCESS)
		TEEC_CloseSession(&session);

	Do_ADBG_EndSubCase(c, NULL);
}

// Ideally this test would verify the core TEE Framework's ability to protect
// itself from unexpected 64bit values. In practice the Client API is the place
// where this protection is implemented (either explicitly or using a cast) and
// where violations are reported to the client application. As a result this
// test actually exercises the Client API and not the TEE Framework.
static void xtest_tee_test_1102(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_SharedMemory parent_in;
	static const uint8_t in[8] =
		{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
	uint8_t out[8] = { 0 };

	// skip test on 64bit systems
	if (sizeof(uint64_t) == sizeof(uintptr_t))
		return;

	res = xtest_teec_open_session(&session,
			&sims_test_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	//===================================================================

	Do_ADBG_BeginSubCase(c, "TEEC_MEMREF_TEMP 64bit padding overflow");

	// set the padding fields to non-zero values to ensure they are ignored
	memset(&op.params, 0xff, sizeof(op.params));
	op.params[0].value.a = 0;
	op.params[1].tmpref.buffer = (void *)in;
	op.params[1].tmpref.size = sizeof(in);
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&session, TA_SIMS_CMD_WRITE, &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	memset(&op.params, 0xff, sizeof(op.params));
	op.params[0].value.a = 0;
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = sizeof(out);
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					TEEC_MEMREF_TEMP_OUTPUT,
					TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&session, TA_SIMS_CMD_READ, &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	if (!ADBG_EXPECT_BUFFER(c, in, sizeof(in), out,
				sizeof(out))) {
		Do_ADBG_Log("in:");
		Do_ADBG_HexLog(in, sizeof(in), 16);
		Do_ADBG_Log("out:");
		Do_ADBG_HexLog(out, sizeof(out), 16);
	}

	Do_ADBG_EndSubCase(c, NULL);

	//===================================================================

	Do_ADBG_BeginSubCase(c, "TEEC_MEMREF_WHOLE 64bit padding overflow");

	memset(&op.params, 0xff, sizeof(op.params));
	memset(&parent_in, 0xff, sizeof(parent_in));
	op.params[0].value.a = 0;
	op.params[1].memref.parent = &parent_in;
	op.params[1].memref.parent->buffer = (void *)in;
	op.params[1].memref.parent->size = sizeof(in);
	op.params[1].memref.parent->flags = TEEC_MEM_INPUT;
	TEEC_RegisterSharedMemory(session.ctx, &parent_in);
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_WHOLE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&session, TA_SIMS_CMD_WRITE, &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	TEEC_ReleaseSharedMemory(&parent_in);

	memset(&op.params, 0xff, sizeof(op.params));
	memset(&parent_in, 0xff, sizeof(parent_in));
	op.params[0].value.a = 0;
	op.params[1].memref.parent = &parent_in;
	op.params[1].memref.parent->buffer = (void *)out;
	op.params[1].memref.parent->size = sizeof(out);
	op.params[1].memref.parent->flags = TEEC_MEM_OUTPUT;
	TEEC_RegisterSharedMemory(session.ctx, &parent_in);
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_WHOLE,
					TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&session, TA_SIMS_CMD_READ, &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	if (!ADBG_EXPECT_BUFFER(c, in, sizeof(in), out,
				sizeof(out))) {
		Do_ADBG_Log("in:");
		Do_ADBG_HexLog(in, sizeof(in), 16);
		Do_ADBG_Log("out:");
		Do_ADBG_HexLog(out, sizeof(out), 16);
	}
	TEEC_ReleaseSharedMemory(&parent_in);

	Do_ADBG_EndSubCase(c, NULL);

	//===================================================================

	Do_ADBG_BeginSubCase(c, "TEEC_MEMREF_PARTIAL 64bit padding overflow");

	memset(&op.params, 0xff, sizeof(op.params));
	memset(&parent_in, 0xff, sizeof(parent_in));
	op.params[0].value.a = 0;
	op.params[1].memref.parent = &parent_in;
	op.params[1].memref.parent->buffer = (void *)in;
	op.params[1].memref.parent->size = sizeof(in);
	op.params[1].memref.parent->flags = TEEC_MEM_INPUT;
	op.params[1].memref.size = sizeof(in);
	op.params[1].memref.offset = 0;
	TEEC_RegisterSharedMemory(session.ctx, &parent_in);
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&session, TA_SIMS_CMD_WRITE, &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	TEEC_ReleaseSharedMemory(&parent_in);

	memset(&op.params, 0xff, sizeof(op.params));
	memset(&parent_in, 0xff, sizeof(parent_in));
	op.params[0].value.a = 0;
	op.params[1].memref.parent = &parent_in;
	op.params[1].memref.parent->buffer = (void *)out;
	op.params[1].memref.parent->size = sizeof(out);
	op.params[1].memref.parent->flags = TEEC_MEM_OUTPUT;
	op.params[1].memref.size = sizeof(out);
	op.params[1].memref.offset = 0;
	TEEC_RegisterSharedMemory(session.ctx, &parent_in);
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT,
					TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&session, TA_SIMS_CMD_READ, &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	if (!ADBG_EXPECT_BUFFER(c, in, sizeof(in), out,
				sizeof(out))) {
		Do_ADBG_Log("in:");
		Do_ADBG_HexLog(in, sizeof(in), 16);
		Do_ADBG_Log("out:");
		Do_ADBG_HexLog(out, sizeof(out), 16);
	}
	TEEC_ReleaseSharedMemory(&parent_in);

	Do_ADBG_EndSubCase(c, NULL);

	//===================================================================

	TEEC_CloseSession(&session);

}

static void xtest_tee_test_1103(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	uintptr_t bad_addr_kernel = 0x80000000;

	Do_ADBG_BeginSubCase(c, "Load TA using invalid TA UUID ptr");
	res = xtest_teec_open_session(&session,
			(const TEEC_UUID*)bad_addr_kernel, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_ACCESS_DENIED, res))
		return;

	if (res == TEEC_SUCCESS)
		TEEC_CloseSession(&session);

	Do_ADBG_EndSubCase(c, NULL);
}

static void xtest_tee_test_1104(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session s_siss = { 0 };
	TEEC_Session s_mi = { 0 };
	TEEC_Session s_tmp = { 0 };
	const TEEC_UUID *siss_uuid = &siss_ta_uuid;
	const TEEC_UUID *mi_uuid = &client_ta_uuid;
	uint32_t ret_orig;

	Do_ADBG_BeginSubCase(c,
		"Invoke cmd on panicked TA: single instance single session");
	res = xtest_teec_open_session(&s_siss, siss_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&s_siss, TA_SISS_CMD_PANIC, NULL, &ret_orig);
	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TEE, ret_orig);

	res = TEEC_InvokeCommand(&s_siss, TA_SISS_CMD_SUCCESS, NULL,
			&ret_orig);
	ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_TARGET_DEAD, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TEE, ret_orig);
	Do_ADBG_EndSubCase(c, NULL);



	Do_ADBG_BeginSubCase(c,
		"Open Session on panicked TA: single instance single session");
	res = xtest_teec_open_session(&s_tmp, siss_uuid, NULL, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	if (res == TEEC_SUCCESS)
		TEEC_CloseSession(&s_tmp);
	TEEC_CloseSession(&s_siss);
	Do_ADBG_EndSubCase(c, NULL);



	Do_ADBG_BeginSubCase(c,
		"Close and re-open session on panicked TA: siss");
	res = xtest_teec_open_session(&s_siss, siss_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&s_siss, TA_SISS_CMD_SUCCESS, NULL,
			&ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	TEEC_CloseSession(&s_siss);
	Do_ADBG_EndSubCase(c, NULL);



	Do_ADBG_BeginSubCase(c,
		"Invoke cmd on panicked TA: multi instance");
	res = xtest_teec_open_session(&s_mi, mi_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&s_mi, TA_CLIENT_CMD_PANIC, NULL, &ret_orig);
	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TEE, ret_orig);

	res = TEEC_InvokeCommand(&s_mi, TA_CLIENT_CMD_SUCCESS, NULL,
			&ret_orig);
	ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_TARGET_DEAD, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TEE, ret_orig);
	Do_ADBG_EndSubCase(c, NULL);



	Do_ADBG_BeginSubCase(c,
		"Open Session on panicked TA: multi instance");
	res = xtest_teec_open_session(&s_tmp, mi_uuid, NULL, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	if (res == TEEC_SUCCESS)
		TEEC_CloseSession(&s_tmp);
	TEEC_CloseSession(&s_mi);
	Do_ADBG_EndSubCase(c, NULL);



	Do_ADBG_BeginSubCase(c,
		"Close and re-open session on panicked TA: multi instance");
	res = xtest_teec_open_session(&s_mi, mi_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&s_mi, TA_CLIENT_CMD_SUCCESS, NULL,
			&ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	TEEC_CloseSession(&s_mi);
	Do_ADBG_EndSubCase(c, NULL);
}

static void xtest_tee_test_1105(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session_0 = { 0 };
	TEEC_Session session_1 = { 0 };
	uint32_t ret_orig;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	Do_ADBG_BeginSubCase(c, "Test client TA panic");
	res = xtest_teec_open_session(&session_0, &client_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = xtest_teec_open_session(&session_1, &client_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
		TEEC_CloseSession(&session_0);
		return;
	}

	op.params[0].tmpref.buffer = (void*)&siss_ta_uuid;
	op.params[0].tmpref.size = sizeof(TEEC_UUID);
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&session_0, TA_CLIENT_CMD_OPENSESSION, &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TRUSTED_APP, ret_orig);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	res = TEEC_InvokeCommand(&session_0, TA_CLIENT_CMD_PANIC, &op, &ret_orig);
	ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_TARGET_DEAD, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TEE, ret_orig);

	op.params[0].tmpref.buffer = (void*)&siss_ta_uuid;
	op.params[0].tmpref.size = sizeof(TEEC_UUID);
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&session_1, TA_CLIENT_CMD_OPENSESSION, &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TRUSTED_APP, ret_orig);

	res = TEEC_InvokeCommand(&session_1, TA_CLIENT_CMD_CLOSESESSION, &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TRUSTED_APP, ret_orig);

	TEEC_CloseSession(&session_0);
	TEEC_CloseSession(&session_1);
	Do_ADBG_EndSubCase(c, NULL);


	Do_ADBG_BeginSubCase(c, "Test default panic handler");
	res = xtest_teec_open_session(&session_0, &client_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = xtest_teec_open_session(&session_1, &client_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
		TEEC_CloseSession(&session_0);
		return;
	}

	res = TEEC_InvokeCommand(&session_0, TA_CLIENT_CMD_DEFAULT_PANIC, NULL, &ret_orig);
	ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_TARGET_DEAD, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TEE, ret_orig);

	res = TEEC_InvokeCommand(&session_1, TA_CLIENT_CMD_SUCCESS, NULL, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TRUSTED_APP, ret_orig);

	TEEC_CloseSession(&session_0);
	TEEC_CloseSession(&session_1);
	Do_ADBG_EndSubCase(c, NULL);


	Do_ADBG_BeginSubCase(c, "Test session open after default panic");
	res = xtest_teec_open_session(&session_0, &client_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&session_0, TA_CLIENT_CMD_SUCCESS, NULL, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TRUSTED_APP, ret_orig);

	TEEC_CloseSession(&session_0);
	Do_ADBG_EndSubCase(c, NULL);
}

static void xtest_tee_test_1106(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_VALUE_INPUT);
	op.params[3].value.a = TA_SISS_CMD_FAILURE;
	op.params[3].value.b = 0;

	Do_ADBG_BeginSubCase(c, "Test OpenSession error from TEE_ORIGIN_TRUSTED_APP");
	res = xtest_teec_open_session(&session, &siss_ta_uuid, &op, &ret_orig);
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_GENERIC, res))
		return;

	TEEC_CloseSession(&session);
	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Test OpenSession sucess after previous OpenSession\n \
							returned error from TEE_ORIGIN_TRUSTED_APP");
	res = xtest_teec_open_session(&session, &siss_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	TEEC_CloseSession(&session);

	Do_ADBG_EndSubCase(c, NULL);

}

static void xtest_tee_test_1107(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session1 = { 0 };
	TEEC_Session session2 = { 0 };
	TEEC_Session session3 = { 0 };
	uint32_t ret_orig;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	op.params[3].value.a = TA_SIMS_CMD_FAILURE;
	op.params[3].value.b = 0;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_VALUE_INPUT);

	Do_ADBG_BeginSubCase(c, "Test OpenSession error from TEE_ORIGIN_TRUSTED_APP for SIMS TAs");
	res = xtest_teec_open_session(&session1, &sims_test_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = xtest_teec_open_session(&session2, &sims_test_ta_uuid, &op, &ret_orig);
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_GENERIC, res))
		return;

	res = xtest_teec_open_session(&session3, &sims_test_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	TEEC_CloseSession(&session1);
	TEEC_CloseSession(&session2);
	TEEC_CloseSession(&session3);

	Do_ADBG_EndSubCase(c, NULL);

}

struct test_1108_thread_arg {
	TEEC_Session *sess;
	uint32_t th_id;
	TEEC_Result res;
};

#define NUM_THREADS    3
#define NR_ITERATIONS  32

static void *test_1108_thread(void *arg)
{
	struct test_1108_thread_arg *a = (struct test_1108_thread_arg *)arg;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Session *sess = a->sess;
	uint32_t th_id = a->th_id;
	uint32_t ret_orig;
	TEEC_Result res;
	uint32_t i;

	for (i = 0; i < NR_ITERATIONS; i++) {
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT,
			TEEC_NONE, TEEC_NONE);
		op.params[0].value.a = th_id;
		op.params[0].value.b = 0;
		op.params[1].value.a = i;
		op.params[1].value.b = 0;

		res = TEEC_InvokeCommand(sess, TA_SISS_CMD_RETURN_TH_ID, &op,
			&ret_orig);
		if (res != TEEC_SUCCESS)
			break;
		if (op.params[0].value.b != th_id) {
			printf("Thread %d got response %d!!!\n", th_id,
				op.params[0].value.b);
			res = TEEC_ERROR_BAD_PARAMETERS;
			break;
		}
		if (op.params[1].value.b != i) {
			printf("Thread %d got response %d, expected %d!!!\n", th_id,
				op.params[1].value.b, i);
			res = TEEC_ERROR_BAD_PARAMETERS;
			break;
		}
	}
	a->res = res;
	return NULL;
}

static void xtest_tee_test_1108(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	pthread_t thr[NUM_THREADS];
	struct test_1108_thread_arg arg[NUM_THREADS];
	uint32_t i;
	uint32_t num_threads = 0;

	res = xtest_teec_open_session(&session, &siss_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	for (i = 0; i < NUM_THREADS; i++, num_threads++) {
		arg[i].sess = &session;
		arg[i].th_id = i;
		arg[i].res = TEEC_ERROR_NO_DATA;
		if (!ADBG_EXPECT(c, 0, pthread_create(thr + i, NULL, test_1108_thread,
			arg + i)))
			break;
	}

	for (i = 0; i < num_threads; i++) {
		ADBG_EXPECT(c, 0, pthread_join(thr[i], NULL));
		ADBG_EXPECT_TEEC_SUCCESS(c, arg[i].res);
	}

	TEEC_CloseSession(&session);
}

static void xtest_tee_test_1109(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_UUID uuid;

	res = xtest_teec_open_session(&session, &multi_instance_memref_ta_uuid,
		NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
		TEEC_NONE, TEEC_NONE);
	memcpy(&uuid, &multi_instance_memref_ta_uuid, sizeof(TEEC_UUID));
	op.params[0].tmpref.buffer = &uuid;
	op.params[0].tmpref.size = sizeof(TEEC_UUID);
	res = TEEC_InvokeCommand(&session, TA_MULTI_INSTANCE_INVOKE_CMD, &op, NULL);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
		TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = TA_MULTI_INSTANCE_INVOKE_CMD,
	op.params[1].tmpref.buffer = &uuid;
	op.params[1].tmpref.size = sizeof(TEEC_UUID);
	res = TEEC_InvokeCommand(&session, TA_MULTI_INSTANCE_INVOKE_CMD, &op, NULL);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
		TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
	op.params[0].value.a = TA_MULTI_INSTANCE_INVOKE_CMD,
	op.params[1].value.a = TA_MULTI_INSTANCE_INVOKE_CMD,
	memcpy(&uuid, &sims_test_ta_uuid, sizeof(TEEC_UUID));
	op.params[2].tmpref.buffer = &uuid;
	op.params[2].tmpref.size = sizeof(TEEC_UUID);
	res = TEEC_InvokeCommand(&session, TA_MULTI_INSTANCE_INVOKE_CMD, &op, NULL);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	TEEC_CloseSession(&session);

	res = xtest_teec_open_session(&session, &sims_test_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE,
		TEEC_NONE);
	res = TEEC_InvokeCommand(&session, TA_SIMS_CMD_GET_COUNTER, &op, NULL);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	ADBG_EXPECT(c, 0, op.params[0].value.a);
	TEEC_CloseSession(&session);
}

static void xtest_tee_test_1110(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session = { 0 };
	uint32_t ret_orig;

	res = xtest_teec_open_session(&session, &core_test_ta_uuid, NULL,
		&ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&session, TA_CORE_TEST_CMD_SESSION_LEAK, NULL,
		&ret_orig);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP, ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	TEEC_CloseSession(&session);
}

static void xtest_tee_test_1111(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session = { 0 };
	uint32_t ret_orig;

	res = xtest_teec_open_session(&session, &core_test_ta_uuid, NULL,
		&ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&session, TA_CORE_TEST_CMD_WAIT_TIMEOUT, NULL,
		&ret_orig);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP, ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	TEEC_CloseSession(&session);
}

static void xtest_tee_test_1112(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session_1 = { 0 };
	TEEC_Session session_2 = { 0 };
	uint32_t ret_orig;

	res = xtest_teec_open_session(&session_1, &core_test_ta_uuid, NULL,
		&ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = xtest_teec_open_session(&session_2, &core_test_ta_uuid, NULL,
		&ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
		TEEC_CloseSession(&session_1);
		return;
	}

	res = TEEC_InvokeCommand(&session_1, TA_CORE_TEST_CMD_OPEN_SIMS_SESSION,
		NULL, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	res = TEEC_InvokeCommand(&session_2, TA_CORE_TEST_CMD_OPEN_SIMS_SESSION,
		NULL, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	res = TEEC_InvokeCommand(&session_1,
		TA_CORE_TEST_CMD_SHARE_BUFFER_AND_PANIC, NULL, &ret_orig);
	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD, res);

	TEEC_CloseSession(&session_1);

	res = TEEC_InvokeCommand(&session_2, TA_CORE_TEST_CMD_CHECK_BUFFER_MAPPING,
		NULL, &ret_orig);
	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD, res);

	TEEC_CloseSession(&session_2);
}

static void xtest_tee_test_1113(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session_1 = { 0 };
	TEEC_Session session_2 = { 0 };
	uint32_t ret_orig;

	Do_ADBG_BeginSubCase(c, "Test memref unmapping 2 parallel sessions");
	res = xtest_teec_open_session(&session_1, &core_test_ta_uuid, NULL,
		&ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = xtest_teec_open_session(&session_2, &core_test_ta_uuid, NULL,
		&ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
		TEEC_CloseSession(&session_1);
		return;
	}

	res = TEEC_InvokeCommand(&session_1, TA_CORE_TEST_CMD_OPEN_SIMS_SESSION,
		NULL, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	res = TEEC_InvokeCommand(&session_2, TA_CORE_TEST_CMD_OPEN_SIMS_SESSION,
		NULL, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	res = TEEC_InvokeCommand(&session_1, TA_CORE_TEST_CMD_SHARE_BUFFER, NULL,
		&ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	res = TEEC_InvokeCommand(&session_2, TA_CORE_TEST_CMD_CHECK_BUFFER_MAPPING,
		NULL, &ret_orig);
	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD, res);

	TEEC_CloseSession(&session_1);
	TEEC_CloseSession(&session_2);
	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Test memref unmapping single session");
	res = xtest_teec_open_session(&session_1, &core_test_ta_uuid, NULL,
		&ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&session_1, TA_CORE_TEST_CMD_OPEN_SIMS_SESSION,
		NULL, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	res = TEEC_InvokeCommand(&session_1, TA_CORE_TEST_CMD_SHARE_BUFFER, NULL,
		&ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	res = TEEC_InvokeCommand(&session_1, TA_CORE_TEST_CMD_CHECK_BUFFER_MAPPING,
		NULL, &ret_orig);
	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD, res);

	TEEC_CloseSession(&session_1);
	Do_ADBG_EndSubCase(c, NULL);
}

static void xtest_tee_test_1114(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session = { 0 };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	Do_ADBG_BeginSubCase(c, "Test timeout cancellations disabled");
	res = xtest_teec_open_session(&session, &core_test_ta_uuid, NULL,
		&ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
		TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = 100; // timeout interval
	op.params[0].value.b = 5000; // TEE_Wait interval
	op.params[1].value.a = 0; // unmask cancellations
	res = TEEC_InvokeCommand(&session, TA_CORE_TEST_CMD_INVOKE_TIMEOUT, &op,
		&ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	TEEC_CloseSession(&session);
	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Test timeout cancellations enabled");
	res = xtest_teec_open_session(&session, &core_test_ta_uuid, NULL,
		&ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
		TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = 100; // timeout interval
	op.params[0].value.b = 5000; // TEE_Wait interval
	op.params[1].value.a = 1; // unmask cancellations
	res = TEEC_InvokeCommand(&session, TA_CORE_TEST_CMD_INVOKE_TIMEOUT, &op,
		&ret_orig);
	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_CANCEL, res);

	TEEC_CloseSession(&session);
	Do_ADBG_EndSubCase(c, NULL);
}

#define SHMEM_SIZE 512

static void xtest_tee_test_1115(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session sess1 = { 0 };
	TEEC_Session sess2 = { 0 };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Context ctx1, ctx2;
	TEEC_SharedMemory shmem;
	uint8_t buff[SHMEM_SIZE];
	uint32_t ret_orig;

	ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InitializeContext(NULL, &ctx1));
	ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InitializeContext(NULL, &ctx2));

	shmem.buffer = (void *)buff;
	shmem.size = sizeof(buff);
	shmem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_RegisterSharedMemory(&ctx1, &shmem));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE,
		TEEC_VALUE_INPUT);
	op.params[0].memref.parent = &shmem;
	op.params[3].value.a = TA_CORE_TEST_CMD_SUCCESS;

	res = TEEC_OpenSession(&ctx1, &sess1, &core_test_ta_uuid, TEEC_LOGIN_PUBLIC,
		NULL, &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	/* Use TEEC_SharedMemory registered in another TEEC_Context */
	res = TEEC_OpenSession(&ctx2, &sess2, &core_test_ta_uuid, TEEC_LOGIN_PUBLIC,
		NULL, &op, &ret_orig);
	ADBG_EXPECT_NOT(c, TEEC_ORIGIN_TRUSTED_APP, ret_orig);
	ADBG_EXPECT_NOT(c, TEEC_SUCCESS, res);

	TEEC_ReleaseSharedMemory(&shmem);
	TEEC_CloseSession(&sess1);
	TEEC_FinalizeContext(&ctx1);
	TEEC_FinalizeContext(&ctx2);
}

struct test_1116_thread_arg {
	ADBG_Case_t *c;
	uint32_t timeout;
	uint32_t masked;
};

static void *test_1116_th_routine(void *arg)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess = { 0 };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	struct test_1116_thread_arg *th_arg = (struct test_1116_thread_arg *)arg;
	ADBG_Case_t *c = ((struct test_1116_thread_arg *)arg)->c;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InitializeContext(NULL, &ctx)))
		goto thr_exit;

	res = TEEC_OpenSession(&ctx, &sess, &core_test_ta_uuid, TEEC_LOGIN_PUBLIC,
		NULL, &op, NULL);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto finalize_ctx;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
		TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = th_arg->timeout; // timeout interval
	op.params[0].value.b = 10000; // TEE_Wait interval
	op.params[1].value.a = 1 - th_arg->masked; // unmask cancellations

	res = TEEC_InvokeCommand(&sess, TA_CORE_TEST_CMD_INVOKE_TIMEOUT, &op, NULL);

	if (th_arg->masked)
		ADBG_EXPECT_TEEC_SUCCESS(c, res);
	else
		ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_CANCEL, res);

	TEEC_CloseSession(&sess);
finalize_ctx:
	TEEC_FinalizeContext(&ctx);
thr_exit:
	return NULL;
}

static void xtest_tee_test_1116(ADBG_Case_t *c)
{
	pthread_t thr_1, thr_2, thr_3;
	struct test_1116_thread_arg arg_1, arg_2, arg_3;

	arg_1.timeout = 3000;
	arg_1.masked = 1;
	arg_1.c = c;
	ADBG_EXPECT(c, 0, pthread_create(&thr_1, NULL, test_1116_th_routine,
		&arg_1));

	arg_2.timeout = 3000;
	arg_2.masked = 0;
	arg_2.c = c;
	ADBG_EXPECT(c, 0, pthread_create(&thr_2, NULL, test_1116_th_routine,
		&arg_2));

	arg_3.timeout = 3000;
	arg_3.masked = 1;
	arg_3.c = c;
	ADBG_EXPECT(c, 0, pthread_create(&thr_3, NULL, test_1116_th_routine,
		&arg_3));

	ADBG_EXPECT(c, 0, pthread_join(thr_1, NULL));
	ADBG_EXPECT(c, 0, pthread_join(thr_2, NULL));
	ADBG_EXPECT(c, 0, pthread_join(thr_3, NULL));
}

static void *test_1117_th_routine(void *arg)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess = { 0 };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	struct test_1116_thread_arg *th_arg = (struct test_1116_thread_arg *)arg;
	ADBG_Case_t *c = ((struct test_1116_thread_arg *)arg)->c;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InitializeContext(NULL, &ctx)))
		goto thr_exit;

	res = TEEC_OpenSession(&ctx, &sess, &core_test_ta_uuid, TEEC_LOGIN_PUBLIC,
		NULL, &op, NULL);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto finalize_ctx;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
		TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = th_arg->timeout; // timeout interval
	op.params[0].value.b = 10000; // TEE_Wait interval
	op.params[1].value.a = 1 - th_arg->masked; // unmask cancellations

	res = TEEC_InvokeCommand(&sess, TA_CORE_TEST_CMD_INVOKE_OPENSESSION_TIMEOUT,
		&op, NULL);

	if (th_arg->masked)
		ADBG_EXPECT_TEEC_SUCCESS(c, res);
	else
		ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_CANCEL, res);

	TEEC_CloseSession(&sess);
finalize_ctx:
	TEEC_FinalizeContext(&ctx);
thr_exit:
	return NULL;
}

static void xtest_tee_test_1117(ADBG_Case_t *c)
{
	pthread_t thr_1, thr_2, thr_3;
	struct test_1116_thread_arg arg_1, arg_2, arg_3;

	arg_1.timeout = 3000;
	arg_1.masked = 1;
	arg_1.c = c;
	ADBG_EXPECT(c, 0, pthread_create(&thr_1, NULL, test_1117_th_routine,
		&arg_1));

	arg_2.timeout = 3000;
	arg_2.masked = 0;
	arg_2.c = c;
	ADBG_EXPECT(c, 0, pthread_create(&thr_2, NULL, test_1117_th_routine,
		&arg_2));

	arg_3.timeout = 3000;
	arg_3.masked = 1;
	arg_3.c = c;
	ADBG_EXPECT(c, 0, pthread_create(&thr_3, NULL, test_1117_th_routine,
		&arg_3));

	ADBG_EXPECT(c, 0, pthread_join(thr_1, NULL));
	ADBG_EXPECT(c, 0, pthread_join(thr_2, NULL));
	ADBG_EXPECT(c, 0, pthread_join(thr_3, NULL));
}

static void *cancellation_thr(void *arg)
{
	while (!TEEC_OperationStarted(arg))
		sleep_ms(50);

	TEEC_RequestCancellation(arg);
	return NULL;
}

#define CANCEL true
#define CANCEL_OPEN_SESSION 0
#define CANCEL_INVOKE       1

struct subcase_1118_args {
	pthread_t thr;
	ADBG_Case_t *c;
	uint32_t timeout;
	bool cancel;
	int cancel_cmd;
};

/*
 * Send cancel request for all operations but only unmask cancel as directed
 * by the test case.
 */
static void run_1118_cancel_operation(ADBG_Case_t *c, int cancel_cmd,
		uint32_t timeout, bool cancel)
{
	pthread_t thr;
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	TEEC_Result res_open;
	TEEC_Result res_invoke;
	TEEC_Result exp;
	bool unmask = false;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	unmask = cancel && (cancel_cmd == CANCEL_OPEN_SESSION);
	exp = unmask ? TEEC_ERROR_CANCEL : TEEC_SUCCESS;
	op.params[0].value.a = timeout;
	op.params[0].value.b = unmask;
	op.params[3].value.a = TA_CORE_TEST_CMD_WAIT;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_VALUE_INPUT);
	ADBG_EXPECT(c, 0, pthread_create(&thr, NULL, cancellation_thr, &op));

	res_open = xtest_teec_open_session(&session, &core_test_ta_uuid, &op,
			&ret_orig);

	ADBG_EXPECT(c, 0, pthread_join(thr, NULL));

	ADBG_EXPECT_TEEC_RESULT(c, exp, res_open);

	if (cancel_cmd == CANCEL_OPEN_SESSION)
		goto end_close_session;

	unmask = cancel && (cancel_cmd == CANCEL_INVOKE);
	exp = unmask ? TEEC_ERROR_CANCEL : TEEC_SUCCESS;
	op.params[0].value.b = unmask;
	op.started = 0;

	ADBG_EXPECT(c, 0, pthread_create(&thr, NULL, cancellation_thr, &op));

	res_invoke = TEEC_InvokeCommand(&session,
			TA_CORE_TEST_CMD_WAIT, &op, &ret_orig);

	ADBG_EXPECT(c, 0, pthread_join(thr, NULL));

	ADBG_EXPECT_TEEC_RESULT(c, exp, res_invoke);
end_close_session:
	if (res_open == TEE_SUCCESS)
		TEEC_CloseSession(&session);
}

/*
 * Force setting unmask for all operations to test for false positives if
 * cancel request is matched to the wrong operation or wrong session.
 */
static void run_1118_cancel_operation_force_unmask(ADBG_Case_t *c,
		int cancel_cmd, uint32_t timeout, bool cancel)
{
	pthread_t thr;
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	TEEC_Result res_open;
	TEEC_Result res_invoke;
	TEEC_Result exp;
	bool unmask = false;
	bool force_unmask = true;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	unmask = cancel && (cancel_cmd == CANCEL_OPEN_SESSION);
	exp = unmask ? TEEC_ERROR_CANCEL : TEEC_SUCCESS;
	op.params[0].value.a = timeout;
	op.params[0].value.b = force_unmask;
	op.params[3].value.a = TA_CORE_TEST_CMD_WAIT;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_VALUE_INPUT);
	if (unmask)
		ADBG_EXPECT(c, 0,
			pthread_create(&thr, NULL, cancellation_thr, &op));

	res_open = xtest_teec_open_session(&session, &core_test_ta_uuid, &op,
			&ret_orig);

	if (unmask)
		ADBG_EXPECT(c, 0, pthread_join(thr, NULL));

	ADBG_EXPECT_TEEC_RESULT(c, exp, res_open);

	if (cancel_cmd == CANCEL_OPEN_SESSION)
		goto end_close_session;

	unmask = cancel && (cancel_cmd == CANCEL_INVOKE);
	exp = unmask ? TEEC_ERROR_CANCEL : TEEC_SUCCESS;
	op.params[0].value.b = force_unmask;
	op.started = 0;

	if (unmask)
		ADBG_EXPECT(c, 0,
			pthread_create(&thr, NULL, cancellation_thr, &op));

	res_invoke = TEEC_InvokeCommand(&session,
			TA_CORE_TEST_CMD_WAIT, &op, &ret_orig);

	if (unmask)
		ADBG_EXPECT(c, 0, pthread_join(thr, NULL));

	ADBG_EXPECT_TEEC_RESULT(c, exp, res_invoke);
end_close_session:
	if (res_open == TEE_SUCCESS)
		TEEC_CloseSession(&session);
}

static void *run_1118_subcase_thr(void *arg)
{
	struct subcase_1118_args *a = arg;

	run_1118_cancel_operation(a->c, a->cancel_cmd, a->timeout, a->cancel);

	return NULL;
}

static void *run_1118_subcase_force_unmask_thr(void *arg)
{
	struct subcase_1118_args *a = arg;

	run_1118_cancel_operation_force_unmask(a->c, a->cancel_cmd,
			a->timeout, a->cancel);

	return NULL;
}

static void test_1118_cancel_queued(ADBG_Case_t *c, const char *subcase,
		struct subcase_1118_args *cases, unsigned int n_cases)
{
	unsigned int i;

	Do_ADBG_BeginSubCase(c, "%s: always request cancel", subcase);
	{
		for (i = 0; i < n_cases; i++)
			(void)ADBG_EXPECT(c, 0,
				pthread_create(&cases[i].thr, NULL,
					run_1118_subcase_thr,
					&cases[i]));

		for (i = 0; i < n_cases; i++)
			(void)ADBG_EXPECT(c, 0,
				pthread_join(cases[i].thr, NULL));
	}
	Do_ADBG_EndSubCase(c, "%s: always request cancel", subcase);

	Do_ADBG_BeginSubCase(c, "%s: force unmask", subcase);
	{
		for (i = 0; i < n_cases; i++)
			(void)ADBG_EXPECT(c, 0,
				pthread_create(&cases[i].thr, NULL,
					run_1118_subcase_force_unmask_thr,
					&cases[i]));

		for (i = 0; i < n_cases; i++)
			(void)ADBG_EXPECT(c, 0,
				pthread_join(cases[i].thr, NULL));
	}
	Do_ADBG_EndSubCase(c, "%s: force unmask", subcase);
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static void xtest_tee_test_1118(ADBG_Case_t *c)
{
	const char *subcase;
	uint32_t timeout_ms = 2000;

	subcase = "TEE Wait cancel queued open session";
	{
		struct subcase_1118_args cases[] = {
			{ 0, c, timeout_ms, false, CANCEL_OPEN_SESSION },
			{ 0, c, timeout_ms, CANCEL, CANCEL_OPEN_SESSION },
			{ 0, c, timeout_ms, false, CANCEL_OPEN_SESSION },
		};
		test_1118_cancel_queued(c, subcase, cases, ARRAY_SIZE(cases));
	}

	subcase = "TEE Wait cancel queued invoke";
	{
		struct subcase_1118_args cases[] = {
			{ 0, c, timeout_ms, false, CANCEL_INVOKE },
			{ 0, c, timeout_ms, false, CANCEL_INVOKE },
			{ 0, c, timeout_ms, CANCEL, CANCEL_INVOKE },
			{ 0, c, timeout_ms, false, CANCEL_INVOKE },
		};
		test_1118_cancel_queued(c, subcase, cases, ARRAY_SIZE(cases));
	}

	subcase = "TEE Wait cancel queued invoke and open session";
	{
		struct subcase_1118_args cases[] = {
			{ 0, c, timeout_ms, false, CANCEL_INVOKE },
			{ 0, c, timeout_ms, false, CANCEL_OPEN_SESSION },
			{ 0, c, timeout_ms, CANCEL, CANCEL_OPEN_SESSION },
			{ 0, c, timeout_ms, false, CANCEL_OPEN_SESSION },
			{ 0, c, timeout_ms, false, CANCEL_INVOKE },
		};
		test_1118_cancel_queued(c, subcase, cases, ARRAY_SIZE(cases));
	}
}

struct test_1119_thread_arg {
	ADBG_Case_t *c;
	uint32_t pause;
	uint32_t timeout;
	TEEC_Result expected;
	const TEEC_UUID *uuid;
	uint32_t cmd;
};

static void *test_1119_th_routine(void *arg)
{
	TEEC_Result res;
	TEEC_Session sess = { 0 };
	uint32_t ret_orig;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	struct test_1119_thread_arg *a = arg;
	ADBG_Case_t *c = a->c;

	sleep_ms(a->pause);

	op.params[0].value.a = a->timeout;
	op.params[0].value.b = false; // unmask cancellations
	op.params[3].value.a = a->cmd;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_VALUE_INPUT);
	res = xtest_teec_open_session(&sess, a->uuid, &op, &ret_orig);
	ADBG_EXPECT_TEEC_RESULT(c, a->expected, res);

	if (res == TEE_SUCCESS)
		TEEC_CloseSession(&sess);

	return NULL;
}

static void xtest_tee_test_1119_subcase(ADBG_Case_t *c, const char *subcase,
	const TEEC_UUID *uuid, uint32_t cmd, TEEC_Result expected)
{
	pthread_t thr_1, thr_2;
	struct test_1119_thread_arg arg_1, arg_2;
	const uint32_t timeout_ms = 4000;
	const uint32_t delay_ms = 200;

	Do_ADBG_BeginSubCase(c, "Test TEEC_ERROR_BUSY: %s", subcase);
	arg_1.uuid = uuid;
	arg_1.cmd = cmd;
	arg_1.pause = 0;
	arg_1.timeout = timeout_ms;
	arg_1.expected = TEEC_SUCCESS;
	arg_1.c = c;
	ADBG_EXPECT(c, 0, pthread_create(&thr_1, NULL, test_1119_th_routine,
		&arg_1));

	/* pause to ensure thr_2 calls open session after thr_1 */
	arg_2.uuid = uuid;
	arg_2.cmd = cmd;
	arg_2.pause = delay_ms;
	arg_2.timeout = 0;
	arg_2.expected = expected;
	arg_2.c = c;
	ADBG_EXPECT(c, 0, pthread_create(&thr_2, NULL, test_1119_th_routine,
		&arg_2));

	ADBG_EXPECT(c, 0, pthread_join(thr_1, NULL));
	ADBG_EXPECT(c, 0, pthread_join(thr_2, NULL));
	Do_ADBG_EndSubCase(c, "Test TEEC_ERROR_BUSY: %s", subcase);
}

static void xtest_tee_test_1119(ADBG_Case_t *c)
{
	xtest_tee_test_1119_subcase(c, "SIMS subcase", &sims_test_ta_uuid,
		TA_SIMS_CMD_WAIT, TEEC_ERROR_BUSY);

	xtest_tee_test_1119_subcase(c, "SISS subcase", &siss_ta_uuid,
		TA_SISS_CMD_WAIT, TEEC_ERROR_BUSY);

	xtest_tee_test_1119_subcase(c, "MI subcase",
		&multi_instance_memref_ta_uuid, TA_MULTI_INSTANCE_WAIT_CMD,
		TEEC_SUCCESS);
}

static void xtest_tee_test_1120(ADBG_Case_t *c)
{
	pthread_t thr_1;
	struct test_1119_thread_arg arg_1;
	TEEC_Result res;
	const uint32_t timeout_ms = 4000;
	const uint32_t delay_ms = 500;
	TEEC_Session sess = { 0 };

	/* open a first session to the SIMS TA */
	res = xtest_teec_open_session(&sess, &sims_test_ta_uuid, NULL, NULL);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	/* open a second session to the SIMS TA which calls TEE_Wait */
	arg_1.pause = 0;
	arg_1.timeout = timeout_ms;
	arg_1.expected = TEEC_SUCCESS;
	arg_1.c = c;
	arg_1.uuid = &sims_test_ta_uuid;
	arg_1.cmd = TA_SIMS_CMD_WAIT;
	ADBG_EXPECT(c, 0, pthread_create(&thr_1, NULL, test_1119_th_routine,
		&arg_1));

	/* pause to ensure the invoke call happens during the TEE_Wait */
	sleep_ms(delay_ms);

	/* invoke a command on the first session while the SIMS TA is busy */
	res = TEEC_InvokeCommand(&sess, TA_SIMS_CMD_SUCCESS, NULL, NULL);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	ADBG_EXPECT(c, 0, pthread_join(thr_1, NULL));

	TEEC_CloseSession(&sess);
}

static TEEC_Result test_1121_opensession_setcancel(ADBG_Case_t *c,
		TEEC_Session *sess1, TEEC_Session *sess2)
{
	pthread_t thr_1;
	const TEEC_UUID *uuid = &sims_test_ta_uuid;
	TEEC_Result res;
	uint32_t ret_orig;
	uint32_t timeout_ms = 3000;

	/* open a first session to the SIMS TA to prevent it from exiting */
	res = xtest_teec_open_session(sess1, uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto end_exit;

	/* open a second session to the SIMS TA */
	res = xtest_teec_open_session(sess2, uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto end_close_session1;

	/* invoke and then cancel a first command on the second session */
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		ADBG_EXPECT(c, 0, pthread_create(&thr_1, NULL,
					cancellation_thr, &op));
		op.params[0].value.a = timeout_ms;
		op.params[0].value.b = true; // unmask
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
		res = TEEC_InvokeCommand(sess2, TA_SIMS_CMD_WAIT, &op,
				&ret_orig);

		ADBG_EXPECT(c, 0, pthread_join(thr_1, NULL));
		if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_CANCEL, res))
			goto end_close_session2;
	}
	res = TEEC_SUCCESS;
	goto end_exit;

end_close_session2:
	TEEC_CloseSession(sess2);
end_close_session1:
	TEEC_CloseSession(sess1);
end_exit:
	return res;
}

static void xtest_tee_test_1121(ADBG_Case_t *c)
{
	TEEC_Result res;
	uint32_t ret_orig;
	TEEC_Session sess1 = { 0 };
	TEEC_Session sess2 = { 0 };

	res = test_1121_opensession_setcancel(c, &sess1, &sess2);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	/* invoke a second command that should NOT encounter the cancel flag,
	 * however leave cancellations unmasked to ensure the cancel flag
	 * value is actually queried.
	 */
	{
		/* set the started field of Operation structure to zero */
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		uint32_t timeout_ms = 100; // no need for a long wait

		op.params[0].value.a = timeout_ms;
		op.params[0].value.b = true; // unmask
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
		res = TEEC_InvokeCommand(&sess2, TA_SIMS_CMD_WAIT, &op,
				&ret_orig);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto end_close_session;
	}

end_close_session:
	TEEC_CloseSession(&sess1);
	TEEC_CloseSession(&sess2);
}

static void *cancel_loop_thr(void *arg)
{
	/* Keep queueing cancel requests until operation returns */
	while (!TEEC_OperationCompleted(arg)) {
		TEEC_RequestCancellation(arg);
		sleep_ms(50);
	}

	return NULL;
}

static void xtest_tee_test_1122(ADBG_Case_t *c)
{
	pthread_t thr_1;
	pthread_t thr_2;
	pthread_t thr_3;
	TEEC_Result res;
	uint32_t ret_orig;
	TEEC_Session sess1 = { 0 };
	TEEC_Session sess2 = { 0 };

	/*
	 * Test for hitting Early Cancel Request race condition window between
	 * when the preceding operation ends, the cancel flag is cleared,
	 * and when a second operation is sent and it is immediately cancelled.
	 *
	 * Verify that the second command is properly cancelled.
	 */
	Do_ADBG_BeginSubCase(c, "Early Cancel Request");
	{
		/* set the started field of Operation structure to zero */
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		uint32_t timeout_ms = 100; // no need for a long wait

		res = test_1121_opensession_setcancel(c, &sess1, &sess2);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto end_subcase_1;

		ADBG_EXPECT(c, 0, pthread_create(&thr_1, NULL, cancel_loop_thr, &op));
		ADBG_EXPECT(c, 0, pthread_create(&thr_2, NULL, cancel_loop_thr, &op));
		ADBG_EXPECT(c, 0, pthread_create(&thr_3, NULL, cancel_loop_thr, &op));

		/* invoke and then cancel second command */
		op.params[0].value.a = timeout_ms;
		op.params[0].value.b = true; // unmask
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
		res = TEEC_InvokeCommand(&sess2, TA_SIMS_CMD_WAIT, &op,
				&ret_orig);
		ADBG_EXPECT(c, 0, pthread_join(thr_1, NULL));
		ADBG_EXPECT(c, 0, pthread_join(thr_2, NULL));
		ADBG_EXPECT(c, 0, pthread_join(thr_3, NULL));

		ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_CANCEL, res);
		TEEC_CloseSession(&sess1);
		TEEC_CloseSession(&sess2);
	}
end_subcase_1:
	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Test for hitting Late Cancel Request race condition window between
	 * when the preceding operation ends, late cancel requests come in
	 * after the cancel flag is cleared, and when a another operation is
	 * sent which should not be cancelled.
	 *
	 * Verify that the second command is not cancelled.
	 */
	Do_ADBG_BeginSubCase(c, "Late Cancel Request");
	{
		/* set the started field of Operation structure to zero */
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		TEEC_Operation op2 = TEEC_OPERATION_INITIALIZER;
		uint32_t timeout_ms = 3000;

		res = test_1121_opensession_setcancel(c, &sess1, &sess2);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto end_subcase_2;

		/* invoke and then cancel first command while ensuring cancel
		 * requests are being sent as late as possible until the
		 * command returns */
		ADBG_EXPECT(c, 0, pthread_create(&thr_1, NULL, cancel_loop_thr, &op));
		ADBG_EXPECT(c, 0, pthread_create(&thr_2, NULL, cancel_loop_thr, &op));
		ADBG_EXPECT(c, 0, pthread_create(&thr_3, NULL, cancel_loop_thr, &op));

		op.params[0].value.a = timeout_ms;
		op.params[0].value.b = true; // unmask
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
		res = TEEC_InvokeCommand(&sess2, TA_SIMS_CMD_WAIT, &op,
				&ret_orig);
		ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_CANCEL, res);

		/* start second command right after first command ends */
		timeout_ms = 100; // no need for a long wait
		op2.params[0].value.a = timeout_ms;
		op2.params[0].value.b = true; // unmask
		op2.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
		res = TEEC_InvokeCommand(&sess2, TA_SIMS_CMD_WAIT, &op2,
				&ret_orig);
		ADBG_EXPECT_TEEC_SUCCESS(c, res);

		ADBG_EXPECT(c, 0, pthread_join(thr_1, NULL));
		ADBG_EXPECT(c, 0, pthread_join(thr_2, NULL));
		ADBG_EXPECT(c, 0, pthread_join(thr_3, NULL));

		TEEC_CloseSession(&sess1);
		TEEC_CloseSession(&sess2);
	}
end_subcase_2:
	Do_ADBG_EndSubCase(c, NULL);
}

static void xtest_tee_test_1123(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session sess1 = { 0 };
	TEEC_Session sess2 = { 0 };
	uint32_t ret_orig;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t iter;

	res = xtest_teec_open_session(&sess1, &sims_test_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&sess1, TA_SIMS_CMD_PANIC, &op, &ret_orig);
	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TEE, ret_orig);

	res = xtest_teec_open_session(&sess2, &sims_test_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto test_1123_close;

	for (iter = 0; iter < 10; iter++) {
		res = TEEC_InvokeCommand(&sess1, TA_SIMS_CMD_SUCCESS, &op, &ret_orig);
		if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD, res))
			break;
		res = TEEC_InvokeCommand(&sess2, TA_SIMS_CMD_SUCCESS, &op, &ret_orig);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			break;
	}
	TEEC_CloseSession(&sess2);
test_1123_close:
	TEEC_CloseSession(&sess1);
}

static void xtest_tee_test_1124(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session sess1 = { 0 };
	TEEC_Session sess2 = { 0 };
	uint32_t ret_orig;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t iter;

	res = xtest_teec_open_session(&sess1, &siss_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&sess1, TA_SISS_CMD_PANIC, &op, &ret_orig);
	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TEE, ret_orig);

	res = xtest_teec_open_session(&sess2, &siss_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto test_1124_close;

	for (iter = 0; iter < 10; iter++) {
		res = TEEC_InvokeCommand(&sess1, TA_SISS_CMD_SUCCESS, &op, &ret_orig);
		if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD, res))
			break;
		res = TEEC_InvokeCommand(&sess2, TA_SISS_CMD_SUCCESS, &op, &ret_orig);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			break;
	}
	TEEC_CloseSession(&sess2);
test_1124_close:
	TEEC_CloseSession(&sess1);
}

struct test_1125_thread_arg {
	ADBG_Case_t *c;
	TEEC_Session *sess;
	uint32_t timeout;
	uint32_t cmd;
	bool cancel;
	TEEC_Result res;
};

static void *test_1125_cancel_thr(void *arg)
{
	TEEC_Operation *op = (TEEC_Operation *)arg;

	sleep_ms(200);
	TEEC_RequestCancellation(op);
	return NULL;
}

static void *test_1125_thread_func(void *arg)
{
	pthread_t thr;
	struct test_1125_thread_arg *a = (struct test_1125_thread_arg *)arg;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
		TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = a->timeout;
	op.params[0].value.b = 0;

	if (a->cancel) {
		ADBG_EXPECT(a->c, 0, pthread_create(&thr, NULL, test_1125_cancel_thr,
			&op));
	}
	ADBG_EXPECT(a->c, a->res, TEEC_InvokeCommand(a->sess, a->cmd, &op, NULL));
	if (a->cancel) {
		ADBG_EXPECT(a->c, 0, pthread_join(thr, NULL));
	}
	return NULL;
}

static void xtest_tee_test_1125(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session sess = { 0 };
	pthread_t thr1, thr2;
	struct test_1125_thread_arg arg1, arg2;

	res = xtest_teec_open_session(&sess, &siss_ta_uuid, NULL, NULL);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	arg1.c = c;
	arg1.sess = &sess;
	arg1.timeout = 5000;
	arg1.cmd = TA_SISS_CMD_WAIT;
	arg1.cancel = false;
	arg1.res = TEE_SUCCESS;

	if (!ADBG_EXPECT(c, 0, pthread_create(&thr1, NULL, test_1125_thread_func,
		&arg1)))
		goto test_1125_end;

	sleep_ms(200);

	arg2.c = c;
	arg2.sess = &sess;
	arg2.timeout = 1000;
	arg2.cmd = TA_SISS_CMD_WAIT;
	arg2.cancel = true;
	arg2.res = TEEC_ERROR_CANCEL;

	if (!ADBG_EXPECT(c, 0, pthread_create(&thr2, NULL, test_1125_thread_func,
		&arg2)))
		goto test_1125_join1;

	ADBG_EXPECT(c, 0, pthread_join(thr2, NULL));

test_1125_join1:
	ADBG_EXPECT(c, 0, pthread_join(thr1, NULL));

test_1125_end:
	TEEC_CloseSession(&sess);
}

static void xtest_tee_test_1126(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session sess = { 0 };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	res = xtest_teec_open_session(&sess, &sims_test_ta_uuid, NULL, NULL);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&sess, TA_SIMS_CMD_PANIC, &op, &ret_orig);
	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TEE, ret_orig);

	TEEC_CloseSession(&sess);

	res = xtest_teec_open_session(&sess, &sims_test_ta_uuid, NULL, NULL);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&sess, TA_SIMS_CMD_SUCCESS, &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TRUSTED_APP, ret_orig);

	TEEC_CloseSession(&sess);
}

static void xtest_tee_test_1127(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session sess = { 0 };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	res = xtest_teec_open_session(&sess, &sims_test_ta_uuid, NULL, NULL);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	TEEC_CloseSession(NULL);

	res = TEEC_InvokeCommand(&sess, TA_SIMS_CMD_SUCCESS, &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TRUSTED_APP, ret_orig);

	TEEC_CloseSession(&sess);
}

static void xtest_tee_test_1200(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	Do_ADBG_BeginSubCase(c, "Test TEE_Malloc alignement");
	res = xtest_teec_open_session(&session, &client_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&session, TA_CLIENT_CMD_TEST_MALLOC_ALIGNEMENT, &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TRUSTED_APP, ret_orig);

	TEEC_CloseSession(&session);
	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Test TEE_Malloc with size = 0");
	res = xtest_teec_open_session(&session, &client_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&session, TA_CLIENT_CMD_TEST_MALLOC_SIZE_ZERO, &op, &ret_orig);
	ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_TARGET_DEAD, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TEE, ret_orig);

	TEEC_CloseSession(&session);
	Do_ADBG_EndSubCase(c, NULL);
}

static void xtest_tee_test_1201(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	Do_ADBG_BeginSubCase(c, "Check content after TEE_Realloc");
	res = xtest_teec_open_session(&session, &client_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&session, TA_CLIENT_CMD_TEST_REALLOC_CONTENT, &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TRUSTED_APP, ret_orig);

	TEEC_CloseSession(&session);
	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Check illegal pointer");
	res = xtest_teec_open_session(&session, &client_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&session, TA_CLIENT_CMD_TEST_REALLOC_ILLEGAL_PTR, &op, &ret_orig);
	ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_TARGET_DEAD, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TEE, ret_orig);

	TEEC_CloseSession(&session);
	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "TEE_Realloc size zero buffer");
	res = xtest_teec_open_session(&session, &client_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&session, TA_CLIENT_CMD_TEST_REALLOC_SIZE_ZERO, &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEE_ORIGIN_TRUSTED_APP, ret_orig);

	TEEC_CloseSession(&session);
	Do_ADBG_EndSubCase(c, NULL);
}

struct test_1202_thread_arg {
	TEEC_Session *sess;
	uint32_t timeout;
	TEEC_Result res;
};

#define BLOCK_THREAD    3

static void *test_1202_thread(void *arg)
{
	struct test_1202_thread_arg *a = (struct test_1202_thread_arg *)arg;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Session *sess = a->sess;
	uint32_t timeout = a->timeout;
	uint32_t ret_orig;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
		TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = timeout;
	op.params[0].value.b = 0;

	a->res = TEEC_InvokeCommand(sess, TA_SISS_CMD_WAIT, &op,
		&ret_orig);

	return NULL;
}

static void xtest_tee_test_1202(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	pthread_t thr[BLOCK_THREAD];
	struct test_1202_thread_arg arg[BLOCK_THREAD];
	uint32_t i;
	uint32_t num_threads = 0;

	Do_ADBG_BeginSubCase(c, "Test IPC_HANDLE_POLL_SEND_UNBLOCKED event handling.");
	res = xtest_teec_open_session(&session, &siss_ta_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	for (i = 0; i < BLOCK_THREAD; i++, num_threads++) {
		arg[i].sess = &session;
		arg[i].timeout = 2000;
		arg[i].res = TEEC_ERROR_NO_DATA;
		if (!ADBG_EXPECT(c, 0, pthread_create(thr + i, NULL, test_1202_thread,
			arg + i)))
			break;
	}

	for (i = 0; i < num_threads; i++) {
		ADBG_EXPECT(c, 0, pthread_join(thr[i], NULL));
		ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_BUSY, arg[i].res);
	}

	TEEC_CloseSession(&session);
	Do_ADBG_EndSubCase(c, NULL);
}

/*
 * Note: with fork() test cases, the ADBG framework is not multi-process
 * aware. Tests should be structured to check for errors in the parent
 * process because test results in the child are not written to the parent
 * process address space.
 */

#define NUM_PROCESSES 4

static void xtest_tee_test_1300(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session sess = { 0 };
	uint32_t ret_orig;
	int status;
	pid_t this_pid;
	pid_t child_pid;
	TEEC_Operation op[NUM_PROCESSES] = { TEEC_OPERATION_INITIALIZER };
	TEEC_Operation *opp = NULL;
	uint32_t i;

	res = xtest_teec_open_session(&sess, &siss_ta_uuid, NULL,
			&ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	for (i = 0; i < NUM_PROCESSES; i++) {
		child_pid = fork();
		if (child_pid == 0) {
			opp = &op[i];
			break;
		}
	}

	if (child_pid == 0) {
		/* run child process: */
		this_pid = getpid();
		opp->paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,
				TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
		opp->params[0].value.a = this_pid;
		opp->params[0].value.b = 0;
		opp->params[1].value.a = i;
		opp->params[1].value.b = 0;
		res = TEEC_InvokeCommand(&sess, TA_SISS_CMD_RETURN_TH_ID, opp,
				&ret_orig);

		if (res != TEEC_SUCCESS)
			goto child_out;
		else if (this_pid != (pid_t)opp->params[0].value.b)
			res = TEEC_ERROR_BAD_PARAMETERS;
		else if (i != opp->params[1].value.b)
			res = TEEC_ERROR_BAD_PARAMETERS;
child_out:
		/* exit child process */
		exit(res);
	} else {
		TEEC_Result child_res;

		res = TEEC_SUCCESS;
		for (i = 0; i < NUM_PROCESSES; i++) {
			child_res = TEEC_ERROR_GENERIC;
			if (wait(&status) != -1) {
				if (WIFEXITED(status))
					child_res = WEXITSTATUS(status);
			}
			if (child_res != TEEC_SUCCESS)
				res = child_res;
		}
	}

	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	TEEC_CloseSession(&sess);
}

static void xtest_tee_test_1301(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session sess = { 0 };
	uint32_t ret_orig;
	bool unmask = true;
	const uint32_t timeout_ms = 2000;
	const uint32_t delay_ms = 200;
	int status;
	pid_t child_pid;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	res = xtest_teec_open_session(&sess, &core_test_ta_uuid, NULL,
			&ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	op.params[0].value.a = timeout_ms;
	op.params[0].value.b = unmask;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	child_pid = fork();
	if (child_pid == 0) {
		/*
		 * Structure the test to check for errors in the parent
		 * process because test results in the child are not
		 * writen to the parent process address space.
		 */
		res = TEEC_InvokeCommand(&sess, TA_CORE_TEST_CMD_WAIT,
				&op, &ret_orig);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			exit(EXIT_FAILURE);

		exit(EXIT_SUCCESS);
	} else {
		sleep_ms(delay_ms);
		/*
		 * check that concurrent usage of the same operation
		 * struct is detected before reaching TEE.
		 */
		ADBG_EXPECT_TRUE(c, child_pid > 0);
		res = TEEC_InvokeCommand(&sess, TA_CORE_TEST_CMD_WAIT,
				&op, &ret_orig);
		ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_GENERIC, res);
		ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_COMMS, ret_orig);

		wait(&status);
		ADBG_EXPECT_TRUE(c, WIFEXITED(status));
	}
	TEEC_CloseSession(&sess);
}

static void xtest_tee_test_1302(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session sess = { 0 };
	uint32_t ret_orig;
	bool unmask = true;
	const uint32_t timeout_ms = 2000;
	const uint32_t delay_ms = 200;
	int status;

	Do_ADBG_BeginSubCase(c,
		"Cancel operation in child");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		pid_t child_pid;

		res = xtest_teec_open_session(&sess, &core_test_ta_uuid, NULL,
				&ret_orig);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			return;

		op.params[0].value.a = timeout_ms;
		op.params[0].value.b = unmask;
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
		child_pid = fork();
		if (child_pid == 0) {
			Do_ADBG_LogText("child calling Request cancellation");
			sleep_ms(delay_ms);
			/*
			 * Force op.session (and ctx) so that child process can
			 * make TEEC_RequestCancellation ioctl call.
			 * Also force started = 1 as a hack to get child
			 * cancellation to work.
			 */
			op.session = &sess;
			op.started = 1;
			TEEC_RequestCancellation(&op);
			exit(EXIT_SUCCESS);
		} else {
			ADBG_EXPECT_TRUE(c, child_pid > 0);
			res = TEEC_InvokeCommand(&sess, TA_CORE_TEST_CMD_WAIT,
					&op, &ret_orig);
			ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_CANCEL, res);

			wait(&status);
			ADBG_EXPECT_TRUE(c, WIFEXITED(status));
		}
		TEEC_CloseSession(&sess);
	}
	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c,
		"Cancel operation in child; parent modifies operation");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		pid_t child_pid;

		res = xtest_teec_open_session(&sess, &core_test_ta_uuid, NULL,
				&ret_orig);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			return;

		child_pid = fork();
		if (child_pid == 0) {
			sleep_ms(delay_ms);
			/*
			 * Force op.session (and ctx) so that child process can
			 * make TEEC_RequestCancellation ioctl call.
			 * Also force started = 1 as a hack to get child
			 * cancellation to work.
			 */
			op.session = &sess;
			op.started = 1;
			TEEC_RequestCancellation(&op);
			exit(EXIT_SUCCESS);
		} else {
			ADBG_EXPECT_TRUE(c, child_pid > 0);
			/* modify operation struct to trigger COW */
			op.params[0].value.a = timeout_ms;
			op.params[0].value.b = unmask;
			op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					TEEC_NONE, TEEC_NONE, TEEC_NONE);
			res = TEEC_InvokeCommand(&sess, TA_CORE_TEST_CMD_WAIT,
					&op, &ret_orig);
			ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_CANCEL, res);

			wait(&status);
			ADBG_EXPECT_TRUE(c, WIFEXITED(status));
		}
		TEEC_CloseSession(&sess);
	}
	Do_ADBG_EndSubCase(c, NULL);
}

static void xtest_tee_test_1303(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session sess = { 0 };
	TEEC_Context ctx1, ctx2;
	uint32_t ret_orig;
	bool unmask = true;
	const uint32_t timeout_ms = 2000;
	const uint32_t delay_ms = 200;
	int status;
	pid_t child_pid;

	ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InitializeContext(NULL, &ctx1));
	ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InitializeContext(NULL, &ctx2));

	res = TEEC_OpenSession(&ctx1, &sess, &core_test_ta_uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto end_cleanup;

	/*
	 * Note for these tests, the parent process uses the original operation
	 * struct whereas the child process sees a new copy-on-write copy of
	 * the operation struct as soon as the original operation is modified.
	 * Each new subcase sees the original operation struct as it is running
	 * in the parent process.
	 */
	Do_ADBG_BeginSubCase(c, "overwrite op ctx");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		op.params[0].value.a = timeout_ms;
		op.params[0].value.b = unmask;
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);

		child_pid = fork();
		if (child_pid == 0) {
			/*
			 * Hack operation to make the cancel request from ctx2
			 * using ctx1's session.
			 * Also force started = 1 as a hack to get child
			 * cancellation to work.
			 */
			sleep_ms(delay_ms);
			op.session = &sess;
			op.started = 1;
			op.session->ctx = &ctx2;
			TEEC_RequestCancellation(&op);
			exit(EXIT_SUCCESS);
		} else {
			ADBG_EXPECT_TRUE(c, child_pid > 0);
			res = TEEC_InvokeCommand(&sess, TA_CORE_TEST_CMD_WAIT,
					&op, &ret_orig);
			ADBG_EXPECT_TEEC_SUCCESS(c, res);

			wait(&status);
			ADBG_EXPECT_TRUE(c, WIFEXITED(status));
		}
	}
	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "overwrite op ctx and session_id");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		op.started = 0;
		op.params[0].value.a = timeout_ms;
		op.params[0].value.b = unmask;
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);

		child_pid = fork();
		if (child_pid == 0) {
			/*
			 * hack operation to make the cancel request from ctx2
			 * using zeroed session_id (as for open session).
			 * Also force started = 1 as a hack to get child
			 * cancellation to work.
			 */
			sleep_ms(delay_ms);
			op.session = &sess;
			op.started = 1;
			op.session->session_id = 0;
			op.session->ctx = &ctx2;
			TEEC_RequestCancellation(&op);
			exit(EXIT_SUCCESS);
		} else {
			ADBG_EXPECT_TRUE(c, child_pid > 0);
			res = TEEC_InvokeCommand(&sess, TA_CORE_TEST_CMD_WAIT,
					&op, &ret_orig);
			ADBG_EXPECT_TEEC_SUCCESS(c, res);

			wait(&status);
			ADBG_EXPECT_TRUE(c, WIFEXITED(status));
		}
	}
	Do_ADBG_EndSubCase(c, NULL);

end_cleanup:
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx1);
	TEEC_FinalizeContext(&ctx2);
}

static void *thr_1900(void *arg)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Session *sess = (TEEC_Session *)arg;
	uint32_t ret_orig;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
		TEEC_VALUE_INPUT);
	op.params[0].value.a = 10000; // long timeout
	op.params[0].value.b = 0; // don't unmask cancellations
	TEEC_InvokeCommand(sess, TA_CORE_TEST_CMD_WAIT, &op, &ret_orig);
	return NULL;
}

static void xtest_tee_test_1900(ADBG_Case_t *c)
{
	int status;
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;

	pid_t child_pid;

	child_pid = fork();
	if (child_pid == 0) {
		pthread_t thr;

		if (TEEC_InitializeContext(NULL, &ctx) != TEEC_SUCCESS)
			exit(EXIT_FAILURE);

		res = TEEC_OpenSession(&ctx, &sess, &core_test_ta_uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, NULL);
		if (res != TEEC_SUCCESS) {
			TEEC_FinalizeContext(&ctx);
			exit(EXIT_FAILURE);
		}

		pthread_create(&thr, NULL, thr_1900, &sess);

		(void)usleep(2000000); // wait until child thread invokes the command
		exit(EXIT_SUCCESS);
	} else {
		ADBG_EXPECT_TRUE(c, child_pid > 0);
		wait(&status);
		ADBG_EXPECT_TRUE(c, WIFEXITED(status));
	}
}

ADBG_CASE_DEFINE(XTEST_TEE_1100, xtest_tee_test_1100,
		/* Title */
		"Multi Instance memref mapping with SIMS TA",
		/* Short description */
		"Verify that memory references are properly mapped when"
		"multi-instance TAs use the Internal Client API to invoke"
		"commands with memref parameters on other TAs",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1101, xtest_tee_test_1101,
		/* Title */
		"Try loading a TA with a misformed manifest",
		/* Short description */
		"Verify that loading a TA with a misformed manifest is"
		"gracefully handled",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1102, xtest_tee_test_1102,
		/* Title */
		"Verify that 64bit overflows in memref params are gracefully handled",
		/* Short description */
		"Try overflowing various memref param fields with a 64bit value",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1103, xtest_tee_test_1103,
		/* Title */
		"Validate internal client API parameters",
		/* Short description */
		"Try passing invalid addresses to internal client API",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1104, xtest_tee_test_1104,
		/* Title */
		"Invoking commands on a dead TA, TEE_ORIGIN_TEE",
		/* Short description */
		"Verify that the TEE Framework returns the proper result code"
		"when the framework panics a TA (TEE_ORIGIN_TEE). This case is"
		"distinct from the panic source is TEE_ORIGIN_TRUSTED_APP.",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1105, xtest_tee_test_1105,
		/* Title */
		"Test client TA panic and exit handling",
		/* Short description */
		"Verify that the TEE Framework cleans up the client sessions"
		"when the client TA panics or exits abruptly.",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1106, xtest_tee_test_1106,
		/* Title */
		"Test if TEE Framework destroys TA instance after OpenSession error",
		/* Short description */
		"Verify that the TEE Framework destroys TA instance "
		"after OpenSession error in case when there is "
		"no more opened sessions on that TA",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1107, xtest_tee_test_1107,
		/* Title */
		"Test if SIMS TAs behave correctly on OpenSession error originating in TA",
		/* Short description */
		"Verify that after OpenSession error SIMS TA continues to work properly for"
		"other sessions.",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1108, xtest_tee_test_1108,
		/* Title */
		"Test concurrency for threads invoking commands on the same session",
		/* Short description */
		"Verify that return values are passed to the originating thread when"
		"invoking commands from multiple threads operating on a same session.",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1109, xtest_tee_test_1109,
		/* Title */
		"Test closing of child sessions",
		/* Short description */
		"Verify that child sessions are closed correctly.",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1110, xtest_tee_test_1110,
		/* Title */
		"Test application handles on open session failure",
		/* Short description */
		"Test if it's possible to exhaust handles if TEE_OpenTASession fails.",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1111, xtest_tee_test_1111,
		/* Title */
		"Test TEE_Wait timeout",
		/* Short description */
		"Test if TEE_Wait time interval is larger than requested timeout.",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1112, xtest_tee_test_1112,
		/* Title */
		"Test TA memrefs on exit",
		/* Short description */
		"Test if TA memrefs unmap on TA exit.",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1113, xtest_tee_test_1113,
		/* Title */
		"Test TA memrefs on entry point return",
		/* Short description */
		"Test if TA memrefs unmap after entry point is finished.",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1114, xtest_tee_test_1114,
		/* Title */
		"Test cancellationRequestTimeout interval",
		/* Short description */
		"Test TEE_InvokeTACommand with timeout.",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1115, xtest_tee_test_1115,
		/* Title */
		"Test TEEC_SharedMemory wrong TEEC_Context",
		/* Short description */
		"Test using TEEC_SharedMemory within wrong context.",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1116, xtest_tee_test_1116,
		/* Title */
		"Test cancel_id on TEE side",
		/* Short description */
		"Test if cancel_id is generated and used correctly on TEE side",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1117, xtest_tee_test_1117,
		/* Title */
		"Test cancel_id on TEE side with open session",
		/* Short description */
		"Test if cancel_id is generated and used correctly on TEE side using"
		"open session command with timeout",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1118, xtest_tee_test_1118,
		/* Title */
		"Test cancel on REE side",
		/* Short description */
		"Test cancelling operations in more complex scenarios",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1119, xtest_tee_test_1119,
		/* Title */
		"Test TEEC_ERROR_BUSY for open session on SIMS TAs",
		/* Short description */
		"Test that TEEC_ERROR_BUSY is properly handled for open "
		"session on single-instance multi-session TAs",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1120, xtest_tee_test_1120,
		/* Title */
		"Test invoking command on busy SIMS TAs",
		/* Short description */
		"Test that invoking command on busy single-instance multi-session TA "
		"gets through once the TA has finished working on previous command.",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1121, xtest_tee_test_1121,
		/* Title */
		"Test that cancel flag is cleared between operations",
		/* Short description */
		"Test that cancel flag is cleared between operations "
		"when TA instance is not exited",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1122, xtest_tee_test_1122,
		/* Title */
		"Test clearing cancel flag under race conditions",
		/* Short description */
		"Send cancel requests with the aim of hitting potential race "
		"conditions in the TEE implementation",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1123, xtest_tee_test_1123,
		/* Title */
		"Test opening session on SIMS TA after panic",
		/* Short description */
		"Try opening a session on a SIMS TA after it has panicked.",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1124, xtest_tee_test_1124,
		/* Title */
		"Test opening session on SISS TA after panic",
		/* Short description */
		"Try opening a session on a SISS TA after it has panicked.",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1125, xtest_tee_test_1125,
		/* Title */
		"Test cancellation of the pending operation",
		/* Short description */
		"Test if system behaves correctly if cancelling operation is pending.",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1126, xtest_tee_test_1126,
		/* Title */
		"Test closing a session on a panicked TA",
		/* Short description */
		"Test system behavior trying to close a session that has caused "
		"TA panic.",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1127, xtest_tee_test_1127,
		/* Title */
		"Test closing a NULL session",
		/* Short description */
		"Test system behavior trying to close a NULL session",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1200, xtest_tee_test_1200,
		/* Title */
		"Test TEE_Malloc",
		/* Short description */
		"Verify that TEE_Malloc meets GP specification requirements",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1201, xtest_tee_test_1201,
		/* Title */
		"Test TEE_Realloc",
		/* Short description */
		"Verify that TEE_Realloc meets GP specification requirements",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1202, xtest_tee_test_1202,
		/* Title */
		"Test IPC_HANDLE_POLL_SEND_UNBLOCKED event",
		/* Short description */
		"Verify that IPC_HANDLE_POLL_SEND_UNBLOCKED is handled correctly.",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1300, xtest_tee_test_1300,
		/* Title */
		"Test fork() using parent session in forked child process",
		/* Short description */
		"Verify fork() usage with GP api",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1301, xtest_tee_test_1301,
		/* Title */
		"Test fork() parent and child using same operation struct",
		/* Short description */
		"Verify that fork() and operation struct interactions",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1302, xtest_tee_test_1302,
		/* Title */
		"Test fork() and cancellation",
		/* Short description */
		"Verify fork() and cancellation interactions",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1303, xtest_tee_test_1303,
		/* Title */
		"Test fork() and cancel from other context",
		/* Short description */
		"Verify fork() and cancellation interactions",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1900, xtest_tee_test_1900,
		/* Title */
		"Test force closing sessions",
		/* Short description */
		"Verify force closing sessions is handled okay",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );
