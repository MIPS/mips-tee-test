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

#include "xtest_helpers.h"
#include "xtest_test.h"
#include "xtest_ta_defines.h"

#include <tee_client_api.h>

#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include <assert.h>

TEEC_Context xtest_teec_ctx;

TEEC_Result xtest_teec_ctx_init(void)
{
	return TEEC_InitializeContext(_device, &xtest_teec_ctx);
}

TEEC_Result xtest_teec_open_session(TEEC_Session *session,
				    const TEEC_UUID *uuid, TEEC_Operation *op,
				    uint32_t *ret_orig)
{
	return TEEC_OpenSession(&xtest_teec_ctx, session, uuid,
				TEEC_LOGIN_PUBLIC, NULL, op, ret_orig);
}

void xtest_teec_ctx_deinit(void)
{
	TEEC_FinalizeContext(&xtest_teec_ctx);
}
