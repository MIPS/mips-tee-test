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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <adbg.h>
#include "xtest_test.h"
#include "xtest_helpers.h"

#if SHA_AND_AES_PERF_NOT_YET_IMPLEMENTED // TODO WITH_CRYPTO_TEST
#include "crypto_common.h"
#endif

#ifdef WITH_GP_TESTS
#include "adbg_case_declare.h"
#include "adbg_entry_declare.h"
#endif

#ifdef WITH_REE
#define INTERNAL_CLIENT_API_ONLY "Internal Client API test only"
#else
#define INTERNAL_CLIENT_API_ONLY NULL
#endif

/*ADBG Cases declaration.*/
ADBG_CASE_DECLARE(XTEST_TEE_1001);
ADBG_CASE_DECLARE(XTEST_TEE_1004);
ADBG_CASE_DECLARE(XTEST_TEE_1005);
ADBG_CASE_DECLARE(XTEST_TEE_1006);
ADBG_CASE_DECLARE(XTEST_TEE_1007);
ADBG_CASE_DECLARE(XTEST_TEE_1008);
ADBG_CASE_DECLARE(XTEST_TEE_1009);
ADBG_CASE_DECLARE(XTEST_TEE_1010);
ADBG_CASE_DECLARE(XTEST_TEE_1011);
ADBG_CASE_DECLARE(XTEST_TEE_1012);
ADBG_CASE_DECLARE(XTEST_TEE_1013);
ADBG_CASE_DECLARE(XTEST_TEE_1100);
ADBG_CASE_DECLARE(XTEST_TEE_1101);
ADBG_CASE_DECLARE(XTEST_TEE_1102);
ADBG_CASE_DECLARE(XTEST_TEE_1103);
ADBG_CASE_DECLARE(XTEST_TEE_1104);
ADBG_CASE_DECLARE(XTEST_TEE_1105);
ADBG_CASE_DECLARE(XTEST_TEE_1106);
ADBG_CASE_DECLARE(XTEST_TEE_1107);
ADBG_CASE_DECLARE(XTEST_TEE_1108);
ADBG_CASE_DECLARE(XTEST_TEE_1109);
ADBG_CASE_DECLARE(XTEST_TEE_1110);
ADBG_CASE_DECLARE(XTEST_TEE_1111);
ADBG_CASE_DECLARE(XTEST_TEE_1112);
ADBG_CASE_DECLARE(XTEST_TEE_1113);
ADBG_CASE_DECLARE(XTEST_TEE_1114);
ADBG_CASE_DECLARE(XTEST_TEE_1115);
ADBG_CASE_DECLARE(XTEST_TEE_1116);
ADBG_CASE_DECLARE(XTEST_TEE_1117);
ADBG_CASE_DECLARE(XTEST_TEE_1118);
ADBG_CASE_DECLARE(XTEST_TEE_1119);
ADBG_CASE_DECLARE(XTEST_TEE_1120);
ADBG_CASE_DECLARE(XTEST_TEE_1121);
ADBG_CASE_DECLARE(XTEST_TEE_1122);
ADBG_CASE_DECLARE(XTEST_TEE_1123);
ADBG_CASE_DECLARE(XTEST_TEE_1124);
ADBG_CASE_DECLARE(XTEST_TEE_1125);
ADBG_CASE_DECLARE(XTEST_TEE_1126);
ADBG_CASE_DECLARE(XTEST_TEE_1127);
ADBG_CASE_DECLARE(XTEST_TEE_1200);
ADBG_CASE_DECLARE(XTEST_TEE_1201);
ADBG_CASE_DECLARE(XTEST_TEE_1202);
ADBG_CASE_DECLARE(XTEST_TEE_1300);
ADBG_CASE_DECLARE(XTEST_TEE_1301);
ADBG_CASE_DECLARE(XTEST_TEE_1302);
ADBG_CASE_DECLARE(XTEST_TEE_1303);
ADBG_CASE_DECLARE(XTEST_TEE_1900);

ADBG_CASE_DECLARE(XTEST_TEE_5006);

ADBG_CASE_DECLARE(XTEST_TEE_80100);
ADBG_CASE_DECLARE(XTEST_TEE_80101);
ADBG_CASE_DECLARE(XTEST_TEE_80102);
ADBG_CASE_DECLARE(XTEST_TEE_80103);
ADBG_CASE_DECLARE(XTEST_TEE_80104);
ADBG_CASE_DECLARE(XTEST_TEE_80105);
ADBG_CASE_DECLARE(XTEST_TEE_80106);
ADBG_CASE_DECLARE(XTEST_TEE_80107);

#ifdef WITH_GP_TESTS
ADBG_CASE_DECLARE_AUTO_GENERATED_TESTS()
#endif

ADBG_SUITE_DECLARE(XTEST_TEE_TEST)

/*ADBG Suite definition.*/
ADBG_SUITE_DEFINE_BEGIN(XTEST_TEE_TEST, NULL)
#if WITH_STATIC_TA_TEST
ADBG_SUITE_ENTRY(XTEST_TEE_1001, NULL)
#endif
ADBG_SUITE_ENTRY(XTEST_TEE_1004, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1005, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1006, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1007, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1008, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1009, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1010, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1011, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1012, NULL)
#if WITH_CONCURRENT_TEST
ADBG_SUITE_ENTRY(XTEST_TEE_1013, NULL)
#endif
ADBG_SUITE_ENTRY(XTEST_TEE_1100, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1101, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1102, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1103, INTERNAL_CLIENT_API_ONLY)
ADBG_SUITE_ENTRY(XTEST_TEE_1104, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1105, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1106, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1107, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1108, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1109, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1110, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1111, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1112, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1113, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1114, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1115, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1116, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1117, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1118, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1119, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1120, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1121, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1122, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1123, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1124, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1125, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1126, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1127, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1200, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1201, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1202, "Obsolete")
ADBG_SUITE_ENTRY(XTEST_TEE_1300, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1301, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1302, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1303, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1900, "NULL")
ADBG_SUITE_ENTRY(XTEST_TEE_5006, NULL)
#if WITH_EXTRA_PROPERTY_TESTS
ADBG_SUITE_ENTRY(XTEST_TEE_80100, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_80101, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_80102, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_80103, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_80104, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_80105, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_80106, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_80107, NULL)
#endif
#if WITH_GP_TESTS
ADBG_ENTRY_AUTO_GENERATED_TESTS()
#endif

ADBG_SUITE_DEFINE_END()

char *_device = NULL;
unsigned int level = 0;
static const char glevel[] = "0";
static const char gsuitename[] = "regression";

int main(int argc, char *argv[])
{
	int ret;
	char *p = (char *)glevel;
	char *test_suite = (char *)gsuitename;
	(void)argc;
	(void)argv;

	if (p)
		level = atoi(p);
	else
		level = 0;
	printf("Run test suite with level=%d\n", level);

	printf("\nTEE test application started with device [%s]\n", _device);

	xtest_teec_ctx_init();

	if (strcmp(test_suite, "regression") == 0)
		ret = Do_ADBG_RunSuite(&ADBG_Suite_XTEST_TEE_TEST, argc - 1, argv + 1);
	else {
		fprintf(stderr, "No test suite found: %s\n", test_suite);
		ret = -1;
	}

	xtest_teec_ctx_deinit();

	printf("TEE test application done!\n");
	return ret;
}
