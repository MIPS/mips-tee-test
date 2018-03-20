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

#ifndef XML_DATASTORAGE_API_H_
#define XML_DATASTORAGE_API_H_

#include <openssl/bn.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#ifdef USER_SPACE
#include <pthread.h>
#include <unistd.h>
#endif

#include "tee_client_api.h"
#include "xml_common_api.h"
#include "xml_ds_crypto_common_api.h"

#define BN_DH_INIT(exit_label, ret) \
	do { \
		saved_dh_val.ctx = BN_CTX_new(); \
		if (saved_dh_val.ctx == NULL) { \
			goto exit_label; \
		} \
		ret = TEE_SUCCESS; \
		saved_dh_val.P = BN_new(); \
		saved_dh_val.G = BN_new(); \
		saved_dh_val.Y = BN_new(); \
		saved_dh_val.X = BN_new(); \
	} while (0)

#define BN_RSA_INIT(exit_label, ret) \
	do { \
		saved_rsa_val.ctx = BN_CTX_new(); \
		if (saved_rsa_val.ctx == NULL) { \
			goto exit_label; \
		} \
		ret = TEE_SUCCESS; \
		saved_rsa_val.mod = BN_new(); \
		saved_rsa_val.pub_exp = BN_new(); \
		saved_rsa_val.priv_exp = BN_new(); \
		saved_rsa_val.prime1 = BN_new(); \
		saved_rsa_val.prime2 = BN_new(); \
		saved_rsa_val.exp1 = BN_new(); \
		saved_rsa_val.exp2 = BN_new(); \
		saved_rsa_val.coef = BN_new(); \
	} while (0)

#define Invoke_CloseAndDeletePersistentObject Invoke_Simple_Function_Object_Handle
#define Invoke_CloseAndDeletePersistentObject1 Invoke_Simple_Function_Object_Handle

#define Invoke_AllocatePersistentObjectEnumerator Invoke_Simple_Function_SubTestCase
#define Invoke_FreePersistentObjectEnumerator Invoke_Simple_Function_SubTestCase
#define Invoke_ResetPersistentObjectEnumerator Invoke_Simple_Function_SubTestCase

#define Invoke_CopyObjectAttributes Invoke_CopyObjectAttributes1
#define Invoke_GetObjectInfo Invoke_GetObjectInfo1

#define TEE_ERROR_TOO_SHORT_BUFFER TEE_ERROR_SHORT_BUFFER

#define NOMINAL_CASE 0

#define BUFFER_ATTRIBUTE 0
#define VALUE_ATTRIBUTE 1

#define STORAGE_ID_NOT_EXISTING 0x01234567
static const uint8_t TEE_ATTR_RSA_OAEP_LABEL_VALUE01[0];

#ifdef USER_SPACE
/* Test data defines */
// static pthread_t THREAD01_DEFAULT;
#endif

static TEEC_Operation *OPERATION01;
static TEEC_Operation *OPERATION02;

// static uint32_t big_size = BIG_SIZE;
// static uint32_t DS_BIG_SIZE = 16384;

/* ALL_OBJECT_IDS */
static uint8_t OBJECT_ID_01[] = "testobject01";
static uint8_t OBJECT_ID_02[] = "testobject02";
static uint8_t OBJECT_ID_03[] = "testobject03";
static uint8_t OBJECT_ID_SR[] = "testobjectSR";
static uint8_t OBJECT_ID_TOO_LONG[] = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEFx";

static uint8_t BUFFER01[] = {
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB
};

static uint8_t EMPTY_BUFFER[0];

static uint8_t INITIAL_DATA[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
	0x1C, 0x1D, 0x1E, 0x1F,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
	0x2C, 0x2D, 0x2E, 0x2F,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
	0x3C, 0x3D, 0x3E, 0x3F,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
	0x4C, 0x4D, 0x4E, 0x4F,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B,
	0x5C, 0x5D, 0x5E, 0x5F,
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B,
	0x6C, 0x6D, 0x6E, 0x6F,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B,
	0x7C, 0x7D, 0x7E, 0x7F,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B,
	0x8C, 0x8D, 0x8E, 0x8F,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B,
	0x9C, 0x9D, 0x9E, 0x9F,
	0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
	0xAC, 0xAD, 0xAE, 0xAF,
	0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB,
	0xBC, 0xBD, 0xBE, 0xBF,
	0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB,
	0xCC, 0xCD, 0xCE, 0xCF,
	0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB,
	0xDC, 0xDD, 0xDE, 0xDF,
	0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB,
	0xEC, 0xED, 0xEE, 0xEF,
	0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB,
	0xFC, 0xFD, 0xFE, 0xFF,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
	0x1C, 0x1D, 0x1E, 0x1F,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
	0x2C, 0x2D, 0x2E, 0x2F,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
	0x3C, 0x3D, 0x3E, 0x3F,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
	0x4C, 0x4D, 0x4E, 0x4F,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B,
	0x5C, 0x5D, 0x5E, 0x5F,
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B,
	0x6C, 0x6D, 0x6E, 0x6F,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B,
	0x7C, 0x7D, 0x7E, 0x7F,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B,
	0x8C, 0x8D, 0x8E, 0x8F,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B,
	0x9C, 0x9D, 0x9E, 0x9F,
	0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
	0xAC, 0xAD, 0xAE, 0xAF,
	0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB,
	0xBC, 0xBD, 0xBE, 0xBF,
	0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB,
	0xCC, 0xCD, 0xCE, 0xCF,
	0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB,
	0xDC, 0xDD, 0xDE, 0xDF,
	0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB,
	0xEC, 0xED, 0xEE, 0xEF,
	0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB,
	0xFC, 0xFD, 0xFE, 0xFF,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
	0x1C, 0x1D, 0x1E, 0x1F,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
	0x2C, 0x2D, 0x2E, 0x2F,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
	0x3C, 0x3D, 0x3E, 0x3F,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
	0x4C, 0x4D, 0x4E, 0x4F,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B,
	0x5C, 0x5D, 0x5E, 0x5F,
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B,
	0x6C, 0x6D, 0x6E, 0x6F,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B,
	0x7C, 0x7D, 0x7E, 0x7F,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B,
	0x8C, 0x8D, 0x8E, 0x8F,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B,
	0x9C, 0x9D, 0x9E, 0x9F,
	0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
	0xAC, 0xAD, 0xAE, 0xAF,
	0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB,
	0xBC, 0xBD, 0xBE, 0xBF,
	0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB,
	0xCC, 0xCD, 0xCE, 0xCF,
	0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB,
	0xDC, 0xDD, 0xDE, 0xDF,
	0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB,
	0xEC, 0xED, 0xEE, 0xEF,
	0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB,
	0xFC, 0xFD, 0xFE, 0xFF,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
	0x1C, 0x1D, 0x1E, 0x1F,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
	0x2C, 0x2D, 0x2E, 0x2F,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
	0x3C, 0x3D, 0x3E, 0x3F,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
	0x4C, 0x4D, 0x4E, 0x4F,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B,
	0x5C, 0x5D, 0x5E, 0x5F,
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B,
	0x6C, 0x6D, 0x6E, 0x6F,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B,
	0x7C, 0x7D, 0x7E, 0x7F,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B,
	0x8C, 0x8D, 0x8E, 0x8F,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B,
	0x9C, 0x9D, 0x9E, 0x9F,
	0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
	0xAC, 0xAD, 0xAE, 0xAF,
	0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB,
	0xBC, 0xBD, 0xBE, 0xBF,
	0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB,
	0xCC, 0xCD, 0xCE, 0xCF,
	0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB,
	0xDC, 0xDD, 0xDE, 0xDF,
	0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB,
	0xEC, 0xED, 0xEE, 0xEF,
	0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB,
	0xFC, 0xFD, 0xFE, 0xFF,
};

static uint8_t SINGLE_BYTE[] = {0x00};

static const uint32_t TEE_ATTR_VALUE_NONE = 0x76543210;

/** ALL_TEEC_UUID
 *
 * These constants are the UUID of existing
 * Trusted Applications
 */
/* "SMARTCSLTDATAST1" */
static TEEC_UUID UUID_TTA_testingInternalAPI_dataStorage = {
	0x534D4152, 0x5443, 0x534C,
	{ 0x54, 0x44, 0x41, 0x54, 0x41, 0x53, 0x54, 0x31 }
};

static TEE_ObjectHandle *OBJECT_HANDLE_03;

static uint32_t iObjectDataFlags1;
static uint32_t iObjectDataFlags2;
static uint32_t iObjectDataFlags3;

struct ds_op_info {
	uint32_t obj_type;
	uint32_t key_size;
	uint32_t max_key_size;
	uint32_t obj_usage;
	uint32_t data_size;
	uint32_t data_pos;
	uint32_t handle_flags;
	uint32_t data_flags;
};

struct attr_val {
	uint32_t a;
	uint32_t b;
};

struct dh_val {
	BN_CTX *ctx;
	BIGNUM *P;
	BIGNUM *G;
	BIGNUM *Y;
	BIGNUM *X;
	int32_t L;
};

struct rsa_val {
	BN_CTX *ctx;
	BIGNUM *mod;
	BIGNUM *pub_exp;
	BIGNUM *priv_exp;
	BIGNUM *prime1;
	BIGNUM *prime2;
	BIGNUM *exp1;
	BIGNUM *exp2;
	BIGNUM *coef;
};

/* Saved in Invoke_GetObjectInfo1 */
struct ds_op_info saved_ds_obj_info;
/* Saved in Invoke_GetObjectValueAttribute */
struct attr_val obj_val_attr;
/* Saved in Macro_GetDHAttributes */
struct dh_val saved_dh_val;
/* Saved in Macro_GetRSAAttributes */
struct rsa_val saved_rsa_val;
/* Saved in Invoke_GetNextPersistentObject_All */
static uint8_t *saved_operation_id;
///* Saved in Invoke_GetNextPersistentObject_All */
// struct ds_op_info saved_pers_obj_enum;

/* Saved in Invoke_ReadObjectData */
struct data_buffer saved_read_data;

/* DATA STORAGE API HELPERS */
#define ABS(n) ((n) < 0 ? 0 - (n) : (n))

static void ds_init(void)
{
	saved_ds_obj_info.obj_type = 0;
	saved_ds_obj_info.key_size = 0;
	saved_ds_obj_info.max_key_size = 0;
	saved_ds_obj_info.obj_usage = 0;
	saved_ds_obj_info.data_size = 0;
	saved_ds_obj_info.data_pos = 0;
	saved_ds_obj_info.handle_flags = 0;
	saved_ds_obj_info.data_flags = 0;
	obj_val_attr.a = 0;
	obj_val_attr.b = 0;
	saved_dh_val.ctx = NULL;
	saved_dh_val.P = NULL;
	saved_dh_val.G = NULL;
	saved_dh_val.Y = NULL;
	saved_dh_val.X = NULL;
	saved_dh_val.L = 0;
	saved_rsa_val.ctx = NULL;
	saved_rsa_val.mod = NULL;
	saved_rsa_val.pub_exp = NULL;
	saved_rsa_val.priv_exp = NULL;
	saved_rsa_val.prime1 = NULL;
	saved_rsa_val.prime2 = NULL;
	saved_rsa_val.exp1 = NULL;
	saved_rsa_val.exp2 = NULL;
	saved_rsa_val.coef = NULL;

	saved_operation_id = NULL;
	DS_CRYPTO_INIT(saved_read_data);
}

static void ds_reset(void)
{
	saved_ds_obj_info.obj_type = 0;
	saved_ds_obj_info.key_size = 0;
	saved_ds_obj_info.max_key_size = 0;
	saved_ds_obj_info.obj_usage = 0;
	saved_ds_obj_info.data_size = 0;
	saved_ds_obj_info.data_pos = 0;
	saved_ds_obj_info.handle_flags = 0;
	saved_ds_obj_info.data_flags = 0;
	obj_val_attr.a = 0;
	obj_val_attr.b = 0;
	BN_clear_free(saved_dh_val.P);
	BN_clear_free(saved_dh_val.G);
	BN_clear_free(saved_dh_val.Y);
	BN_clear_free(saved_dh_val.X);
	saved_dh_val.L = 0;
	if (saved_dh_val.ctx)
		BN_CTX_free(saved_dh_val.ctx);
	BN_clear_free(saved_rsa_val.mod);
	BN_clear_free(saved_rsa_val.pub_exp);
	BN_clear_free(saved_rsa_val.priv_exp);
	BN_clear_free(saved_rsa_val.prime1);
	BN_clear_free(saved_rsa_val.prime2);
	BN_clear_free(saved_rsa_val.exp1);
	BN_clear_free(saved_rsa_val.exp2);
	BN_clear_free(saved_rsa_val.coef);
	if (saved_rsa_val.ctx)
		BN_CTX_free(saved_rsa_val.ctx);

	saved_operation_id = NULL;
	DS_CRYPTO_FREE(saved_read_data);
}

static struct attr_list_node *get_next_attribute(struct attr_list_node *list_node)
{
	if (is_attr_list_empty(list_node)) {
		return NULL;
	} else {
		return list_node->next;
	}
}

static TEEC_Result Invoke_Simple_Function_SubTestCase(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t subTestCase)
{
	TEEC_Result res = TEEC_SUCCESS;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	op.params[0].value.a = subTestCase;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_CopyObjectAttributes1(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	TEE_ObjectHandle *obhDst, TEE_ObjectHandle *obhSrc)
{
	TEEC_Result res = TEEC_SUCCESS;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	op.params[0].value.a = (uint32_t)*obhDst;
	op.params[0].value.b = (uint32_t)*obhSrc;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_CreatePersistentObject(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t storageID,
	uint8_t *objectID, uint32_t dataFlags, TEE_ObjectHandle *attr,
	uint8_t *initData, uint32_t initDataLen, TEE_ObjectHandle *obh)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(sess->ctx, SHARE_MEM01, strlen((const char *)objectID),
			       TEEC_MEM_INPUT, objectID, mem01_exit);

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(sess->ctx, SHARE_MEM02, initDataLen,
			       TEEC_MEM_INPUT, initData, mem02_exit);

	op.params[0].value.a = (uint32_t)*obh;
	op.params[0].value.b = storageID;
	op.params[1].value.a = dataFlags;
	op.params[1].value.b = (uint32_t)*attr;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM01, SHARE_MEM01->size);
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, SHARE_MEM02->size);

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_PARTIAL_INPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_GenerateKey(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	TEE_ObjectHandle *obh, uint32_t keySize, struct attr_list_node *attrList)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	struct attr_list_node *pAttr = attrList;
	uint32_t org;
	(void)c;

	op.params[0].value.a = (uint32_t)*obh;
	op.params[0].value.b = keySize;

	if(!is_attr_list_empty(pAttr)) {
		op.params[1].value.a = pAttr->attr_idx;
		pAttr = get_next_attribute(pAttr);
	} else {
		op.params[1].value.a = ATTR_NONE;
	}
	if(!is_attr_list_empty(pAttr)) {
		op.params[1].value.b = pAttr->attr_idx;
		pAttr = get_next_attribute(pAttr);
	} else {
		op.params[1].value.b = ATTR_NONE;
	}
	if(!is_attr_list_empty(pAttr)) {
		op.params[2].value.a = pAttr->attr_idx;
		pAttr = get_next_attribute(pAttr);
	} else {
		op.params[2].value.a = ATTR_NONE;
	}
	if(!is_attr_list_empty(pAttr)) {
		op.params[2].value.b = pAttr->attr_idx;
		pAttr = get_next_attribute(pAttr);
	} else {
		op.params[2].value.b = ATTR_NONE;
	}

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
		TEEC_VALUE_INPUT, TEEC_NONE);

	return TEEC_InvokeCommand(sess, cmdId, &op, &org);
}

static TEEC_Result Invoke_Retrieve_ObjectInfo(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t objInfo)
{
	TEEC_Result res = TEEC_SUCCESS;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	op.params[0].value.a = objInfo;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INOUT,  TEEC_VALUE_OUTPUT,
		TEEC_VALUE_OUTPUT,  TEEC_VALUE_OUTPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if ( res == TEEC_SUCCESS) {
		saved_ds_obj_info.obj_type = op.params[0].value.b;
		saved_ds_obj_info.key_size = op.params[1].value.a;
		saved_ds_obj_info.max_key_size = op.params[1].value.b;
		saved_ds_obj_info.obj_usage = op.params[2].value.a;
		saved_ds_obj_info.data_size = op.params[2].value.b;
		saved_ds_obj_info.data_pos = op.params[3].value.a;
		saved_ds_obj_info.handle_flags = op.params[3].value.b;
	}

	return res;
}

static TEEC_Result Invoke_GetNextPersistentObject_All(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t objEnum, uint32_t objInfo, uint32_t count)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	(void)count;
	ALLOCATE_SHARED_MEMORY(sess->ctx, SHARE_MEM01, TEE_OBJECT_ID_MAX_LEN,
			       TEEC_MEM_OUTPUT, mem01_exit);

	op.params[0].value.a = objEnum;
	op.params[0].value.b = objInfo;
	op.params[1].value.a = 0;
	op.params[1].value.b = 0;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM01,
					      SHARE_MEM01->size);

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT,
		TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (res != TEEC_SUCCESS)
		goto next_obj_err;

	/* Save objId for observation */
	saved_operation_id = (uint8_t *)malloc(SHARE_MEM01->size);
	if (!saved_operation_id)
		goto next_obj_err;
	memcpy((void *)saved_operation_id, SHARE_MEM01->buffer, SHARE_MEM01->size);

	res = Invoke_Retrieve_ObjectInfo(c, SESSION01, CMD_DS_Retrieve_ObjectInfo,
		objInfo);

next_obj_err:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static void Check_EnumeratedPersistentObject(ADBG_Case_t *c,
	uint8_t *cObjId, uint32_t cObjType, uint32_t cKeySize,
	uint32_t cMaxKeySize, uint32_t cObjUsage, uint32_t cDataSize,
	uint32_t cHandleFlags, uint32_t cDataFlags)
{
	(void)ADBG_EXPECT_NOT_NULL(c, saved_operation_id);
	if (saved_operation_id) {
		(void)ADBG_EXPECT_EQUAL(c, (void *)&cObjId, saved_operation_id,
			strlen((const char*)cObjId));
	}
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cObjType, ==,
		saved_ds_obj_info.obj_type);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cKeySize, ==,
		saved_ds_obj_info.key_size);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cMaxKeySize, ==,
		saved_ds_obj_info.max_key_size);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cObjUsage, ==,
		saved_ds_obj_info.obj_usage);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cDataSize, ==,
		saved_ds_obj_info.data_size);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, (cHandleFlags | cDataFlags), ==,
		saved_ds_obj_info.handle_flags);
	free(saved_operation_id);
	saved_operation_id = NULL;
}

static TEEC_Result Invoke_GetNextPersistentObject_ErrorChecking(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t objEnum, uint32_t objInfo, uint32_t objIdNull, uint32_t objIdLenNull)
{
	TEEC_Result res = TEEC_SUCCESS;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	op.params[0].value.a = objEnum;
	op.params[0].value.b = objInfo;
	op.params[1].value.a = objIdNull;
	op.params[1].value.b = objIdLenNull;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static void Check_ObjectBufferAttribute_ValueIsTheFullKeySize(ADBG_Case_t *c,
	uint32_t keySize)
{
	/* Check that the buffer size is $IN_KeySize$ bits. */
	/* NOTE: obj_data_attr.size is size in bytes! */
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, keySize, ==, obj_data_attr.size * 8);
}

static TEEC_Result Invoke_GetObjectInfo1(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	TEE_ObjectHandle *obh, uint32_t objInfo)
{
	TEEC_Result res = TEEC_SUCCESS;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	op.params[0].value.a = (uint32_t)*obh;
	op.params[0].value.b = objInfo;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INOUT,  TEEC_VALUE_OUTPUT,
		TEEC_VALUE_OUTPUT,  TEEC_VALUE_OUTPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if ( res == TEEC_SUCCESS) {
		saved_ds_obj_info.obj_type = op.params[0].value.b;
		saved_ds_obj_info.key_size = op.params[1].value.a;
		saved_ds_obj_info.max_key_size = op.params[1].value.b;
		saved_ds_obj_info.obj_usage = op.params[2].value.a;
		saved_ds_obj_info.data_size = op.params[2].value.b;
		saved_ds_obj_info.data_pos = op.params[3].value.a;
		saved_ds_obj_info.handle_flags = op.params[3].value.b;
	}

	return res;
}

static void Check_ObjectInfo(ADBG_Case_t *c,
	uint32_t cObjType, uint32_t cKeySize, uint32_t cMaxKeySize,
	uint32_t cObjUsage, uint32_t cDataSize, uint32_t cDataPos,
	uint32_t cHandleFlags, uint32_t cDataFlags)
{
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cObjType, ==, saved_ds_obj_info.obj_type);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cKeySize, ==, saved_ds_obj_info.key_size);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cMaxKeySize, ==, saved_ds_obj_info.max_key_size);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cObjUsage, ==, saved_ds_obj_info.obj_usage);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cDataSize, ==, saved_ds_obj_info.data_size);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, cDataPos, ==, saved_ds_obj_info.data_pos);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, (cHandleFlags | cDataFlags), ==, saved_ds_obj_info.handle_flags);
}

static TEEC_Result Invoke_GetObjectValueAttribute(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	TEE_ObjectHandle *obh, uint32_t attr,
	uint32_t extA, uint32_t extB)
{
	TEEC_Result res = TEEC_SUCCESS;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	op.params[0].value.a = (uint32_t)*obh;
	op.params[0].value.b = attr;
	op.params[1].value.a = extA;
	op.params[1].value.b = extB;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (res == TEEC_SUCCESS) {
		obj_val_attr.a = op.params[2].value.a;
		obj_val_attr.b = op.params[2].value.b;
	}

	return res;
}

static void Check_ObjectValueAttribute(ADBG_Case_t *c, uint32_t expA, uint32_t expB)
{
	if (expA != TEE_ATTR_VALUE_NONE)
		(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, expA, ==, obj_val_attr.a);
	if (expB != TEE_ATTR_VALUE_NONE)
		(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, expB, ==, obj_val_attr.b);
}

static TEEC_Result Invoke_InitValueAttribute(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t attr, uint32_t attrId, uint32_t inA, uint32_t inB)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	op.params[0].value.a = attr;
	op.params[0].value.b = attrId;
	op.params[1].value.a = inA;
	op.params[1].value.b = inB;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, cmdId, &op, &org);
}

static TEEC_Result Invoke_OpenPersistentObject(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t storageId, uint8_t *objectId, uint32_t dataFlags,
	TEE_ObjectHandle *obh)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(sess->ctx, SHARE_MEM01, strlen((const char *)objectId),
			       TEEC_MEM_INPUT, objectId, mem01_exit);

	op.params[0].value.a = (uint32_t)*obh;
	op.params[0].value.b = storageId;
	op.params[1].value.a = dataFlags;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM01, SHARE_MEM01->size);

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_PopulateTransientObject(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	TEE_ObjectHandle *obh, struct attr_list_node *attrList)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	struct attr_list_node *pAttr = attrList;
	uint32_t org;
	(void)c;

	op.params[0].value.a = (uint32_t)*obh;

	if(!is_attr_list_empty(pAttr)) {
		op.params[1].value.a = pAttr->attr_idx;
		pAttr = get_next_attribute(pAttr);
	} else {
		op.params[1].value.a = ATTR_NONE;
	}
	if(!is_attr_list_empty(pAttr)) {
		op.params[1].value.b = pAttr->attr_idx;
		pAttr = get_next_attribute(pAttr);
	} else {
		op.params[1].value.b = ATTR_NONE;
	}
	if(!is_attr_list_empty(pAttr)) {
		op.params[2].value.a = pAttr->attr_idx;
		pAttr = get_next_attribute(pAttr);
	} else {
		op.params[2].value.a = ATTR_NONE;
	}
	if(!is_attr_list_empty(pAttr)) {
		op.params[2].value.b = pAttr->attr_idx;
		pAttr = get_next_attribute(pAttr);
	} else {
		op.params[2].value.b = ATTR_NONE;
	}
	if(!is_attr_list_empty(pAttr)) {
		op.params[3].value.a = pAttr->attr_idx;
		pAttr = get_next_attribute(pAttr);
	} else {
		op.params[3].value.a = ATTR_NONE;
	}
	if(!is_attr_list_empty(pAttr)) {
		op.params[3].value.b = pAttr->attr_idx;
		pAttr = get_next_attribute(pAttr);
	} else {
		op.params[3].value.b = ATTR_NONE;
	}

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT);

	return TEEC_InvokeCommand(sess, cmdId, &op, &org);
}

static TEEC_Result Invoke_ReadObjectData(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	TEE_ObjectHandle *obh, uint32_t buffer, uint32_t bufferSize)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	ALLOCATE_SHARED_MEMORY(sess->ctx, SHARE_MEM01, bufferSize,
			       TEEC_MEM_OUTPUT, mem01_exit);

	op.params[0].value.a = (uint32_t)*obh;
	op.params[0].value.b = buffer;

	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size);

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE,
		TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (res == TEEC_SUCCESS) {
		/* Save data for later verification. */
		DS_CRYPTO_FREE(saved_read_data);
		DS_CRYPTO_MALLOC(saved_read_data, op.params[1].memref.size);
		memcpy((void *)saved_read_data.buffer, op.params[1].memref.parent->buffer,
				saved_read_data.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static void Check_ReadObjectData_AfterTruncate(ADBG_Case_t *c, uint8_t *data,
	uint32_t size_before, uint32_t size_after)
{
	/* Check that the size of the data read is $IN_SizeAfter$ bytes. */
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, size_after, ==, saved_read_data.size);
	if (size_after == saved_read_data.size) {
		if (size_after <size_before) {
			/* Check that the data read is equal to the first $IN_SizeAfter$
			 * bytes of $IN_Data$.
			 */
			(void)ADBG_EXPECT_EQUAL(c, data, saved_read_data.buffer, size_after);
		} else {
			/* Check that the data read is equal to $IN_Data$ extended by '00'
			 * bytes at the end.
			 */
			void *extended_in = calloc(1, size_after);
			memcpy(extended_in, (void *)data, size_before);
			(void)ADBG_EXPECT_EQUAL(c, data, extended_in, size_after);
			free(extended_in);
		}
	}
}

static void Check_ReadObjectData_AfterWrite(ADBG_Case_t *c, uint8_t *data,
	uint32_t size_written)
{
	uint32_t size_diff;
	uint8_t *data_after_diff;

	/* Check that the size of the data read is at least $IN_SizeWritten$ bytes. */
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, size_written, <=, saved_read_data.size);

	if(size_written <= saved_read_data.size) {
		size_diff = saved_read_data.size - size_written;
		data_after_diff = saved_read_data.buffer + size_diff;
		/* Check that the last $IN_SizeWritten$ bytes of the data read are equal to
		 * $IN_DataWritten$.
		 */
		(void)ADBG_EXPECT_EQUAL(c, data_after_diff, data, size_written);
		/* Check that the remaining bytes are filled with '00's. */
		data_after_diff = (uint8_t *)calloc(1, size_diff);
		(void)ADBG_EXPECT_EQUAL(c, saved_read_data.buffer, data_after_diff,
			size_diff);
		free(data_after_diff);
	}
}

static void Check_ReadObjectData_DataRead(ADBG_Case_t *c, uint8_t *data,
	uint32_t size_read)
{
	/* Check that the size of the data read is $IN_SizeRead$ bytes. */
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, size_read, ==, saved_read_data.size);

	/* Check that the data read is equal to the first $IN_SizeRead$
	 * bytes of $IN_Data$.
	 */
	if (size_read <= saved_read_data.size)
		(void)ADBG_EXPECT_EQUAL(c, saved_read_data.buffer, data, size_read);
}

static TEEC_Result Invoke_RenamePersistentObject(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	TEE_ObjectHandle *obh, uint8_t *objectId, uint32_t useParamBuff)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(sess->ctx, SHARE_MEM01, strlen((const char *)objectId),
			       TEEC_MEM_INPUT, objectId, mem01_exit);

	op.params[0].value.a = (uint32_t)*obh;
	op.params[1].value.a = useParamBuff;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM01, SHARE_MEM01->size);

	op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_SeekObjectData(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	TEE_ObjectHandle *obh, int32_t buffOfset, TEE_Whence seekMode)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	(void)c;

	op.params[0].value.a = (uint32_t)*obh;
	op.params[1].value.a = (uint32_t)ABS(buffOfset);
	op.params[1].value.b = (uint32_t)(buffOfset < 0 ? 1 : 0);
	op.params[2].value.a = (uint32_t)seekMode;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE);

	return TEEC_InvokeCommand(sess, cmdId, &op, &org);
}

static TEEC_Result Invoke_StartPersistentObjectEnumerator(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmd_id,
	uint32_t objEnum, uint32_t storageId)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t orig;
	(void)c;

	op.params[0].value.a = objEnum;
	op.params[0].value.b = storageId;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, cmd_id, &op, &orig);
}

static TEEC_Result Invoke_StoreBuffer(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmd_id,
	uint32_t tta_buffer_id, const uint8_t *data, uint32_t size)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(sess->ctx, SHARE_MEM01,
					size,
					TEEC_MEM_INPUT, data, store_attr_exit);

	op.params[0].value.a = tta_buffer_id;
	if (data) {
		op.params[1].value.a = size;
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
										 TEEC_NONE, TEEC_NONE);
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
						      SHARE_MEM01->size);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
										 TEEC_MEMREF_PARTIAL_INPUT,
										 TEEC_NONE, TEEC_NONE);
	}
	res = TEEC_InvokeCommand(sess, cmd_id, &op, &ret_orig);

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
store_attr_exit:
	return res;
}

static TEEC_Result Invoke_TruncateObjectData(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmd_id,
	TEE_ObjectHandle *obh, uint32_t buffSize)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	op.params[0].value.a = (uint32_t)*obh;
	op.params[1].value.a = buffSize;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, cmd_id, &op, &ret_orig);
}

static TEEC_Result Invoke_WriteObjectData(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmd_id,
	TEE_ObjectHandle *obh, uint32_t buffSize)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	(void)c;

	op.params[0].value.a = (uint32_t)*obh;
	op.params[0].value.b = buffSize;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, cmd_id, &op, &ret_orig);
}

#define Macro_GetDHAttributes(c, sess, objectH) \
	({ \
		TEEC_Result __ret = TEE_ERROR_OUT_OF_MEMORY; \
		BN_DH_INIT(macro_dh_exit, __ret); \
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_GetObjectBufferAttribute(c, sess, \
			CMD_DS_GetObjectBufferAttribute, objectH, TEE_ATTR_DH_PRIME, false, \
			BIG_ATTRIBUTE_BUFFER_SIZE)); \
		if (!BN_bin2bn(obj_data_attr.buffer, obj_data_attr.size, saved_dh_val.P)) \
			goto macro_dh_exit; \
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_GetObjectBufferAttribute(c, sess, \
			CMD_DS_GetObjectBufferAttribute, objectH, TEE_ATTR_DH_BASE, false, \
			BIG_ATTRIBUTE_BUFFER_SIZE)); \
		if (!BN_bin2bn(obj_data_attr.buffer, obj_data_attr.size, saved_dh_val.G)) \
			goto macro_dh_exit; \
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_GetObjectBufferAttribute(c, sess, \
			CMD_DS_GetObjectBufferAttribute, objectH, TEE_ATTR_DH_PUBLIC_VALUE, \
			false, BIG_ATTRIBUTE_BUFFER_SIZE)); \
		if (!BN_bin2bn(obj_data_attr.buffer, obj_data_attr.size, saved_dh_val.Y)) \
			goto macro_dh_exit; \
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_GetObjectBufferAttribute(c, sess, \
			CMD_DS_GetObjectBufferAttribute, objectH, TEE_ATTR_DH_PRIVATE_VALUE, \
			false, BIG_ATTRIBUTE_BUFFER_SIZE)); \
		if (!BN_bin2bn(obj_data_attr.buffer, obj_data_attr.size, saved_dh_val.X)) \
			goto macro_dh_exit; \
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_GetObjectValueAttribute(c, sess, \
			CMD_DS_GetObjectValueAttribute, objectH, TEE_ATTR_DH_X_BITS, true, false)); \
		saved_dh_val.L = obj_val_attr.a; \
	macro_dh_exit: \
		__ret; \
	})

static void Check_GeneratedDHAttributes(ADBG_Case_t *c)
{
	uint32_t bigL = saved_dh_val.L;
	unsigned char *l = (unsigned char *)&bigL;
	BN_CTX *ctx = NULL;
	BIGNUM *bnOne = NULL;
	BIGNUM *bnTwo = NULL;
	BIGNUM *bnRes = NULL;
	BIGNUM *bnL = NULL;

	/* Convert saved_dh_val.L to big endian */
	bigL = ((l[0] << 8 | l[1]) << 8 | l[2]) << 8 | l[3];

	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto check_dh_exit;
	bnOne = BN_new();
	bnTwo = BN_new();
	bnRes = BN_new();
	bnL = BN_new();

	if (!BN_dec2bn(&bnOne, "1"))
		goto check_dh_clear;

	if (!BN_dec2bn(&bnOne, "2"))
		goto check_dh_clear;

	if (!BN_bin2bn(l, sizeof(uint32_t), bnL))
		goto check_dh_clear;

	/* For all values except L, on output of Invoke_GetObjectBufferAttribute the
	 * buffer contains the integer in the bignum format, that is:
	 * "An unsigned bignum in big endian binary format. Leading zero bytes are
	 * allowed."
	 * That means that checking if the value is greater than zero is not needed.
	 */

	/* X < (P-1) */
	if (BN_sub(bnRes, saved_dh_val.P, bnOne))
		goto check_dh_clear;

	(void)ADBG_EXPECT_COMPARE_SIGNED(c, -1, ==, BN_cmp(saved_dh_val.X, bnRes));

	/* 2^(L-1) <= X < 2^L */
	if (BN_exp(bnRes, bnTwo, bnL, ctx))
		goto check_dh_clear;
	(void)ADBG_EXPECT_COMPARE_SIGNED(c, -1, ==, BN_cmp(saved_dh_val.X, bnRes));
	if (BN_sub(bnRes, bnL, bnOne))
		goto check_dh_clear;
	if (BN_exp(bnRes, bnTwo, bnRes, ctx))
		goto check_dh_clear;
	(void)ADBG_EXPECT_COMPARE_SIGNED(c, 1, >, BN_cmp(bnRes, saved_dh_val.X));

	/* Y = (G^X) mod P */
	if (BN_mod_exp(bnRes, saved_dh_val.G, saved_dh_val.X, saved_dh_val.P, ctx))
		goto check_dh_clear;
	(void)ADBG_EXPECT_COMPARE_SIGNED(c, 0, ==, BN_cmp(bnRes, saved_dh_val.Y));

	/* Y < P */
	(void)ADBG_EXPECT_COMPARE_SIGNED(c, -1, ==, BN_cmp(saved_dh_val.Y,
		saved_dh_val.P));

check_dh_clear:
	BN_free(bnOne);
	BN_free(bnTwo);
	BN_free(bnRes);
	BN_CTX_free(ctx);
check_dh_exit:
	return;
}

#define Macro_GetRSAAttributes(c, sess, objectH) \
	({ \
		TEEC_Result __ret = TEE_ERROR_OUT_OF_MEMORY; \
		BN_RSA_INIT(macro_rsa_exit, __ret); \
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_GetObjectBufferAttribute(c, sess, \
			CMD_DS_GetObjectBufferAttribute, objectH, TEE_ATTR_RSA_MODULUS, \
			false, BIG_ATTRIBUTE_BUFFER_SIZE)); \
		if (!BN_bin2bn(obj_data_attr.buffer, obj_data_attr.size, saved_rsa_val.mod)) \
			goto macro_rsa_exit; \
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_GetObjectBufferAttribute(c, sess, \
			CMD_DS_GetObjectBufferAttribute, objectH, TEE_ATTR_RSA_PUBLIC_EXPONENT, \
			false, BIG_ATTRIBUTE_BUFFER_SIZE)); \
		if (!BN_bin2bn(obj_data_attr.buffer, obj_data_attr.size, saved_rsa_val.pub_exp)) \
			goto macro_rsa_exit; \
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_GetObjectBufferAttribute(c, sess, \
			CMD_DS_GetObjectBufferAttribute, objectH, TEE_ATTR_RSA_PRIVATE_EXPONENT, \
			false, BIG_ATTRIBUTE_BUFFER_SIZE)); \
		if (!BN_bin2bn(obj_data_attr.buffer, obj_data_attr.size, saved_rsa_val.priv_exp)) \
			goto macro_rsa_exit; \
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_GetObjectBufferAttribute(c, sess, \
			CMD_DS_GetObjectBufferAttribute, objectH, TEE_ATTR_RSA_PRIME1, false, \
			BIG_ATTRIBUTE_BUFFER_SIZE)); \
		if (!BN_bin2bn(obj_data_attr.buffer, obj_data_attr.size, saved_rsa_val.prime1)) \
			goto macro_rsa_exit; \
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_GetObjectBufferAttribute(c, sess, \
			CMD_DS_GetObjectBufferAttribute, objectH, TEE_ATTR_RSA_PRIME2, false, \
			BIG_ATTRIBUTE_BUFFER_SIZE)); \
		if (!BN_bin2bn(obj_data_attr.buffer, obj_data_attr.size, saved_rsa_val.prime2)) \
			goto macro_rsa_exit; \
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_GetObjectBufferAttribute(c, sess, \
			CMD_DS_GetObjectBufferAttribute, objectH, TEE_ATTR_RSA_EXPONENT1, false, \
			BIG_ATTRIBUTE_BUFFER_SIZE)); \
		if (!BN_bin2bn(obj_data_attr.buffer, obj_data_attr.size, saved_rsa_val.exp1)) \
			goto macro_rsa_exit; \
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_GetObjectBufferAttribute(c, sess, \
			CMD_DS_GetObjectBufferAttribute, objectH, TEE_ATTR_RSA_EXPONENT2, false, \
			BIG_ATTRIBUTE_BUFFER_SIZE)); \
		if (!BN_bin2bn(obj_data_attr.buffer, obj_data_attr.size, saved_rsa_val.exp2)) \
			goto macro_rsa_exit; \
		ADBG_EXPECT(c, TEE_SUCCESS, Invoke_GetObjectBufferAttribute(c, sess, \
			CMD_DS_GetObjectBufferAttribute, objectH, TEE_ATTR_RSA_COEFFICIENT, \
			false, BIG_ATTRIBUTE_BUFFER_SIZE)); \
		BN_bin2bn(obj_data_attr.buffer, obj_data_attr.size, saved_rsa_val.coef); \
	macro_rsa_exit: \
		__ret; \
	})

static void Check_GeneratedRSAAttributes(ADBG_Case_t *c)
{
	(void)c;
	/**
	 * Check that all the attribute values extracted in the calls to
	 * Invoke_GetObjectBufferAttribute form a valid RSA key-pair.
	 * In order to do this, choose valid arbitrary data and check that it is
	 * successfully recovered after being encrypted using the public key and
	 * the result decrypted using the private key.
	 */
	return;
}

#endif /* XML_DATASTORAGE_API_H_ */
