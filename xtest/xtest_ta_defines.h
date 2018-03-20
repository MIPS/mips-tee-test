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

#ifndef XTEST_TA_DEFINES_H
#define XTEST_TA_DEFINES_H

/* ta_crypt */
#define TA_CRYPT_UUID { 0xcb3e5ba0, 0xadf1, 0x11e0, \
    { 0x99, 0x8b, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b } }

#define TA_CRYPT_CMD_SHA224                         1
#define TA_CRYPT_CMD_SHA256                         2
#define TA_CRYPT_CMD_AES256ECB_ENC                  3
#define TA_CRYPT_CMD_AES256ECB_DEC                  4
#define TA_CRYPT_CMD_ALLOCATE_OPERATION             5
#define TA_CRYPT_CMD_FREE_OPERATION                 6
#define TA_CRYPT_CMD_GET_OPERATION_INFO             7
#define TA_CRYPT_CMD_RESET_OPERATION                8
#define TA_CRYPT_CMD_SET_OPERATION_KEY              9
#define TA_CRYPT_CMD_SET_OPERATION_KEY2             10
#define TA_CRYPT_CMD_COPY_OPERATION                 11
#define TA_CRYPT_CMD_DIGEST_UPDATE                  12
#define TA_CRYPT_CMD_DIGEST_DO_FINAL                13
#define TA_CRYPT_CMD_CIPHER_INIT                    14
#define TA_CRYPT_CMD_CIPHER_UPDATE                  15
#define TA_CRYPT_CMD_CIPHER_DO_FINAL                16
#define TA_CRYPT_CMD_MAC_INIT                       17
#define TA_CRYPT_CMD_MAC_UPDATE                     18
#define TA_CRYPT_CMD_MAC_FINAL_COMPUTE              19
#define TA_CRYPT_CMD_MAC_FINAL_COMPARE              20
#define TA_CRYPT_CMD_ALLOCATE_TRANSIENT_OBJECT      21
#define TA_CRYPT_CMD_FREE_TRANSIENT_OBJECT          22
#define TA_CRYPT_CMD_RESET_TRANSIENT_OBJECT         23
#define TA_CRYPT_CMD_POPULATE_TRANSIENT_OBJECT      24
#define TA_CRYPT_CMD_COPY_OBJECT_ATTRIBUTES         25
#define TA_CRYPT_CMD_GENERATE_KEY                   26
#define TA_CRYPT_CMD_ASYMMETRIC_ENCRYPT             27
#define TA_CRYPT_CMD_ASYMMETRIC_DECRYPT             28
#define TA_CRYPT_CMD_ASYMMETRIC_SIGN_DIGEST         29
#define TA_CRYPT_CMD_ASYMMETRIC_VERIFY_DIGEST       30
#define TA_CRYPT_CMD_DERIVE_KEY                     31
#define TA_CRYPT_CMD_RANDOM_NUMBER_GENEREATE        32
#define TA_CRYPT_CMD_AE_INIT                        33
#define TA_CRYPT_CMD_AE_UPDATE_AAD                  34
#define TA_CRYPT_CMD_AE_UPDATE                      35
#define TA_CRYPT_CMD_AE_ENCRYPT_FINAL               36
#define TA_CRYPT_CMD_AE_DECRYPT_FINAL               37
#define TA_CRYPT_CMD_GET_OBJECT_BUFFER_ATTRIBUTE    38
#define TA_CRYPT_CMD_GET_OBJECT_VALUE_ATTRIBUTE     39
#define TA_CRYPT_CMD_SETGLOBAL                      40
#define TA_CRYPT_CMD_GETGLOBAL                      41

/* ta_os_test */
#define TA_OS_TEST_UUID { 0x5b9e0e40, 0x2636, 0x11e1, \
    { 0xad, 0x9e, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b } }

#define TA_OS_TEST_CMD_INIT                         0
#define TA_OS_TEST_CMD_CLIENT_WITH_TIMEOUT          1
#define TA_OS_TEST_CMD_BASIC                        5
#define TA_OS_TEST_CMD_PANIC                        6
#define TA_OS_TEST_CMD_CLIENT                       7
#define TA_OS_TEST_CMD_PARAMS_ACCESS                8
#define TA_OS_TEST_CMD_WAIT                         9
#define TA_OS_TEST_CMD_BAD_MEM_ACCESS               10
#define TA_OS_TEST_MFW_CMD_BASE                     11
#define TA_OS_TEST_MFW_CMD_LAST                     16

/* ta_multi_instance_memref */
#define TA_MULTI_INSTANCE_MEMREF_UUID { 0x634c11cf, 0x1bf6, 0x4938, \
    { 0xb5, 0x17, 0x79, 0xa7, 0x5a, 0xb4, 0x3c, 0xf8 } }

#define TA_MULTI_INSTANCE_MEMREF_CMD                11
#define TA_MULTI_INSTANCE_INVOKE_CMD                12
#define TA_MULTI_INSTANCE_WAIT_CMD                  13

/* ta_bad_manifest_test */
#define TA_BAD_MANIFEST_UUID    { 0xfce38bf2, 0xecbd, 0x4ebd, \
                    { 0x99, 0xd8, 0x6f, 0xfe, 0x8e, 0x7c, 0xd9, 0x25 } }

/* ta_create_fail_test */
#define TA_CREATE_FAIL_TEST_UUID { 0xc3f6e2c0, 0x3548, 0x11e1, \
    { 0xb8, 0x6c, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66 } }


/* ta_storage_benchmark */
#define TA_STORAGE_BENCHMARK_UUID { 0xf157cda0, 0x550c, 0x11e5,\
    { 0xa6, 0xfa, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b } }

enum storage_benchmark_cmd {
    TA_STORAGE_BENCHMARK_CMD_TEST_READ,
    TA_STORAGE_BENCHMARK_CMD_TEST_WRITE,
    TA_STORAGE_BENCHMARK_CMD_TEST_REWRITE,
};

/* ta_client */
#define TA_CLIENT_TA_UUID { 0xc67430d3, 0x9b8c, 0x4df1, \
    { 0x9d, 0xf0, 0x3c, 0x0a, 0xa0, 0xd1, 0xe8, 0xa9 } }

#define TA_CLIENT_CMD_OPENSESSION   0
#define TA_CLIENT_CMD_PANIC         1
#define TA_CLIENT_CMD_CLOSESESSION  2
#define TA_CLIENT_CMD_TEST_MALLOC_ALIGNEMENT    3
#define TA_CLIENT_CMD_TEST_MALLOC_SIZE_ZERO     4
#define TA_CLIENT_CMD_TEST_REALLOC_CONTENT      5
#define TA_CLIENT_CMD_TEST_REALLOC_ILLEGAL_PTR  6
#define TA_CLIENT_CMD_TEST_REALLOC_SIZE_ZERO    7
#define TA_CLIENT_CMD_DEFAULT_PANIC             8
#define TA_CLIENT_CMD_SUCCESS                   9

/* ta_siss */
#define TA_SISS_TA_UUID { 0x24922593, 0xa36f, 0x465f, \
    { 0x81, 0x6c, 0xe8, 0xa2, 0x97, 0xbd, 0x8e, 0xe8 } }

#define TA_SISS_CMD_SUCCESS                     0
#define TA_SISS_CMD_PANIC                       1
#define TA_SISS_CMD_RETURN_TH_ID                2
#define TA_SISS_CMD_FAILURE                     3
#define TA_SISS_CMD_WAIT                        4

/* ta_rpc_test */
#define TA_RPC_TEST_UUID { 0xd17f73a0, 0x36ef, 0x11e1,          \
    { 0x98, 0x4a, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b } }

#define TA_RPC_CMD_CRYPT_SHA224                     1
#define TA_RPC_CMD_CRYPT_SHA256                     2
#define TA_RPC_CMD_CRYPT_AES256ECB_ENC              3
#define TA_RPC_CMD_CRYPT_AES256ECB_DEC              4
#define TA_RPC_CMD_OPEN                             5

/* ta_sims */
#define TA_SIMS_TEST_UUID { 0xe6a33ed4, 0x562b, 0x463a, \
    { 0xbb, 0x7e, 0xff, 0x5e, 0x15, 0xa4, 0x93, 0xc8 } }

#define TA_SIMS_CMD_SUCCESS                         0
#define TA_SIMS_CMD_READ                            1
#define TA_SIMS_CMD_WRITE                           2
#define TA_SIMS_CMD_GET_COUNTER                     3
#define TA_SIMS_CMD_GET_MEMREF_UINT                 4
#define TA_SIMS_CMD_CHECK_BUFFER                    5
#define TA_SIMS_CMD_FAILURE                         6
#define TA_SIMS_CMD_WAIT                            7
#define TA_SIMS_CMD_PANIC                           8

/* ta_storage */
#define TA_STORAGE_UUID { 0xb689f2a7, 0x8adf, 0x477a, \
    { 0x9f, 0x99, 0x32, 0xe9, 0x0c, 0x0a, 0xd0, 0xa2 } }
#define TA_STORAGE2_UUID { 0x731e279e, 0xaafb, 0x4575, \
    { 0xa7, 0x71, 0x38, 0xca, 0xa6, 0xf0, 0xcc, 0xa6 } }

#define TA_STORAGE_CMD_OPEN                         0
#define TA_STORAGE_CMD_CLOSE                        1
#define TA_STORAGE_CMD_READ                         2
#define TA_STORAGE_CMD_WRITE                        3
#define TA_STORAGE_CMD_CREATE                       4
#define TA_STORAGE_CMD_SEEK                         5
#define TA_STORAGE_CMD_UNLINK                       6
#define TA_STORAGE_CMD_RENAME                       7
#define TA_STORAGE_CMD_TRUNC                        8
#define TA_STORAGE_CMD_ALLOC_ENUM                   9
#define TA_STORAGE_CMD_FREE_ENUM                    10
#define TA_STORAGE_CMD_RESET_ENUM                   11
#define TA_STORAGE_CMD_START_ENUM                   12
#define TA_STORAGE_CMD_NEXT_ENUM                    13
#define TA_STORAGE_CMD_CREATE_OVERWRITE             14
#define TA_STORAGE_CMD_KEY_IN_PERSISTENT            15
#define TA_STORAGE_CMD_LOOP                         16
#define TA_STORAGE_CMD_RESTRICT_USAGE               17
#define TA_STORAGE_CMD_ALLOC_OBJ                    18
#define TA_STORAGE_CMD_FREE_OBJ                     19
#define TA_STORAGE_CMD_RESET_OBJ                    20

/* enc_fs */
#define ENC_FS_KEY_MANAGER_TEST_UUID \
        { 0x17E5E280, 0xD12E, 0x11E4,  \
            { 0xA4, 0x1A, 0x00, 0x02, 0xA5, 0xD5, 0xC5, 0x1B } }

#define CMD_SELF_TESTS                              0

/* concurrent */
#define TA_CONCURRENT_UUID { 0xe13010e0, 0x2ae1, 0x11e5, \
    { 0x89, 0x6a, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b } }

#define TA_CONCURRENT_CMD_BUSY_LOOP                 0
#define TA_CONCURRENT_CMD_SHA256                    1

/* concurrent large */
#define TA_CONCURRENT_LARGE_UUID { 0x5ce0c432, 0x0ab0, 0x40e5, \
    { 0xa0, 0x56, 0x78, 0x2c, 0xa0, 0xe6, 0xab, 0xa2 } }

/* Internal Core TA */
#define TA_CORE_TEST_UUID { 0x5387ad61, 0xff1c, 0x43a0, \
    { 0xa7, 0xad, 0xd8, 0x5c, 0xda, 0x69, 0x9f, 0x51 } }

#define TA_CORE_TEST_CMD_SUCCESS                    0
#define TA_CORE_TEST_CMD_SESSION_LEAK               1
#define TA_CORE_TEST_CMD_WAIT_TIMEOUT               2
#define TA_CORE_TEST_CMD_SHARE_BUFFER_AND_PANIC     3
#define TA_CORE_TEST_CMD_CHECK_BUFFER_MAPPING       4
#define TA_CORE_TEST_CMD_OPEN_SIMS_SESSION          5
#define TA_CORE_TEST_CMD_SHARE_BUFFER               6
#define TA_CORE_TEST_CMD_INVOKE_TIMEOUT             7
#define TA_CORE_TEST_CMD_WAIT                       8
#define TA_CORE_TEST_CMD_INVOKE_OPENSESSION_TIMEOUT 9

/* TTA_DS */
#define TA_TTA_DS_UUID { 0x534D4152, 0x5443, 0x534C, \
    { 0x54, 0x44, 0x41, 0x54, 0x41, 0x53, 0x54, 0x31 } }

/* TTA Client API */
#define COMMAND_TTA_Remember_Expected_ParamTypes      0x00000002
#define COMMAND_TTA_Copy_ParamIn_to_ParamOut          0x00000001
#define COMMAND_TTA_Check_ParamTypes                  0x00000003
#define COMMAND_TTA_To_Be_Cancelled                   0x00000004
#define COMMAND_TTA_Success                           0x00000005
#define COMMAND_TTA_Panic                             0x00000006

/* TTA Testing Client API Parameters */
#define COMMAND_TTA_Check_Update_Params         0xFFFF0002u
#define COMMAND_TTA_Store_Expected_Param_Info   0xFFFF0001u

/* TTA_TCF */
#define CMD_TEE_GetPropertyAsString_withoutEnum             0x00000010
#define CMD_TEE_GetPropertyAsBool_withoutEnum               0x00000015
#define CMD_TEE_GetPropertyAsInt_withoutEnum                0x00000020
#define CMD_TEE_GetPropertyAsBinaryBlock_withoutEnum        0x00000025
#define CMD_TEE_GetPropertyAsUUID_withoutEnum               0x00000030
#define CMD_TEE_GetPropertyAsIdentity_withoutEnum           0x00000035
#define CMD_TEE_GetPropertyAsXXXX_fromEnum                  0x00000045
#define CMD_TEE_AllocatePropertyEnumerator                  0x00000060
#define CMD_TEE_StartPropertyEnumerator                     0x00000065
#define CMD_TEE_ResetPropertyEnumerator                     0x00000070
#define CMD_TEE_FreePropertyEnumerator                      0x00000075
#define CMD_TEE_GetPropertyName                             0x00000080
#define CMD_TEE_Malloc                                      0x00000100
#define CMD_TEE_Realloc                                     0x00000110
#define CMD_TEE_MemMove                                     0x00000120
#define CMD_TEE_MemCompare                                  0x00000130
#define CMD_TEE_MemFill                                     0x00000140
#define CMD_TEE_Panic                                       0x00000104
#define CMD_TEE_CheckMemoryAccessRight                      0x00000103
#define CMD_TEE_GetCancellationFlag_RequestedCancel         0x00000105
#define CMD_TEE_MaskUnmaskCancellations                     0x00000106
#define CMD_TEE_Free                                        0x00000107
#define CMD_ProcessInvokeTAOpenSession                      0x00000200
#define CMD_ProcessTAInvokeTA_simple                        0x00000201
#define CMD_ProcessTAInvokeTA_PayloadValue                  0x00000202
#define CMD_TEE_GetNextPropertyEnumerator_notStarted        0x00000203
#define CMD_ProcessTAInvokeTA_PayloadMemref                 0x00000204
#define CMD_ProcessTAInvokeTA_PayloadValue_In_Out           0x00000205
#define CMD_TEE_OpenTASession                               0x00000300
#define CMD_TEE_InvokeTACommand                             0x00000301
#define CMD_TEE_CloseTASession                              0x00000302

/* TTA_TCF_ICA */
#define CMD_SET_PANIC_ON_DESTROY                            0x00000001
#define CMD_SUCCESS                                         0x00000001

/* TTA_Time */
#define CMD_TEE_GetSystemTime                                        0x00000010
#define CMD_TEE_Wait                                                 0x00000011
#define CMD_TEE_SetTAPersistentTime_and_GetTAPersistentTime          0x00000012
#define CMD_TEE_GetREETime                                           0x00000013
#define CMD_TEE_SetTAPersistentTime_and_GetTAPersistentTimeOverflow  0x00000014
#define CMD_TEE_GetTAPersistentTimeNotSetAndSetTAPersistentTime      0x00000015

/* TTA_Arithmetic */
#define CMD_Arithm_BigIntComputeFMM             0x00000041
#define CMD_Arithm_BigIntConvertFromFMM         0x00000042
#define CMD_Arithm_BigIntConvertFromOctetString 0x00000046
#define CMD_Arithm_BigIntConvertFromS32         0x00000048
#define CMD_Arithm_BigIntConvertToFMM           0x00000043
#define CMD_Arithm_BigIntConvertToOctetString   0x00000040
#define CMD_Arithm_BigIntConvertToS32           0x00000047
#define CMD_Arithm_BigIntInitFMMContext         0x00000044
#define CMD_Arithm_TTA_New_BigInt               0x00000039
#define CMD_Arithm_TTA_New_BigIntFMM            0x00000045
#define CMD_Arithm_TTA_Store_Value_S32          0x00000038

#define CMD_Crypto_AEDecryptFinal                   0x0001001B
#define CMD_Crypto_AEEncryptFinal                   0x0001001A
#define CMD_Crypto_AEInit                           0x00010017
#define CMD_Crypto_AEUpdate                         0x00010018
#define CMD_Crypto_AEUpdateAAD                      0x00010019
#define CMD_Crypto_Abuse_TEE_DigestDoFinal_1        0x1FF06A0A
#define CMD_Crypto_Abuse_TEE_DigestDoFinal_2        0x1FF06A0B
#define CMD_Crypto_Abuse_TEE_DigestUpdate_1         0x1FF06A09
#define CMD_Crypto_Abuse_TEE_MACCompareFinal_1      0x1FF06A08
#define CMD_Crypto_Abuse_TEE_MACComputeFinal_1      0x1FF06A06
#define CMD_Crypto_Abuse_TEE_MACComputeFinal_2      0x1FF06A07
#define CMD_Crypto_Abuse_TEE_MACInit_1              0x1FF06A01
#define CMD_Crypto_Abuse_TEE_MACInit_2              0x1FF06A02
#define CMD_Crypto_Abuse_TEE_MACInit_3              0x1FF06A03
#define CMD_Crypto_Abuse_TEE_MACUpdate_1            0x1FF06A04
#define CMD_Crypto_Abuse_TEE_MACUpdate_2            0x1FF06A05
#define CMD_Crypto_AllocateOperation                0x00010003
#define CMD_Crypto_AsymmetricDecrypt                0x00010014
#define CMD_Crypto_AsymmetricEncrypt                0x00010013
#define CMD_Crypto_AsymmetricSignDigest             0x00010015
#define CMD_Crypto_AsymmetricVerifyDigest           0x00010016
#define CMD_Crypto_CipherDoFinal                    0x0001000E
#define CMD_Crypto_CipherInit                       0x0001000C
#define CMD_Crypto_CipherUpdate                     0x0001000D
#define CMD_Crypto_CopyOperation                    0x00010008
#define CMD_Crypto_DeriveKey                        0x0001001D
#define CMD_Crypto_DigestDoFinal                    0x0001000B
#define CMD_Crypto_DigestUpdate                     0x0001000A
#define CMD_Crypto_FreeAllKeysAndOperations         0x00010002
#define CMD_Crypto_GenerateRandom                   0x0001001E
#define CMD_Crypto_GetOperationInfo                 0x00010009
#define CMD_Crypto_GetOperationInfoMultiple         0x0001001F
#define CMD_Crypto_InitObjectWithKeys               0x00010001
#define CMD_Crypto_InitObjectWithKeysExt            0x00010021
#define CMD_Crypto_MACCompareFinal                  0x00010012
#define CMD_Crypto_MACComputeFinal                  0x00010011
#define CMD_Crypto_MACInit                          0x0001000F
#define CMD_Crypto_MACUpdate                        0x00010010
#define CMD_Crypto_ResetOperation                   0x00010005
#define CMD_Crypto_Security_DeriveKey               0x1FF06000
#define CMD_Crypto_SetOperationKey                  0x00010006
#define CMD_Crypto_SetOperationKey2                 0x00010007
#define CMD_Crypto_TTAEnsureIntermediateBufferSize  0x00010020
#define CMD_DS_AllocatePersistentObjectEnumerator           0x10000015
#define CMD_DS_AllocateTransientObject                      0x10000001
#define CMD_DS_Check_ObjectInfo                             0x100000C2
/* CloseAndDeletePersistentObject is depracted.
 * Use new version for tests.
 */
// CMD_DS_CloseAndDeletePersistentObject               0x1000102B
#define CMD_DS_CloseAndDeletePersistentObject               CMD_DS_CloseAndDeletePersistentObject1
#define CMD_DS_CloseAndDeletePersistentObject1              0x1000102C
#define CMD_DS_CloseObject                                  0x10000011
/* CopyObjectAttributes is depracted.
 * Use new version for tests.
 */
// #define CMD_DS_CopyObjectAttributes                         0x10000022
#define CMD_DS_CopyObjectAttributes                         CMD_DS_CopyObjectAttributes1
#define CMD_DS_CopyObjectAttributes1                        0x10000009
#define CMD_DS_CreatePersistentObject                       0x10000010
#define CMD_DS_FreePersistentObjectEnumerator               0x10000016
#define CMD_DS_FreeTransientObject                          0x10000004
#define CMD_DS_GenerateKey                                  0x1000100B
#define CMD_DS_GetNextPersistentObject                      0x10000019
#define CMD_DS_GetObjectBufferAttribute                     0x10000008
/* GetObjectInfo is depracted.
 * Use new version for tests.
 */
// #define CMD_DS_GetObjectInfo                                0x10000023
#define CMD_DS_GetObjectInfo                                CMD_DS_GetObjectInfo1
#define CMD_DS_GetObjectInfo1                               0x10000002
#define CMD_DS_GetObjectValueAttribute                      0x10000012
#define CMD_DS_InitRefAttribute                             0x10000006
#define CMD_DS_InitValueAttribute                           0x1000101F
#define CMD_DS_OpenPersistentObject                         0x10000013
#define CMD_DS_PopulateTransientObject                      0x10000007
#define CMD_DS_PopulateTransientObject_BadAttrBuffer        0x10000027
#define CMD_DS_ReadObjectData                               0x10001028
#define CMD_DS_RenamePersistentObject                       0x10000014
#define CMD_DS_ResetPersistentObjectEnumerator              0x10000017
#define CMD_DS_ResetTransientObject                         0x10000005
/* RestrictObjectUsag is depracted.
 * Use new version for tests.
 */
// #define CMD_DS_RestrictObjectUsage                          0x10000021
#define CMD_DS_RestrictObjectUsage                          CMD_DS_RestrictObjectUsage1
#define CMD_DS_RestrictObjectUsage1                         0x10000003
#define CMD_DS_Retrieve_ObjectInfo                          0x10000020
#define CMD_DS_Security_CreatePersistentObject              0x1FF05003
#define CMD_DS_Security_Memory_AllocateFreeTransientObject  0x00000A04
#define CMD_DS_Security_Memory_AllocateStartFreePersistentObjectEnum     0x00000A05
#define CMD_DS_Security_MutateAttributeID                   0x1FF05001
#define CMD_DS_Security_OpenPersistentObject                0x1FF05002
#define CMD_DS_Security_RenamePersistentObject              0x1FF05004
#define CMD_DS_SeekObjectData                               0x10000024
#define CMD_DS_StartPersistentObjectEnumerator              0x10000018
#define CMD_DS_StoreBuffer                                  0x1F0000CB
#define CMD_DS_TruncateObjectData                           0x10000026
#define CMD_DS_WriteObjectData                              0x10000025

#define CMD_TEE_BigIntAdd                       0x00000010
#define CMD_TEE_BigIntAddMod                    0x00000011
#define CMD_TEE_BigIntCmp                       0x00000012
#define CMD_TEE_BigIntCmpS32                    0x00000013
#define CMD_TEE_BigIntComputeExtendedGcd        0x00000014
#define CMD_TEE_BigIntDiv                       0x00000018
#define CMD_TEE_BigIntGetBit                    0x00000020
#define CMD_TEE_BigIntGetBitCount               0x00000021
#define CMD_TEE_BigIntInvMod                    0x00000023
#define CMD_TEE_BigIntIsProbablePrime           0x00000024
#define CMD_TEE_BigIntMod                       0x00000025
#define CMD_TEE_BigIntMul                       0x00000026
#define CMD_TEE_BigIntMulMod                    0x00000027
#define CMD_TEE_BigIntNeg                       0x00000028
#define CMD_TEE_BigIntRelativePrime             0x00000029
#define CMD_TEE_BigIntShiftRight                0x00000030
#define CMD_TEE_BigIntSquare                    0x00000031
#define CMD_TEE_BigIntSquareMod                 0x00000032
#define CMD_TEE_BigIntSub                       0x00000033
#define CMD_TEE_BigIntSubMod                    0x00000034

#endif
