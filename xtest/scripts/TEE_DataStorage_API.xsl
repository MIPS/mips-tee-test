<?xml version="1.0" encoding="UTF-8"?>

<!--  Copyright (c) 2017-2018, MIPS Tech, LLC and/or its affiliated group -->
<!--  companies (“MIPS”). -->
<!--  Copyright (c) 2014, STMicroelectronics International N.V. -->
<!--  All rights reserved. -->
<!--  -->
<!--  Redistribution and use in source and binary forms, with or without -->
<!--  modification, are permitted provided that the following conditions are met: -->
<!--  -->
<!--  1. Redistributions of source code must retain the above copyright notice, -->
<!--  this list of conditions and the following disclaimer. -->
<!--  -->
<!--  2. Redistributions in binary form must reproduce the above copyright notice, -->
<!--  this list of conditions and the following disclaimer in the documentation -->
<!--  and/or other materials provided with the distribution. -->
<!--  -->
<!--  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" -->
<!--  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE -->
<!--  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE -->
<!--  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE -->
<!--  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR -->
<!--  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF -->
<!--  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS -->
<!--  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN -->
<!--  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) -->
<!--  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE -->
<!--  POSSIBILITY OF SUCH DAMAGE. -->

<xsl:stylesheet version="1.0"
xmlns:fn="http://www.w3.org/2005/xpath-functions" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output method="text"/>
<xsl:strip-space elements="*"/>
<xsl:param name="target"/>

<xsl:template match="package">
<xsl:text>
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
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */


#include &lt;stdio.h&gt;
#include &lt;string.h&gt;
#include &lt;stdlib.h&gt;
#include &lt;sys/types.h&gt;
#include &lt;unistd.h&gt;
#include "xtest_ta_defines.h"
#include &lt;tee_api_types.h&gt;
#include "xtest_test.h"
#include "xtest_helpers.h"
#include "xml_ds_crypto_common_api.h"
#include "xml_datastorage_api.h"
#include "xml_crypto_attributes.h"

static bool xtest_init = false;

static void xtest_tee_deinit(void);
static bool xtest_tee_init(ADBG_Case_t *c)
{
    if (xtest_init) {
        return true;
    }

    ds_crypto_common_init();
    ds_init();

    SHARE_MEM01 = malloc(sizeof(TEEC_SharedMemory));
    if (!ADBG_EXPECT_NOT_NULL(c, SHARE_MEM01)) {
        goto exit;
    }
    SHARE_MEM02 = malloc(sizeof(TEEC_SharedMemory));
    if (!ADBG_EXPECT_NOT_NULL(c, SHARE_MEM02)) {
        goto exit;
    }
    SHARE_MEM03 = malloc(sizeof(TEEC_SharedMemory));
    if (!ADBG_EXPECT_NOT_NULL(c, SHARE_MEM03)) {
        goto exit;
    }
    SHARE_MEM04 = malloc(sizeof(TEEC_SharedMemory));
    if (!ADBG_EXPECT_NOT_NULL(c, SHARE_MEM04)) {
        goto exit;
    }
    SESSION01 = malloc(sizeof(TEEC_Session));
    if (!ADBG_EXPECT_NOT_NULL(c, SESSION01)) {
        goto exit;
    }
    SESSION02 = malloc(sizeof(TEEC_Session));
    if (!ADBG_EXPECT_NOT_NULL(c, SESSION02)) {
        goto exit;
    }
    CONTEXT01 = malloc(sizeof(TEEC_Context));
    if (!ADBG_EXPECT_NOT_NULL(c, CONTEXT01)) {
        goto exit;
    }
    CONTEXT02 = malloc(sizeof(TEEC_Context));
    if (!ADBG_EXPECT_NOT_NULL(c, CONTEXT02)) {
        goto exit;
    }
    OPERATION01 = malloc(sizeof(TEEC_Operation));
    if (!ADBG_EXPECT_NOT_NULL(c, OPERATION01)) {
        goto exit;
    }
    OPERATION02 = malloc(sizeof(TEEC_Operation));
    if (!ADBG_EXPECT_NOT_NULL(c, OPERATION02)) {
        goto exit;
    }
    OBJECT_HANDLE_NULL = malloc(sizeof(TEE_ObjectHandle));
    if (!ADBG_EXPECT_NOT_NULL(c, OBJECT_HANDLE_NULL)) {
        goto exit;
    }
    *OBJECT_HANDLE_NULL = (TEE_ObjectHandle)0;
    OBJECT_HANDLE_01 = malloc(sizeof(TEE_ObjectHandle));
    if (!ADBG_EXPECT_NOT_NULL(c, OBJECT_HANDLE_01)) {
        goto exit;
    }
    *OBJECT_HANDLE_01 = (TEE_ObjectHandle)1;
    OBJECT_HANDLE_02 = malloc(sizeof(TEE_ObjectHandle));
    if (!ADBG_EXPECT_NOT_NULL(c, OBJECT_HANDLE_02)) {
        goto exit;
    }
    *OBJECT_HANDLE_02 = (TEE_ObjectHandle)2;
    OBJECT_HANDLE_03 = malloc(sizeof(TEE_ObjectHandle));
    if (!ADBG_EXPECT_NOT_NULL(c, OBJECT_HANDLE_03)) {
        goto exit;
    }
    *OBJECT_HANDLE_03 = (TEE_ObjectHandle)3;
    OBJECT_HANDLE_INVALID = malloc(sizeof(TEE_ObjectHandle));
    if (!ADBG_EXPECT_NOT_NULL(c, OBJECT_HANDLE_INVALID)) {
        goto exit;
    }
    *OBJECT_HANDLE_INVALID = (TEE_ObjectHandle)4;

    iObjectDataFlags1 = 0;
    iObjectDataFlags2 = 0;
    iObjectDataFlags3 = 0;

    xtest_init = true;

    return xtest_init;

exit:
    xtest_tee_deinit();

    return xtest_init;
}

static void xtest_tee_deinit(void)
{
    ds_crypto_common_reset();
    ds_reset();

    if (SHARE_MEM01) {
      free(SHARE_MEM01);
      SHARE_MEM01 = NULL;
    }
    if (SHARE_MEM02) {
      free(SHARE_MEM02);
      SHARE_MEM02 = NULL;
    }
    if (SHARE_MEM03) {
      free(SHARE_MEM03);
      SHARE_MEM03 = NULL;
    }
    if (SHARE_MEM04) {
      free(SHARE_MEM04);
      SHARE_MEM04 = NULL;
    }
    if (SESSION01) {
      free(SESSION01);
      SESSION01 = NULL;
    }
    if (SESSION02) {
      free(SESSION02);
      SESSION02 = NULL;
    }
    if (CONTEXT01) {
      free(CONTEXT01);
      CONTEXT01 = NULL;
    }
    if (CONTEXT02) {
      free(CONTEXT02);
      CONTEXT02 = NULL;
    }
    if (OPERATION01) {
      free(OPERATION01);
      OPERATION01 = NULL;
    }
    if (OPERATION02) {
      free(OPERATION02);
      OPERATION02 = NULL;
    }
    if (OBJECT_HANDLE_NULL) {
        free(OBJECT_HANDLE_NULL);
        OBJECT_HANDLE_NULL = NULL;
    }
    if (OBJECT_HANDLE_01) {
        free(OBJECT_HANDLE_01);
        OBJECT_HANDLE_01 = NULL;
    }
    if (OBJECT_HANDLE_02) {
        free(OBJECT_HANDLE_02);
        OBJECT_HANDLE_02 = NULL;
    }
    if (OBJECT_HANDLE_03) {
        free(OBJECT_HANDLE_03);
        OBJECT_HANDLE_03 = NULL;
    }
    if (OBJECT_HANDLE_INVALID) {
        free(OBJECT_HANDLE_INVALID);
        OBJECT_HANDLE_INVALID = NULL;
    }

    xtest_init = false;
}
</xsl:text>

<xsl:for-each select="initial-state/scenario">
/*<xsl:value-of select="substring(substring-after(./@name, '('), 0, 9)" />*/
static void xtest_tee_<xsl:value-of select="position()+75000" />(ADBG_Case_t *c)
{
<xsl:text>    if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
        return;
</xsl:text>
<xsl:for-each select="./preamble/call/operation">
    <xsl:apply-templates select="."></xsl:apply-templates>
</xsl:for-each>
<xsl:for-each select="./body/call/operation">
    <xsl:apply-templates select="."></xsl:apply-templates>
</xsl:for-each>
<xsl:for-each select="./verification/call/operation">
    <xsl:apply-templates select="."></xsl:apply-templates>
</xsl:for-each>
<xsl:for-each select="./postamble/call/operation">
    <xsl:apply-templates select="."></xsl:apply-templates>
</xsl:for-each>
<xsl:text>    xtest_tee_deinit();
}
</xsl:text>
</xsl:for-each>

<xsl:for-each select="initial-state/scenario">
<xsl:variable name="position" select="position()+75000" />
ADBG_CASE_DEFINE(XTEST_TEE_<xsl:value-of select="$position" />, xtest_tee_<xsl:value-of select="$position" /><xsl:text>,
                 /* Title */
                 "</xsl:text><xsl:value-of select="substring(substring-after(./@name, '('), 0, 9)" /><xsl:text>",
                 /* Short description */
                 "</xsl:text><xsl:value-of select="substring-before(./@name, ' ')" /><xsl:text>",
                 /* Requirement IDs */
                 "</xsl:text><xsl:value-of select="./req[last()]/@name" /><xsl:text>",
                 /* How to implement */
                 "Description of how to implement ...");</xsl:text>
</xsl:for-each>
</xsl:template>

<xsl:template match="operation">
<xsl:choose>
<!--Call an operation with ADBG_EXPECT() macro.-->
<xsl:when test="(contains(./argument[last()]/parameter/@name, 'xpected') and not(contains(./@name, 'OpenSession')) and not(contains(./@name, 'InitializeContext')))">    ADBG_EXPECT(c, <xsl:for-each select="./argument"><xsl:if test="position()=last()"><xsl:apply-templates select="value"></xsl:apply-templates></xsl:if></xsl:for-each>, <xsl:apply-templates select="./@name"></xsl:apply-templates><xsl:for-each select="./argument/value"><xsl:if test="position()>1 and not(position()=last())">, </xsl:if><xsl:if test="not(position()=last())"><xsl:apply-templates select="."></xsl:apply-templates></xsl:if></xsl:for-each>));
<xsl:for-each select="../observations"><xsl:apply-templates select="." /></xsl:for-each>
</xsl:when>
<xsl:otherwise>
<xsl:text>    </xsl:text><xsl:apply-templates select="./@name"></xsl:apply-templates><xsl:for-each select="./argument"><xsl:if test="position()>1">, </xsl:if>
            <xsl:apply-templates select="./value"></xsl:apply-templates>
</xsl:for-each>);
</xsl:otherwise>
</xsl:choose>

</xsl:template>

<xsl:template match="value">
<xsl:choose>
<xsl:when test="(contains(./@name, 'UUID'))"><xsl:text>&amp;</xsl:text><xsl:value-of select="./@name" />
</xsl:when>
<!-- <xsl:when test="(contains(./@name, 'CMD_DS'))"><xsl:text>CMD</xsl:text><xsl:value-of select="substring(./@name, string-length('CMD_DS')+1)" /> -->
<!-- </xsl:when> -->
<xsl:when test="(contains(../type/@name, 'ALL_ATTRIBUTE_VALUES'))"><xsl:value-of select="./@name" /><xsl:if test="(contains(../../@name, 'Macro_StoreRefAttribute') or contains(../../@name, 'Invoke_StoreAttributeBuffer'))"><xsl:text>, sizeof(</xsl:text><xsl:value-of select="./@name" /><xsl:text>)</xsl:text></xsl:if>
</xsl:when>
<xsl:when test="(../type/@name='ALL_TEE_NAMES' and ./@name='NULL')"><xsl:text>_device</xsl:text>
</xsl:when>
<xsl:when test="(../type/@name='ALL_TTA_STORED_ATTRIBUTES' and ./@name='NULL')"><xsl:text>ATTR_NONE</xsl:text>
</xsl:when>
<xsl:when test="(../type/@name='ALL_TTA_STORED_OBJECT_ENUMERATORS' and ./@name='NULL')"><xsl:text>BUFF_NULL</xsl:text>
</xsl:when>
<xsl:when test="(../type/@name='ALL_TEE_OBJECT_HANDLES' and ./@name='NULL')"><xsl:text>OBJECT_HANDLE_NULL</xsl:text>
</xsl:when>
<xsl:otherwise>
<!--xsl:text>&amp;</xsl:text--><xsl:value-of select="./@name" />
</xsl:otherwise>
</xsl:choose>
</xsl:template>

<xsl:template match="parameter">
        <xsl:value-of select="./@name" />
</xsl:template>

<xsl:template match="@name">
<xsl:choose>
<xsl:when test=".='InitializeContext'"><xsl:text>XML_</xsl:text><xsl:value-of select="." /><xsl:text>(c, </xsl:text>
</xsl:when>
<xsl:when test=".='OpenSession'"><xsl:text>XML_</xsl:text><xsl:value-of select="." /><xsl:text>(c, </xsl:text>
</xsl:when>
<xsl:when test=".='SelectApp'"><xsl:text>TEEC_</xsl:text><xsl:value-of select="." /><xsl:text>(</xsl:text>
</xsl:when>
<xsl:when test=".='CloseSession'"><xsl:text>TEEC_</xsl:text><xsl:value-of select="." /><xsl:text>(</xsl:text>
</xsl:when>
<xsl:when test=".='FinalizeContext'"><xsl:text>TEEC_</xsl:text><xsl:value-of select="." /><xsl:text>(</xsl:text>
</xsl:when>
<xsl:when test=".='createThread'"><xsl:text>TEEC_</xsl:text><xsl:value-of select="." /><xsl:text>(</xsl:text>
</xsl:when>
<xsl:when test=".='PARAM_TYPES'"><xsl:text>OPERATION_TEEC_</xsl:text><xsl:value-of select="." /><xsl:text>(</xsl:text>
</xsl:when>
<xsl:when test=".='SetUp_TEE'"><xsl:text>TEEC_</xsl:text><xsl:value-of select="." /><xsl:text>(</xsl:text>
</xsl:when>
<xsl:when test=".='TearDown_TEE'"><xsl:text>TEEC_</xsl:text><xsl:value-of select="." /><xsl:text>(</xsl:text>
</xsl:when>
<xsl:otherwise>
<xsl:value-of select="." /><xsl:text>(c, </xsl:text>
</xsl:otherwise>
</xsl:choose>
</xsl:template>

<xsl:template match="observations">
<!-- <xsl:if test="*"><xsl:value-of select="./operation/@name" />(<xsl:for-each select="./operation/argument/value"><xsl:apply-templates select="." /><xsl:if test="not(position()=last())">, </xsl:if></xsl:for-each>); -->
<xsl:if test="*"><xsl:for-each select="./operation"><xsl:text>    </xsl:text><xsl:value-of select="./@name" /><xsl:text>(c</xsl:text><xsl:if test="not(contains(./@name, 'Check_Generated'))"><xsl:text>, </xsl:text></xsl:if><xsl:for-each select="./argument/value"><xsl:apply-templates select="." /><xsl:if test="not(position()=last())">, </xsl:if></xsl:for-each>);
</xsl:for-each>
</xsl:if>
</xsl:template>

</xsl:stylesheet>