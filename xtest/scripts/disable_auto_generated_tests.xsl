<?xml version="1.0" encoding="UTF-8"?>

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
<xsl:param name="f2" select="'TEE_DataStorage_API.xml'"/>
<xsl:param name="f3" select="'TEE_Internal_API.xml'"/>
<xsl:param name="f4" select="'TEE_TimeArithm_API.xml'"/>
<xsl:param name="f5" select="'TEE_Crypto_API.xml'"/>
<xsl:variable name="doc2" select="document($f2)"/>
<xsl:variable name="doc3" select="document($f3)"/>
<xsl:variable name="doc4" select="document($f4)"/>
<xsl:variable name="doc5" select="document($f5)"/>

<xsl:template match="package">
<xsl:text>/*
*
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
*
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
*/

#ifndef DISABLE_AUTO_GENERATED_TESTS_H
#define DISABLE_AUTO_GENERATED_TESTS_H

</xsl:text>
<xsl:for-each select="initial-state">
<xsl:variable name="scenario_name" select="@name" />
<xsl:text>#define Disable_</xsl:text><xsl:value-of select="$scenario_name"/>_or_NULL NULL
</xsl:for-each>
<!-- Exclude Crypto tests for now
<xsl:for-each select="$doc2/package/initial-state/scenario">
<xsl:variable name="position" select="position()" />    ADBG_SUITE_ENTRY(XTEST_TEE_<xsl:value-of select="$position+75000" />, NULL)\
</xsl:for-each>
<xsl:text>\
</xsl:text>
-->
<xsl:for-each select="$doc3/package/initial-state">
<xsl:variable name="scenario_name" select="@name" />
<xsl:text>#define Disable_</xsl:text><xsl:value-of select="$scenario_name"/>_or_NULL NULL
</xsl:for-each>
<xsl:for-each select="$doc4/package/initial-state">
<xsl:variable name="scenario_name" select="@name" />
<!-- Exclude Arithmetic tests for now -->
<xsl:if test="not(./configuration)">
<xsl:text>#define Disable_</xsl:text><xsl:value-of select="$scenario_name"/>_or_NULL NULL
</xsl:if>
</xsl:for-each>
<!-- Exclude Data Storage tests for now
<xsl:for-each select="$doc5/package/initial-state/scenario">
<xsl:variable name="position" select="position()" />    ADBG_SUITE_ENTRY(XTEST_TEE_<xsl:value-of select="$position+90000" />, NULL)\
</xsl:for-each>
-->
<xsl:text>
#endif /* DISABLE_AUTO_GENERATED_TESTS_H */
</xsl:text>
</xsl:template>
</xsl:stylesheet>

