/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
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

#include <trusty_app_manifest.h>
#include <stddef.h>
#include <tee_api_properties.h>

tee_api_properties_t TEE_API_PROP_ATTRS tee_api_properties =
{
    { "gpd.ta.description", TA_PROP_TYPE_STR, "xtest"},
    { "gpd.ta.singleInstance", TA_PROP_TYPE_BOOL, &(const bool){1}},
    { "gpd.ta.multiSession", TA_PROP_TYPE_BOOL, &(const bool){0}},
};

static const size_t ta_props_len = sizeof(tee_api_properties) / sizeof(tee_api_properties[0]);

trusty_app_manifest_t TRUSTY_APP_MANIFEST_ATTRS trusty_app_manifest =
{
    /* UUID : {98cc5934-5a70-4ff0-b1fa-a5624a7ca243} */
    { 0x98cc5934, 0x5a70, 0x4ff0,
    { 0xb1, 0xfa, 0xa5, 0x62, 0x4a, 0x7c, 0xa2, 0x43 } },

    /* optional configuration options here */
    {
        /* four pages for heap */
        TRUSTY_APP_CONFIG_MIN_HEAP_SIZE(1536 * 4096),

	TRUSTY_APP_CONFIG_MIN_STACK_SIZE(1024 * 1024),

        /* enable/disable auto start */
        TRUSTY_APP_CONFIG_AUTO_START(1),

        /* custom external config options */
        TRUSTY_APP_CONFIG_EXTERN((uint32_t)&tee_api_properties, (uint32_t)&ta_props_len),
    },
};
