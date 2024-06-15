/**
 * API Set Lookup
 * Copyright (c) 2018-2019 Aidan Khoury. All rights reserved.
 *
 * @file apiset.h
 * @author Aidan Khoury (ajkhoury)
 * @date 11/22/2018
 */

#pragma once

//
// API schema definitions.
//

#define API_SET_SCHEMA_VERSION_V2 0x00000002
#define API_SET_SCHEMA_VERSION_V3 0x00000003 // No offline support.
#define API_SET_SCHEMA_VERSION_V4 0x00000004
#define API_SET_SCHEMA_VERSION_V6 0x00000006

PCHAR api_set_resolve(
    IN PCHAR dll_name);
