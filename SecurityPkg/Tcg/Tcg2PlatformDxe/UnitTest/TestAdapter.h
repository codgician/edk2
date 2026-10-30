/** @file Host PCD binding for the hierarchy callers. SPDX-License-Identifier: BSD-2-Clause-Patent **/
#ifndef HIERARCHY_CALLERS_TEST_ADAPTER_H_
#define HIERARCHY_CALLERS_TEST_ADAPTER_H_
#include <Uefi.h>
#include <Guid/TcgEventHob.h>
extern BOOLEAN  mRandomizeHierarchy;
#define _PCD_GET_MODE_BOOL_PcdRandomizePlatformHierarchy  mRandomizeHierarchy
#endif
