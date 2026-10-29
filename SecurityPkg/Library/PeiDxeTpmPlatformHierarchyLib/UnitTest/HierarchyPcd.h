/** @file Host PCD adapter. SPDX-License-Identifier: BSD-2-Clause-Patent **/
#include <Uefi.h>
extern BOOLEAN  mRandomize;
extern CONST CHAR8  *gEfiCallerBaseName;
#define _PCD_GET_MODE_BOOL_PcdRandomizePlatformHierarchy  mRandomize
