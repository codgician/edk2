/** @file
    Null TPM Platform Hierarchy configuration library.

    This library provides stub functions for customizing the TPM's Platform Hierarchy.

    Copyright (c) 2021, IBM Corporation.
    SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Library/TpmPlatformHierarchyLib.h>

/**
  A NULL implementation cannot establish hierarchy protection.

  @retval EFI_UNSUPPORTED  No TPM hierarchy configuration is implemented.
**/
EFI_STATUS
EFIAPI
ConfigureTpmPlatformHierarchy (
  VOID
  )
{
  return EFI_UNSUPPORTED;
}
