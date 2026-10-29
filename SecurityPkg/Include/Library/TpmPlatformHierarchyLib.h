/** @file
    TPM Platform Hierarchy configuration library.

    This library provides functions for customizing the TPM's Platform Hierarchy
    Authorization Value (platformAuth) and Platform Hierarchy Authorization
    Policy (platformPolicy) can be defined through this function.

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef TPM_PLATFORM_HIERARCHY_LIB_H_
#define TPM_PLATFORM_HIERARCHY_LIB_H_

/**
  Protect the TPM platform hierarchy according to platform policy.

  @retval EFI_SUCCESS  A new authorization made entirely from successful RNG
                       output was accepted, or the hierarchy was disabled.
  @retval Others       Capability, entropy or TPM failure; protection is not
                       established. The caller must enforce its failure policy.
**/
EFI_STATUS
EFIAPI
ConfigureTpmPlatformHierarchy (
  VOID
  );

#endif
