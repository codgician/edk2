/** @file
    TPM Platform Hierarchy configuration library.

    This library provides functions for customizing the TPM's Platform Hierarchy
    Authorization Value (platformAuth) and Platform Hierarchy Authorization
    Policy (platformPolicy) can be defined through this function.

    Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
    Copyright (c) Microsoft Corporation.<BR>
    SPDX-License-Identifier: BSD-2-Clause-Patent

    @par Specification Reference:
    https://trustedcomputinggroup.org/resource/tcg-tpm-v2-0-provisioning-guidance/
**/

#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/RngLib.h>
#include <Library/Tpm2CommandLib.h>
#include <Library/Tpm2DeviceLib.h>
#include <Library/TpmPlatformHierarchyLib.h>

//
// The authorization value may be no larger than the digest produced by the hash
//   algorithm used for context integrity.
//

UINT16  mAuthSize;

/**
  Generate entropy through the platform RNG library.

  @param[in]   Length        Size of the buffer, in bytes, to fill with.
  @param[out]  Entropy       Pointer to the buffer to store the entropy data.

  @retval EFI_SUCCESS        Entropy generation succeeded.
  @retval EFI_NOT_READY      Failed to request random data.

**/
EFI_STATUS
EFIAPI
RdRandGenerateEntropy (
  IN UINTN   Length,
  OUT UINT8  *Entropy
  )
{
  EFI_STATUS  Status;
  UINTN       Remaining;
  UINTN       Size;
  UINT64      Seed[2];
  UINT8       *Ptr;

  Status    = EFI_SUCCESS;
  Remaining = Length;
  Ptr       = Entropy;
  ZeroMem (Seed, sizeof (Seed));

  while (Remaining > 0) {
    if (!GetRandomNumber128 (Seed)) {
      Status = EFI_NOT_READY;
      ZeroMem (Entropy, Length);
      break;
    }

    Size = MIN (Remaining, sizeof (Seed));
    CopyMem (Ptr, Seed, Size);
    Remaining -= Size;
    Ptr       += Size;
  }

  ZeroMem (Seed, sizeof (Seed));
  return Status;
}

/**
  Return the digest size of the TPM context-integrity algorithm.

  PCR banks, including inactive banks, do not determine the authValue limit.
  Cache only a successfully validated fixed-property response.

  @param[out] AuthSize                 Maximum TPM authorization size.

  @retval EFI_SUCCESS                  Auth size returned.
  @retval EFI_UNSUPPORTED              Context hash algorithm is unknown.
  @retval EFI_DEVICE_ERROR             The capability response is invalid.
  @retval Others                       The capability query failed.

**/
EFI_STATUS
EFIAPI
GetAuthSize (
  OUT UINT16  *AuthSize
  )
{
  EFI_STATUS            Status;
  TPMS_CAPABILITY_DATA  CapabilityData;
  TPMI_YES_NO           MoreData;
  UINT16                DigestSize;

  *AuthSize = 0;
  if (mAuthSize != 0) {
    *AuthSize = mAuthSize;
    return EFI_SUCCESS;
  }

  ZeroMem (&CapabilityData, sizeof (CapabilityData));
  Status = Tpm2GetCapability (
             TPM_CAP_TPM_PROPERTIES,
             TPM_PT_CONTEXT_HASH,
             1,
             &MoreData,
             &CapabilityData
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((SwapBytes32 (CapabilityData.capability) != TPM_CAP_TPM_PROPERTIES) ||
      (SwapBytes32 (CapabilityData.data.tpmProperties.count) != 1) ||
      (SwapBytes32 (CapabilityData.data.tpmProperties.tpmProperty[0].property) != TPM_PT_CONTEXT_HASH))
  {
    return EFI_DEVICE_ERROR;
  }

  switch (SwapBytes32 (CapabilityData.data.tpmProperties.tpmProperty[0].value)) {
    case TPM_ALG_SHA1:
      DigestSize = SHA1_DIGEST_SIZE;
      break;
    case TPM_ALG_SHA256:
      DigestSize = SHA256_DIGEST_SIZE;
      break;
    case TPM_ALG_SHA384:
      DigestSize = SHA384_DIGEST_SIZE;
      break;
    case TPM_ALG_SHA512:
      DigestSize = SHA512_DIGEST_SIZE;
      break;
    case TPM_ALG_SM3_256:
      DigestSize = SM3_256_DIGEST_SIZE;
      break;
    default:
      return EFI_UNSUPPORTED;
  }

  if (DigestSize > sizeof (((TPM2B_AUTH *)0)->buffer)) {
    return EFI_UNSUPPORTED;
  }

  mAuthSize = DigestSize;
  *AuthSize = DigestSize;
  return EFI_SUCCESS;
}

/**
  Set platformAuth to a value made entirely from successful RNG output.

  @retval EFI_SUCCESS  The TPM accepted the new authorization.
  @retval Others       Capability, entropy or TPM command failure.
**/
EFI_STATUS
RandomizePlatformAuth (
  VOID
  )
{
  EFI_STATUS  Status;
  UINT16      AuthSize;
  TPM2B_AUTH  NewPlatformAuth;

  ZeroMem (&NewPlatformAuth, sizeof (NewPlatformAuth));
  Status = GetAuthSize (&AuthSize);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  NewPlatformAuth.size = AuthSize;
  Status              = RdRandGenerateEntropy (AuthSize, NewPlatformAuth.buffer);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  Status = Tpm2HierarchyChangeAuth (TPM_RH_PLATFORM, NULL, &NewPlatformAuth);
  DEBUG ((DEBUG_INFO, "Tpm2HierarchyChangeAuth Result: %r\n", Status));

Exit:
  ZeroMem (&NewPlatformAuth, sizeof (NewPlatformAuth));
  return Status;
}

/**
  Disable the TPM platform hierarchy.

  @retval   EFI_SUCCESS       The TPM was disabled successfully.
  @retval   Others            An error occurred attempting to disable the TPM platform hierarchy.

**/
EFI_STATUS
DisableTpmPlatformHierarchy (
  VOID
  )
{
  EFI_STATUS  Status;

  // Make sure that we have use of the TPM.
  Status = Tpm2RequestUseTpm ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a:%a() - Tpm2RequestUseTpm Failed! %r\n", gEfiCallerBaseName, __func__, Status));
    return Status;
  }

  // Let's do what we can to shut down the hierarchies.

  // Disable the PH NV.
  // IMPORTANT NOTE: We *should* be able to disable the PH NV here, but TPM parts have
  //                 been known to store the EK cert in the PH NV. If we disable it, the
  //                 EK cert will be unreadable.

  // Disable the PH.
  Status =  Tpm2HierarchyControl (
              TPM_RH_PLATFORM,     // AuthHandle
              NULL,                // AuthSession
              TPM_RH_PLATFORM,     // Hierarchy
              NO                   // State
              );
  DEBUG ((DEBUG_VERBOSE, "%a:%a() -  Disable PH = %r\n", gEfiCallerBaseName, __func__, Status));
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a:%a() -  Disable PH Failed! %r\n", gEfiCallerBaseName, __func__, Status));
  }

  return Status;
}

/**
   This service defines the configuration of the Platform Hierarchy Authorization Value (platformAuth)
   and Platform Hierarchy Authorization Policy (platformPolicy).

   @retval EFI_SUCCESS  Authorization was replaced, or the hierarchy disabled.
   @retval Others       Hierarchy protection failed.
**/
EFI_STATUS
EFIAPI
ConfigureTpmPlatformHierarchy (
  VOID
  )
{
  if (PcdGetBool (PcdRandomizePlatformHierarchy)) {
    //
    // Send Tpm2HierarchyChange Auth with random value to avoid PlatformAuth being null
    //
    return RandomizePlatformAuth ();
  } else {
    //
    // Disable the hierarchy entirely (do not randomize it)
    //
    return DisableTpmPlatformHierarchy ();
  }
}
