/** @file
  Hierarchy protection boundary tests with synthetic entropy only.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/Tpm2CommandLib.h>
#include <Library/Tpm2DeviceLib.h>
#include <Library/TpmPlatformHierarchyLib.h>

EFI_STATUS EFIAPI RdRandGenerateEntropy (UINTN Length, UINT8 *Entropy);
EFI_STATUS EFIAPI GetAuthSize (UINT16 *AuthSize);
extern UINT16 mAuthSize;
BOOLEAN mRandomize;
CONST CHAR8 *gEfiCallerBaseName = "HierarchyTest";

STATIC EFI_STATUS mCapabilityStatus;
STATIC EFI_STATUS mChangeStatus;
STATIC EFI_STATUS mRequestStatus;
STATIC EFI_STATUS mControlStatus;
STATIC UINT32 mContextHash;
STATIC UINTN mMalformedCapability;
STATIC UINTN mAuthClears;
STATIC UINTN mRngCalls;
STATIC UINTN mFailRngCall;
STATIC UINTN mChanges;
STATIC UINTN mCapabilities;
STATIC UINTN mRequests;
STATIC UINTN mControls;
STATIC VOID *mSeed;
STATIC VOID *mAuth;
STATIC BOOLEAN mSeedErased;
STATIC BOOLEAN mAuthErased;
STATIC TPM2B_AUTH mSubmitted;

VOID *EFIAPI __real_ZeroMem (VOID *Buffer, UINTN Length);
VOID *EFIAPI
__wrap_ZeroMem (VOID *Buffer, UINTN Length)
{
  VOID *Result = __real_ZeroMem (Buffer, Length);
  if ((Buffer == mSeed) && (Length == 16)) {
    assert_memory_equal (Buffer, (UINT8[16]){0}, 16);
    mSeedErased = TRUE;
  }
  if (Length == sizeof (TPM2B_AUTH)) {
    mAuth = Buffer;
    assert_memory_equal (Buffer, (TPM2B_AUTH[1]){{0}}, Length);
    mAuthErased = TRUE;
    mAuthClears++;
  }
  return Result;
}

BOOLEAN EFIAPI
GetRandomNumber128 (UINT64 *Rand)
{
  UINTN Index;
  mSeed = Rand;
  mSeedErased = FALSE;
  mRngCalls++;
  if (mRngCalls == mFailRngCall) {
    // A provider can fail after modifying only part of its output.
    ((UINT8 *)Rand)[0] = 0xee;
    return FALSE;
  }
  for (Index = 0; Index < 16; Index++) {
    ((UINT8 *)Rand)[Index] = (UINT8)(mRngCalls * 16 + Index);
  }
  return TRUE;
}

EFI_STATUS EFIAPI
Tpm2GetCapability (TPM_CAP Capability, UINT32 Property, UINT32 PropertyCount,
                  TPMI_YES_NO *MoreData, TPMS_CAPABILITY_DATA *Data)
{
  assert_int_equal (Capability, TPM_CAP_TPM_PROPERTIES);
  assert_int_equal (Property, TPM_PT_CONTEXT_HASH);
  assert_int_equal (PropertyCount, 1);
  mCapabilities++;
  if (EFI_ERROR (mCapabilityStatus)) {
    return mCapabilityStatus;
  }
  memset (Data, 0, sizeof (*Data));
  *MoreData = NO;
  Data->capability = SwapBytes32 (Capability);
  Data->data.tpmProperties.count = SwapBytes32 (1);
  Data->data.tpmProperties.tpmProperty[0].property = SwapBytes32 (Property);
  Data->data.tpmProperties.tpmProperty[0].value = SwapBytes32 (mContextHash);
  if (mMalformedCapability == 1) {
    Data->capability = SwapBytes32 (TPM_CAP_ALGS);
  } else if (mMalformedCapability == 2) {
    Data->data.tpmProperties.count = 0;
  } else if (mMalformedCapability == 3) {
    Data->data.tpmProperties.count = SwapBytes32 (2);
  } else if (mMalformedCapability == 4) {
    Data->data.tpmProperties.tpmProperty[0].property = SwapBytes32 (Property + 1);
  }
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI
Tpm2HierarchyChangeAuth (TPMI_RH_HIERARCHY_AUTH Handle,
                        TPMS_AUTH_COMMAND *Session, TPM2B_AUTH *Auth)
{
  assert_int_equal (Handle, TPM_RH_PLATFORM);
  assert_null (Session);
  mAuth = Auth;
  mAuthErased = FALSE;
  mChanges++;
  memcpy (&mSubmitted, Auth, sizeof (*Auth));
  return mChangeStatus;
}

EFI_STATUS EFIAPI
Tpm2RequestUseTpm (VOID)
{
  mRequests++;
  assert_int_equal (mRequests, 1);
  return mRequestStatus;
}

EFI_STATUS EFIAPI
Tpm2HierarchyControl (TPMI_RH_HIERARCHY Handle, TPMS_AUTH_COMMAND *Session,
                     TPMI_RH_HIERARCHY Hierarchy, TPMI_YES_NO State)
{
  assert_int_equal (Handle, TPM_RH_PLATFORM);
  assert_null (Session);
  assert_int_equal (Hierarchy, TPM_RH_PLATFORM);
  assert_int_equal (State, NO);
  mControls++;
  assert_int_equal (mControls, 1);
  return mControlStatus;
}

STATIC int
Reset (void **State)
{
  (void)State;
  mAuthSize = 0;
  mRandomize = TRUE;
  mCapabilityStatus = mChangeStatus = mRequestStatus = mControlStatus = EFI_SUCCESS;
  mContextHash = TPM_ALG_SHA256;
  mMalformedCapability = mAuthClears = 0;
  mRngCalls = mFailRngCall = mChanges = mCapabilities = mRequests = mControls = 0;
  mSeed = mAuth = NULL;
  mSeedErased = mAuthErased = FALSE;
  memset (&mSubmitted, 0, sizeof (mSubmitted));
  return 0;
}

STATIC EFI_STATUS
Configure (VOID)
{
  return ConfigureTpmPlatformHierarchy ();
}

STATIC VOID
EntropyFailure (void **State)
{
  UINT8 Data[32];
  (void)State;
  memset (Data, 0xa5, sizeof (Data));
  mFailRngCall = 1;
  assert_int_equal (RdRandGenerateEntropy (sizeof (Data), Data), EFI_NOT_READY);
  assert_true (mSeedErased);
  assert_memory_equal (Data, (UINT8[32]){0}, sizeof (Data));
}

STATIC VOID
EntropyFullBlocks (void **State)
{
  UINT8 Data[32];
  UINTN Index;
  (void)State;
  assert_int_equal (RdRandGenerateEntropy (sizeof (Data), Data), EFI_SUCCESS);
  assert_int_equal (mRngCalls, 2);
  for (Index = 0; Index < sizeof (Data); Index++) {
    assert_int_equal (Data[Index], 16 + Index);
  }
  assert_true (mSeedErased);
}

STATIC VOID
EntropyRemainder (void **State)
{
  UINT8 Data[19];
  UINTN Index;
  (void)State;
  assert_int_equal (RdRandGenerateEntropy (sizeof (Data), Data), EFI_SUCCESS);
  assert_int_equal (mRngCalls, 2);
  for (Index = 0; Index < sizeof (Data); Index++) {
    assert_int_equal (Data[Index], 16 + Index);
  }
  assert_true (mSeedErased);
}

STATIC VOID
EntropyPartialFailure (void **State)
{
  UINT8 Data[32];
  (void)State;
  mFailRngCall = 2;
  assert_int_equal (RdRandGenerateEntropy (sizeof (Data), Data), EFI_NOT_READY);
  assert_true (mSeedErased);
  assert_memory_equal (Data, (UINT8[32]){0}, sizeof (Data));
}

STATIC VOID
CapabilityFailureNoCommand (void **State)
{
  (void)State;
  mCapabilityStatus = EFI_DEVICE_ERROR;
  Configure ();
  assert_int_equal (mChanges, 0);
  assert_int_equal (mAuthClears, 2);
}

STATIC VOID
CapabilityRetry (void **State)
{
  UINT16 Size;
  (void)State;
  mCapabilityStatus = EFI_DEVICE_ERROR;
  assert_int_equal (GetAuthSize (&Size), EFI_DEVICE_ERROR);
  mCapabilityStatus = EFI_SUCCESS;
  assert_int_equal (GetAuthSize (&Size), EFI_SUCCESS);
  assert_int_equal (mCapabilities, 2);
  assert_int_equal (Size, 32);
}

STATIC VOID
RngFailureNoCommand (void **State)
{
  (void)State;
  mFailRngCall = 2;
  Configure ();
  assert_int_equal (mChanges, 0);
  assert_true (mSeedErased);
  assert_int_equal (mAuthClears, 2);
}

STATIC VOID
ContextHashAuth (void **State)
{
  UINTN Index;
  (void)State;
  assert_int_equal (Configure (), EFI_SUCCESS);
  assert_int_equal (mChanges, 1);
  assert_int_equal (mSubmitted.size, 32);
  assert_int_equal (mRngCalls, 2);
  for (Index = 0; Index < mSubmitted.size; Index++) {
    assert_int_equal (mSubmitted.buffer[Index], 16 + Index);
  }
  for (; Index < sizeof (mSubmitted.buffer); Index++) {
    assert_int_equal (mSubmitted.buffer[Index], 0);
  }
  assert_true (mSeedErased);
  assert_true (mAuthErased);
}

STATIC VOID
ChangeError (void **State)
{
  (void)State;
  mChangeStatus = EFI_ACCESS_DENIED;
  assert_int_equal (Configure (), EFI_ACCESS_DENIED);
  assert_int_equal (mChanges, 1);
  assert_true (mAuthErased);
}

STATIC VOID
FailureStatuses (void **State)
{
  (void)State;
  mCapabilityStatus = EFI_TIMEOUT;
  assert_int_equal (Configure (), EFI_TIMEOUT);
  mCapabilityStatus = EFI_SUCCESS;
  mFailRngCall = 1;
  assert_int_equal (Configure (), EFI_NOT_READY);
  assert_int_equal (mChanges, 0);
}

STATIC VOID
UnsupportedContext (void **State)
{
  (void)State;
  mContextHash = TPM_ALG_NULL;
  assert_int_equal (Configure (), EFI_UNSUPPORTED);
  assert_int_equal (mChanges, 0);
  assert_int_equal (mRngCalls, 0);
}

STATIC VOID
ContextAlgorithms (void **State)
{
  STATIC CONST UINT16 Algorithms[] = {
    TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512, TPM_ALG_SM3_256
  };
  STATIC CONST UINT16 Sizes[] = { 20, 32, 48, 64, 32 };
  UINTN Index;
  UINTN Byte;
  for (Index = 0; Index < ARRAY_SIZE (Algorithms); Index++) {
    Reset (State);
    mContextHash = Algorithms[Index];
    assert_int_equal (Configure (), EFI_SUCCESS);
    assert_int_equal (mSubmitted.size, Sizes[Index]);
    assert_int_equal (mRngCalls, (Sizes[Index] + 15) / 16);
    for (Byte = 0; Byte < Sizes[Index]; Byte++) {
      assert_int_equal (mSubmitted.buffer[Byte], Byte + 16);
    }
    assert_int_equal (mAuthClears, 2);
    assert_true (mSeedErased);
  }
}

STATIC VOID
MalformedCapability (void **State)
{
  UINTN Case;
  for (Case = 1; Case <= 4; Case++) {
    Reset (State);
    mMalformedCapability = Case;
    assert_int_equal (Configure (), EFI_DEVICE_ERROR);
    assert_int_equal (mChanges, 0);
    assert_int_equal (mRngCalls, 0);
    assert_int_equal (mAuthSize, 0);
    assert_int_equal (mAuthClears, 2);
  }
}

STATIC VOID
DisableStatuses (void **State)
{
  (void)State;
  mRandomize = FALSE;
  assert_int_equal (Configure (), EFI_SUCCESS);
  assert_int_equal (mRequests, 1);
  assert_int_equal (mControls, 1);
  mRequests = mControls = 0;
  mControlStatus = EFI_DEVICE_ERROR;
  assert_int_equal (Configure (), EFI_DEVICE_ERROR);
  mRequests = mControls = 0;
  mRequestStatus = EFI_NOT_FOUND;
  assert_int_equal (Configure (), EFI_NOT_FOUND);
  assert_int_equal (mControls, 0);
}

int main (void)
{
  const struct CMUnitTest Tests[] = {
    cmocka_unit_test_setup (EntropyFailure, Reset),
    cmocka_unit_test_setup (EntropyFullBlocks, Reset),
    cmocka_unit_test_setup (EntropyRemainder, Reset),
    cmocka_unit_test_setup (EntropyPartialFailure, Reset),
    cmocka_unit_test_setup (CapabilityFailureNoCommand, Reset),
    cmocka_unit_test_setup (CapabilityRetry, Reset),
    cmocka_unit_test_setup (RngFailureNoCommand, Reset),
    cmocka_unit_test_setup (ContextHashAuth, Reset),
    cmocka_unit_test_setup (ChangeError, Reset),
    cmocka_unit_test_setup (FailureStatuses, Reset),
    cmocka_unit_test_setup (UnsupportedContext, Reset),
    cmocka_unit_test_setup (ContextAlgorithms, Reset),
    cmocka_unit_test_setup (MalformedCapability, Reset),
    cmocka_unit_test_setup (DisableStatuses, Reset),
  };
  return cmocka_run_group_tests (Tests, NULL, NULL);
}
