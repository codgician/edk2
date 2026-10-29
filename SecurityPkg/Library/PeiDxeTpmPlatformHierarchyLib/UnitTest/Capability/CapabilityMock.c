/** @file Strict TPM transport mock. SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <stdlib.h>
#include <string.h>
#include "CapabilityMock.h"

UINT8 mResponse[CAP_RESPONSE_CAPACITY + 32];
UINT32 mResponseSize;
EFI_STATUS mTransportStatus;
STATIC BOOLEAN mExpected;
STATIC UINT32 mCapability;
STATIC UINT32 mProperty;
STATIC UINT32 mCount;
STATIC BOOLEAN mQueued;
STATIC UINT32 mQueuedProperty;
STATIC UINT32 mQueuedValue;

VOID
QueueProperty (UINT32 Property, UINT32 Value)
{
  if (mQueued) { abort (); }
  mQueued = TRUE;
  mQueuedProperty = Property;
  mQueuedValue = Value;
}

UINT32
Get32 (CONST UINT8 *Buffer)
{
  return ((UINT32)Buffer[0] << 24) | ((UINT32)Buffer[1] << 16) |
         ((UINT32)Buffer[2] << 8) | Buffer[3];
}

VOID
Put16 (UINTN Offset, UINT16 Value)
{
  mResponse[Offset] = (UINT8)(Value >> 8);
  mResponse[Offset + 1] = (UINT8)Value;
}

VOID
Put32 (UINTN Offset, UINT32 Value)
{
  mResponse[Offset] = (UINT8)(Value >> 24);
  mResponse[Offset + 1] = (UINT8)(Value >> 16);
  mResponse[Offset + 2] = (UINT8)(Value >> 8);
  mResponse[Offset + 3] = (UINT8)Value;
}

VOID
ExpectCapability (TPM_CAP Capability, UINT32 Property, UINT32 Count)
{
  if (mExpected) {
    abort ();
  }
  mExpected = TRUE;
  mCapability = Capability;
  mProperty = Property;
  mCount = Count;
}

VOID
CheckConsumed (VOID)
{
  if (mExpected || mQueued) {
    abort ();
  }
}

VOID
MakeResponse (TPM_CAP Capability, UINT32 Count, UINT32 Size)
{
  memset (mResponse, 0, sizeof (mResponse));
  mResponseSize = Size;
  mTransportStatus = EFI_SUCCESS;
  Put16 (0, TPM_ST_NO_SESSIONS);
  Put32 (2, Size);
  Put32 (6, TPM_RC_SUCCESS);
  Put32 (11, Capability);
  Put32 (15, Count);
}

EFI_STATUS
EFIAPI
Tpm2SubmitCommand (
  IN UINT32 InputParameterBlockSize,
  IN UINT8 *InputParameterBlock,
  IN OUT UINT32 *OutputParameterBlockSize,
  IN UINT8 *OutputParameterBlock
  )
{
  UINT32 Capacity;
  EFI_STATUS Status;

  if (!mExpected || (InputParameterBlockSize != 22) ||
      (InputParameterBlock[0] != 0x80) || (InputParameterBlock[1] != 1) ||
      (Get32 (InputParameterBlock + 2) != 22) ||
      (Get32 (InputParameterBlock + 6) != TPM_CC_GetCapability) ||
      (Get32 (InputParameterBlock + 10) != mCapability) ||
      (Get32 (InputParameterBlock + 14) != mProperty) ||
      (Get32 (InputParameterBlock + 18) != mCount)) {
    abort ();
  }
  mExpected = FALSE;
  Capacity = *OutputParameterBlockSize;
  if (Capacity != CAP_RESPONSE_CAPACITY) {
    abort ();
  }
  memcpy (OutputParameterBlock, mResponse, MIN (Capacity, mResponseSize));
  *OutputParameterBlockSize = mResponseSize;
  Status = mTransportStatus;
  if (mQueued) {
    mQueued = FALSE;
    MakeResponse (TPM_CAP_TPM_PROPERTIES, 1, 27);
    Put32 (19, mQueuedProperty);
    Put32 (23, mQueuedValue);
    ExpectCapability (TPM_CAP_TPM_PROPERTIES, mQueuedProperty, 1);
  }
  return Status;
}
