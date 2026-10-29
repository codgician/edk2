/** @file Capability transport fixture. SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CAPABILITY_MOCK_H_
#define CAPABILITY_MOCK_H_
#include <Library/Tpm2CommandLib.h>
#include <Library/Tpm2DeviceLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>

#define CAP_FRAME_PREFIX  19U
#define CAP_RESPONSE_CAPACITY  (11U + sizeof (TPMS_CAPABILITY_DATA))
extern UINT8 mResponse[CAP_RESPONSE_CAPACITY + 32];
extern UINT32 mResponseSize;
extern EFI_STATUS mTransportStatus;
VOID Put16 (UINTN Offset, UINT16 Value);
VOID Put32 (UINTN Offset, UINT32 Value);
UINT32 Get32 (CONST UINT8 *Buffer);
VOID ExpectCapability (TPM_CAP Capability, UINT32 Property, UINT32 Count);
VOID CheckConsumed (VOID);
VOID MakeResponse (TPM_CAP Capability, UINT32 Count, UINT32 Size);
VOID QueueProperty (UINT32 Property, UINT32 Value);
#endif
