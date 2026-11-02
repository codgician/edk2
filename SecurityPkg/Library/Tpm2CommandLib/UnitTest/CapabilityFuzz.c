/** @file Capability framing and consumer oracle. SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <stdlib.h>
#include <string.h>
#include "CapabilityMock.h"

STATIC VOID
Require (BOOLEAN Condition)
{
  if (!Condition) { abort (); }
}

int
LLVMFuzzerTestOneInput (CONST UINT8 *Data, size_t Size)
{
  TPMS_CAPABILITY_DATA Result;
  TPMS_CAPABILITY_DATA Before;
  TPMI_YES_NO More;
  TPM_CAP Capability;
  UINT32 Count;
  UINT32 Width;
  UINT32 Limit;
  UINT32 Offset;
  UINT32 Index;
  UINT32 SelectSize;
  UINT32 Property;
  UINT32 RequestCount;
  EFI_STATUS Status;
  BOOLEAN Valid;
  UINT8 Mode;

  if (Size < 1) { return 0; }
  Mode = Data[0] % 4;
  Capability = Mode == 0 ? TPM_CAP_TPM_PROPERTIES : Mode == 1 ? TPM_CAP_ALGS : Mode == 2 ? TPM_CAP_COMMANDS : TPM_CAP_PCRS;
  Property = Mode == 0 ? TPM_PT_MANUFACTURER : Mode == 1 ? 1 : Mode == 2 ? TPM_CC_GetCapability : 0;
  RequestCount = Mode == 1 ? MAX_CAP_ALGS : 1;
  MakeResponse (Capability, 0, 19);
  if ((Data[0] & 4) != 0) {
    mResponseSize = (UINT32)MIN (Size - 1, sizeof (mResponse));
    memcpy (mResponse, Data + 1, mResponseSize);
  } else {
    Count = Size > 1 ? Data[1] : 0;
    Width = Mode == 0 ? 8 : Mode == 1 ? 6 : Mode == 2 ? 4 : 0;
    mResponseSize = (UINT32)MIN (19 + (UINTN)Count * Width, sizeof (mResponse));
    Put32 (2, mResponseSize);
    Put32 (15, Count);
    if (Size > 2) { memcpy (mResponse + 19, Data + 2, MIN (Size - 2, sizeof (mResponse) - 19)); }
    if (Mode == 0) { Put32 (19, Property); }
    if (Size > 3 && (Data[0] & 8) != 0) { mResponseSize = Data[2] | ((UINT32)Data[3] << 8); }
  }
  Valid = mResponseSize >= 19 && mResponseSize <= CAP_RESPONSE_CAPACITY;
  Valid = Valid && mResponse[0] == 0x80 && mResponse[1] == 1 &&
          Get32 (mResponse + 2) == mResponseSize && Get32 (mResponse + 6) == TPM_RC_SUCCESS &&
          mResponse[10] <= 1 && Get32 (mResponse + 11) == Capability;
  Count = Get32 (mResponse + 15);
  Limit = Mode == 0 ? MAX_TPM_PROPERTIES : Mode == 1 ? MAX_CAP_ALGS : Mode == 2 ? MAX_CAP_CC : HASH_COUNT;
  Valid = Valid && Count <= Limit;
  Offset = 19;
  if (Mode < 3) {
    Width = Mode == 0 ? 8 : Mode == 1 ? 6 : 4;
    Valid = Valid && Count <= (mResponseSize >= 19 ? (mResponseSize - 19) / Width : 0) &&
            (UINT64)19 + (UINT64)Count * Width == mResponseSize;
  } else if (Valid) {
    for (Index = 0; Index < Count && Valid; Index++) {
      if (mResponseSize - Offset < 3) { Valid = FALSE; break; }
      SelectSize = mResponse[Offset + 2];
      Valid = SelectSize <= PCR_SELECT_MAX && SelectSize <= mResponseSize - Offset - 3;
      if (Valid) { Offset += 3 + SelectSize; }
    }
    Valid = Valid && Offset == mResponseSize;
  }
  memset (&Result, 0xa5, sizeof (Result));
  memcpy (&Before, &Result, sizeof (Before));
  More = 9;
  ExpectCapability (Capability, Property, RequestCount);
  Status = Tpm2GetCapability (Capability, Property, RequestCount, &More, &Result);
  CheckConsumed ();
  Require (Status == (Valid ? EFI_SUCCESS : EFI_DEVICE_ERROR));
  if (Valid) {
    Require (More == mResponse[10]);
    Require (memcmp (&Result, mResponse + 11, mResponseSize - 11) == 0);
  } else {
    Require (More == 9 && memcmp (&Result, &Before, sizeof (Result)) == 0);
  }
  if (Mode == 0) {
    UINT32 Value = 0xa5a5a5a5;
    Valid = Valid && Count == 1 && Get32 (mResponse + 19) == Property;
    ExpectCapability (Capability, Property, 1);
    Status = Tpm2GetCapabilityManufactureID (&Value);
    CheckConsumed ();
    Require (Status == (Valid ? EFI_SUCCESS : EFI_DEVICE_ERROR));
    Require (Value == (Valid ? SwapBytes32 (Get32 (mResponse + 23)) : 0xa5a5a5a5));
  } else if (Mode == 1) {
    TPML_ALG_PROPERTY Algs;
    ExpectCapability (Capability, Property, RequestCount);
    Status = Tpm2GetCapabilitySupportedAlg (&Algs);
    CheckConsumed ();
    Require (Status == (Valid ? EFI_SUCCESS : EFI_DEVICE_ERROR));
    if (Valid) {
      Require (Algs.count == Count);
      for (Index = 0; Index < Count; Index++) {
        Require (Algs.algProperties[Index].alg == (((UINT16)mResponse[19 + Index * 6] << 8) | mResponse[20 + Index * 6]));
        Require (ReadUnaligned32 ((UINT32 *)&Algs.algProperties[Index].algProperties) == Get32 (mResponse + 21 + Index * 6));
      }
    }
  } else if (Mode == 2) {
    BOOLEAN Implemented = 7;
    Valid = Valid && Count <= 1;
    ExpectCapability (Capability, Property, RequestCount);
    Status = Tpm2GetCapabilityIsCommandImplemented (Property, &Implemented);
    CheckConsumed ();
    Require (Status == (Valid ? EFI_SUCCESS : EFI_DEVICE_ERROR));
    if (Valid) { Require (Implemented == (Count == 1 && (Get32 (mResponse + 19) & 0x2000ffff) == Property)); }
  } else {
    TPML_PCR_SELECTION Pcrs;
    ExpectCapability (Capability, Property, RequestCount);
    Status = Tpm2GetCapabilityPcrs (&Pcrs);
    CheckConsumed ();
    Require (Status == (Valid ? EFI_SUCCESS : EFI_DEVICE_ERROR));
    if (Valid) {
      Require (Pcrs.count == Count);
      Offset = 19;
      for (Index = 0; Index < Count; Index++) {
        SelectSize = mResponse[Offset + 2];
        Require (Pcrs.pcrSelections[Index].hash == (((UINT16)mResponse[Offset] << 8) | mResponse[Offset + 1]));
        Require (Pcrs.pcrSelections[Index].sizeofSelect == SelectSize);
        Require (memcmp (Pcrs.pcrSelections[Index].pcrSelect, mResponse + Offset + 3, SelectSize) == 0);
        Offset += 3 + SelectSize;
      }
    }
  }
  return 0;
}
