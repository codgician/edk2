/** @file Capability response regressions. SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include "CapabilityMock.h"

STATIC EFI_STATUS
Raw (TPMS_CAPABILITY_DATA *Data, TPMI_YES_NO *More)
{
  EFI_STATUS Status;
  ExpectCapability (TPM_CAP_TPM_PROPERTIES, TPM_PT_MANUFACTURER, 1);
  Status = Tpm2GetCapability (TPM_CAP_TPM_PROPERTIES, TPM_PT_MANUFACTURER, 1, More, Data);
  CheckConsumed ();
  return Status;
}

STATIC VOID
ValidRaw (VOID **State)
{
  TPMS_CAPABILITY_DATA Data;
  TPMI_YES_NO More = 9;
  (void)State;
  MakeResponse (TPM_CAP_TPM_PROPERTIES, 1, 27);
  Put32 (19, TPM_PT_MANUFACTURER);
  Put32 (23, 0x49465800);
  mResponse[10] = 1;
  memset (&Data, 0xa5, sizeof (Data));
  assert_int_equal (Raw (&Data, &More), EFI_SUCCESS);
  assert_int_equal (More, 1);
  assert_memory_equal (&Data, mResponse + 11, 16);
}

STATIC VOID
Framing (VOID **State)
{
  TPMS_CAPABILITY_DATA Data;
  TPMS_CAPABILITY_DATA Before;
  TPMI_YES_NO More;
  UINT32 Case;
  (void)State;
  for (Case = 0; Case < 12; Case++) {
    MakeResponse (TPM_CAP_TPM_PROPERTIES, 1, 27);
    Put32 (19, TPM_PT_MANUFACTURER);
    switch (Case) {
      case 0: mResponseSize = CAP_RESPONSE_CAPACITY + 1; break;
      case 1: mResponseSize = 12; Put32 (2, 12); break;
      case 2: mResponseSize = 18; Put32 (2, 18); break;
      case 3: mResponseSize = 26; Put32 (2, 26); break;
      case 4: Put32 (2, 26); break;
      case 5: Put32 (2, 28); break;
      case 6: Put16 (0, TPM_ST_SESSIONS); break;
      case 7: mResponse[10] = 2; break;
      case 8: Put32 (11, TPM_CAP_ALGS); break;
      case 9: Put32 (15, MAX_TPM_PROPERTIES + 1); break;
      case 10: Put32 (15, 2); break;
      default: Put32 (6, TPM_RC_FAILURE); break;
    }
    memset (&Data, 0xa5, sizeof (Data));
    memcpy (&Before, &Data, sizeof (Before));
    More = 9;
    assert_int_equal (Raw (&Data, &More), EFI_DEVICE_ERROR);
    assert_memory_equal (&Data, &Before, sizeof (Data));
    assert_int_equal (More, 9);
  }
}

typedef EFI_STATUS (EFIAPI *PROPERTY_HELPER)(UINT32 *Value);
STATIC VOID
Properties (VOID **State)
{
  STATIC CONST struct {
    PROPERTY_HELPER Helper;
    UINT32 Property;
    BOOLEAN RawOrder;
  } Helpers[] = {
    { Tpm2GetCapabilityManufactureID, TPM_PT_MANUFACTURER, TRUE },
    { Tpm2GetCapabilityLockoutCounter, TPM_PT_LOCKOUT_COUNTER, FALSE },
    { Tpm2GetCapabilityLockoutInterval, TPM_PT_LOCKOUT_INTERVAL, FALSE },
    { Tpm2GetCapabilityInputBufferSize, TPM_PT_INPUT_BUFFER, FALSE },
    { Tpm2GetCapabilityAlgorithmSet, TPM_PT_ALGORITHM_SET, FALSE }
  };
  UINTN Index;
  UINTN Case;
  UINT32 Value;
  CHAR8 Family[4];
  UINT32 Other;
  (void)State;
  for (Index = 0; Index < ARRAY_SIZE (Helpers); Index++) {
    for (Case = 0; Case < 3; Case++) {
      MakeResponse (TPM_CAP_TPM_PROPERTIES, Case == 1 ? 0 : 1, Case == 1 ? 19 : 27);
      Put32 (19, Helpers[Index].Property + (Case == 2 ? 1 : 0));
      Put32 (23, 0x12345678);
      Value = 0xa5a5a5a5;
      ExpectCapability (TPM_CAP_TPM_PROPERTIES, Helpers[Index].Property, 1);
      assert_int_equal (Helpers[Index].Helper (&Value), Case == 0 ? EFI_SUCCESS : EFI_DEVICE_ERROR);
      CheckConsumed ();
      assert_int_equal (Value, Case == 0 ? (Helpers[Index].RawOrder ? SwapBytes32 (0x12345678) : 0x12345678) : 0xa5a5a5a5);
    }
  }
  MakeResponse (TPM_CAP_TPM_PROPERTIES, 1, 27);
  Put32 (19, TPM_PT_FAMILY_INDICATOR);
  Put32 (23, 0x322e3000);
  ExpectCapability (TPM_CAP_TPM_PROPERTIES, TPM_PT_FAMILY_INDICATOR, 1);
  assert_int_equal (Tpm2GetCapabilityFamily (Family), EFI_SUCCESS);
  assert_memory_equal (Family, "2.0", 4);
  CheckConsumed ();
  MakeResponse (TPM_CAP_TPM_PROPERTIES, 0, 19);
  ExpectCapability (TPM_CAP_TPM_PROPERTIES, TPM_PT_FIRMWARE_VERSION_1, 1);
  assert_int_equal (Tpm2GetCapabilityFirmwareVersion (&Value, &Other), EFI_DEVICE_ERROR);
  CheckConsumed ();
  MakeResponse (TPM_CAP_TPM_PROPERTIES, 1, 27);
  Put32 (19, TPM_PT_MAX_COMMAND_SIZE + 1);
  ExpectCapability (TPM_CAP_TPM_PROPERTIES, TPM_PT_MAX_COMMAND_SIZE, 1);
  assert_int_equal (Tpm2GetCapabilityMaxCommandResponseSize (&Value, &Other), EFI_DEVICE_ERROR);
  CheckConsumed ();
}

STATIC VOID
Algorithms (VOID **State)
{
  TPML_ALG_PROPERTY Algs;
  UINT32 Count;
  UINT32 Index;
  (void)State;
  for (Count = 0; Count <= MAX_CAP_ALGS; Count += (Count == 0 ? 1 : MAX_CAP_ALGS - 1)) {
    MakeResponse (TPM_CAP_ALGS, Count, 19 + Count * 6);
    for (Index = 0; Index < Count; Index++) {
      Put16 (19 + Index * 6, TPM_ALG_SHA256);
      Put32 (21 + Index * 6, 0x12345678);
    }
    ExpectCapability (TPM_CAP_ALGS, 1, MAX_CAP_ALGS);
    assert_int_equal (Tpm2GetCapabilitySupportedAlg (&Algs), EFI_SUCCESS);
    assert_int_equal (Algs.count, Count);
    for (Index = 0; Index < Count; Index++) {
      assert_int_equal (Algs.algProperties[Index].alg, TPM_ALG_SHA256);
      assert_int_equal (ReadUnaligned32 ((UINT32 *)&Algs.algProperties[Index].algProperties), 0x12345678);
    }
    CheckConsumed ();
  }
  MakeResponse (TPM_CAP_ALGS, 2, 25);
  ExpectCapability (TPM_CAP_ALGS, 1, MAX_CAP_ALGS);
  assert_int_equal (Tpm2GetCapabilitySupportedAlg (&Algs), EFI_DEVICE_ERROR);
  CheckConsumed ();
}

STATIC VOID
Pcrs (VOID **State)
{
  TPML_PCR_SELECTION Pcrs;
  UINTN Case;
  (void)State;
  for (Case = 0; Case < 6; Case++) {
    MakeResponse (TPM_CAP_PCRS, 2, 28);
    Put16 (19, TPM_ALG_SHA1);
    mResponse[21] = 1;
    mResponse[22] = 0x81;
    Put16 (23, TPM_ALG_SHA256);
    mResponse[25] = 2;
    mResponse[26] = 0x42;
    mResponse[27] = 0x24;
    switch (Case) {
      case 1: Put32 (15, HASH_COUNT + 1); break;
      case 2: mResponse[21] = PCR_SELECT_MAX + 1; break;
      case 3: mResponseSize = 27; Put32 (2, 27); break;
      case 4: Put32 (15, 3); break;
      case 5: MakeResponse (TPM_CAP_PCRS, 0, 19); break;
      default: break;
    }
    ExpectCapability (TPM_CAP_PCRS, 0, 1);
    assert_int_equal (Tpm2GetCapabilityPcrs (&Pcrs), (Case == 0 || Case == 5) ? EFI_SUCCESS : EFI_DEVICE_ERROR);
    CheckConsumed ();
    if (Case == 0) {
      assert_int_equal (Pcrs.count, 2);
      assert_int_equal (Pcrs.pcrSelections[0].hash, TPM_ALG_SHA1);
      assert_int_equal (Pcrs.pcrSelections[0].sizeofSelect, 1);
      assert_int_equal (Pcrs.pcrSelections[0].pcrSelect[0], 0x81);
      assert_int_equal (Pcrs.pcrSelections[1].hash, TPM_ALG_SHA256);
      assert_int_equal (Pcrs.pcrSelections[1].sizeofSelect, 2);
      assert_memory_equal (Pcrs.pcrSelections[1].pcrSelect, "\x42\x24", 2);
    } else if (Case == 5) {
      assert_int_equal (Pcrs.count, 0);
    }
  }
}

STATIC VOID
Commands (VOID **State)
{
  BOOLEAN Implemented;
  UINT32 Case;
  (void)State;
  for (Case = 0; Case < 5; Case++) {
    MakeResponse (TPM_CAP_COMMANDS, Case == 2 ? 0 : (Case == 3 ? 2 : 1), Case == 2 ? 19 : 23);
    Put32 (19, Case == 1 ? TPM_CC_GetCapability + 1 : TPM_CC_GetCapability);
    if (Case == 4) { mResponseSize = 22; Put32 (2, 22); }
    Implemented = TRUE;
    ExpectCapability (TPM_CAP_COMMANDS, TPM_CC_GetCapability, 1);
    assert_int_equal (Tpm2GetCapabilityIsCommandImplemented (TPM_CC_GetCapability, &Implemented), Case >= 3 ? EFI_DEVICE_ERROR : EFI_SUCCESS);
    CheckConsumed ();
    if (Case < 3) { assert_int_equal (Implemented, Case == 0); }
  }
}

STATIC VOID
PropertyPairsAndErrors (VOID **State)
{
  UINT32 First;
  UINT32 Second;
  UINT32 Case;
  TPMS_CAPABILITY_DATA Result;
  TPMI_YES_NO More = 9;
  (void)State;
  for (Case = 0; Case < 2; Case++) {
    MakeResponse (TPM_CAP_TPM_PROPERTIES, 1, 27);
    Put32 (19, Case == 0 ? TPM_PT_FIRMWARE_VERSION_1 : TPM_PT_MAX_COMMAND_SIZE);
    Put32 (23, 0x12345678);
    QueueProperty (Case == 0 ? TPM_PT_FIRMWARE_VERSION_2 : TPM_PT_MAX_RESPONSE_SIZE, 0x87654321);
    ExpectCapability (TPM_CAP_TPM_PROPERTIES, Case == 0 ? TPM_PT_FIRMWARE_VERSION_1 : TPM_PT_MAX_COMMAND_SIZE, 1);
    assert_int_equal (Case == 0 ? Tpm2GetCapabilityFirmwareVersion (&First, &Second) : Tpm2GetCapabilityMaxCommandResponseSize (&First, &Second), EFI_SUCCESS);
    CheckConsumed ();
    assert_int_equal (First, 0x12345678);
    assert_int_equal (Second, 0x87654321);
  }
  MakeResponse (TPM_CAP_TPM_PROPERTIES, 1, 27);
  mTransportStatus = EFI_TIMEOUT;
  memset (&Result, 0xa5, sizeof (Result));
  assert_int_equal (Raw (&Result, &More), EFI_TIMEOUT);
  assert_int_equal (More, 9);
  for (Case = 0; Case <= 10; Case++) {
    MakeResponse (TPM_CAP_TPM_PROPERTIES, 0, Case);
    assert_int_equal (Raw (&Result, &More), EFI_DEVICE_ERROR);
  }
}

STATIC VOID
OtherCapabilityLists (VOID **State)
{
  STATIC CONST TPM_CAP Capabilities[] = {
    TPM_CAP_HANDLES, TPM_CAP_PP_COMMANDS, TPM_CAP_AUDIT_COMMANDS,
    TPM_CAP_ECC_CURVES, TPM_CAP_PCR_PROPERTIES
  };
  TPMS_CAPABILITY_DATA Result;
  TPMI_YES_NO More;
  UINTN Index;
  UINTN Case;
  UINT32 Width;
  (void)State;
  for (Index = 0; Index < ARRAY_SIZE (Capabilities); Index++) {
    Width = Index == 3 ? 2 : Index == 4 ? 6 : 4;
    for (Case = 0; Case < 3; Case++) {
      MakeResponse (Capabilities[Index], 1, 19 + Width);
      if (Index == 4) { mResponse[23] = 1; mResponse[24] = 0x80; }
      if (Case == 1) { mResponseSize--; Put32 (2, mResponseSize); }
      if (Case == 2) { Put32 (15, 0xffffffff); }
      ExpectCapability (Capabilities[Index], 0, 1);
      assert_int_equal (Tpm2GetCapability (Capabilities[Index], 0, 1, &More, &Result), Case == 0 ? EFI_SUCCESS : EFI_DEVICE_ERROR);
      CheckConsumed ();
      if (Case == 0) { assert_memory_equal (&Result, mResponse + 11, mResponseSize - 11); }
    }
  }
}

int
main (void)
{
  CONST struct CMUnitTest Tests[] = {
    cmocka_unit_test (ValidRaw), cmocka_unit_test (Framing),
    cmocka_unit_test (Properties), cmocka_unit_test (Algorithms),
    cmocka_unit_test (Pcrs), cmocka_unit_test (Commands),
    cmocka_unit_test (PropertyPairsAndErrors), cmocka_unit_test (OtherCapabilityLists)
  };
  return cmocka_run_group_tests (Tests, NULL, NULL);
}
