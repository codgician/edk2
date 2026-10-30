/** @file
  Exercise the real DXE and PEI hierarchy notification callers.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>
#include <PiPei.h>
#include <Library/HobLib.h>
#include <Library/PeiServicesLib.h>
#include <Library/PrintLib.h>
#include <Library/SerialPortLib.h>
#include <Library/UefiLib.h>
#include <Protocol/DxeSmmReadyToLock.h>
#include <Protocol/Tcg2Protocol.h>
#include <Ppi/EndOfPeiPhase.h>

VOID EFIAPI SmmReadyToLockEventCallBack (EFI_EVENT Event, VOID *Context);
EFI_STATUS EFIAPI PlatformInitEndOfPei (CONST EFI_PEI_SERVICES **Services, EFI_PEI_NOTIFY_DESCRIPTOR *Descriptor, VOID *Ppi);

EFI_GUID gEfiDxeSmmReadyToLockProtocolGuid = { 1 };
EFI_GUID gEfiTcg2ProtocolGuid = { 2 };
EFI_GUID gTcgEventEntryHobGuid = { 3 };
EFI_GUID gTcgEvent2EntryHobGuid = { 4 };
EFI_GUID gEfiEndOfPeiSignalPpiGuid = { 5 };
EFI_SYSTEM_TABLE *gST;
BOOLEAN mRandomizeHierarchy;
STATIC EFI_BOOT_SERVICES mBootServices;
EFI_BOOT_SERVICES *gBS = &mBootServices;
STATIC EFI_TCG2_PROTOCOL mTcg2;
STATIC EFI_STATUS mHierarchyStatus;
STATIC EFI_STATUS mCapabilityStatus;
STATIC EFI_STATUS mCapStatus;
STATIC BOOLEAN mProtocolAvailable;
STATIC BOOLEAN mPresent;
STATIC BOOLEAN mHaveHob;
STATIC BOOLEAN mExpectStop;
STATIC UINTN mCapCalls;
STATIC UINTN mFailPcr;
STATIC UINTN mCloseCalls;
STATIC CHAR8 mSerial[1024];
STATIC jmp_buf mStop;

EFI_STATUS EFIAPI ConfigureTpmPlatformHierarchy (VOID) { return mHierarchyStatus; }
VOID EFIAPI CpuDeadLoop (VOID) {
  assert_true (mExpectStop);
  assert_non_null (strstr (mSerial, "PCR cap failed, stopping"));
  longjmp (mStop, 1);
}
STATIC EFI_STATUS EFIAPI CloseEvent (EFI_EVENT Event) {
  assert_ptr_equal (Event, (VOID *)(UINTN)1);
  mCloseCalls++;
  return EFI_SUCCESS;
}
STATIC EFI_STATUS EFIAPI LocateProtocol (EFI_GUID *Guid, VOID *Registration, VOID **Interface) {
  assert_null (Registration);
  if (Guid == &gEfiDxeSmmReadyToLockProtocolGuid) {
    *Interface = &mBootServices;
    return EFI_SUCCESS;
  }
  assert_ptr_equal (Guid, &gEfiTcg2ProtocolGuid);
  if (!mProtocolAvailable) {
    return EFI_NOT_FOUND;
  }
  *Interface = &mTcg2;
  return EFI_SUCCESS;
}
STATIC EFI_STATUS EFIAPI GetCapability (EFI_TCG2_PROTOCOL *This, EFI_TCG2_BOOT_SERVICE_CAPABILITY *Capability) {
  assert_ptr_equal (This, &mTcg2);
  assert_int_equal (Capability->Size, sizeof (*Capability));
  Capability->TPMPresentFlag = mPresent;
  return mCapabilityStatus;
}
STATIC EFI_STATUS EFIAPI Cap (EFI_TCG2_PROTOCOL *This, UINT64 Flags, EFI_PHYSICAL_ADDRESS Data, UINT64 DataSize, EFI_TCG2_EVENT *Event) {
  UINT32 Value;
  assert_ptr_equal (This, &mTcg2);
  assert_int_equal (Flags, EFI_TCG2_EXTEND_ONLY);
  assert_int_equal (DataSize, sizeof (Value));
  memcpy (&Value, (VOID *)(UINTN)Data, sizeof (Value));
  assert_int_equal (Value, 1);
  assert_int_equal (Event->Size, OFFSET_OF (EFI_TCG2_EVENT, Event) + sizeof (Value));
  assert_int_equal (Event->Header.HeaderSize, sizeof (Event->Header));
  assert_int_equal (Event->Header.HeaderVersion, EFI_TCG2_EVENT_HEADER_VERSION);
  assert_int_equal (Event->Header.PCRIndex, mCapCalls);
  assert_int_equal (Event->Header.EventType, EV_SEPARATOR);
  assert_memory_equal (Event->Event, &Value, sizeof (Value));
  mCapCalls++;
  return Event->Header.PCRIndex == mFailPcr ? mCapStatus : EFI_SUCCESS;
}
EFI_EVENT EFIAPI EfiCreateProtocolNotifyEvent (EFI_GUID *Guid, EFI_TPL Tpl, EFI_EVENT_NOTIFY Notify, VOID *Context, VOID **Registration) {
  fail_msg ("unexpected event creation");
  return NULL;
}
VOID *EFIAPI GetFirstGuidHob (CONST EFI_GUID *Guid) { return mHaveHob ? &mHaveHob : NULL; }
EFI_STATUS EFIAPI PeiServicesGetBootMode (EFI_BOOT_MODE *Mode) { fail_msg ("unexpected boot-mode query"); return EFI_ABORTED; }
EFI_STATUS EFIAPI PeiServicesNotifyPpi (CONST EFI_PEI_NOTIFY_DESCRIPTOR *List) { fail_msg ("unexpected PEI registration"); return EFI_ABORTED; }
UINTN EFIAPI AsciiSPrint (CHAR8 *Buffer, UINTN Size, CONST CHAR8 *Format, ...) {
  va_list Args;
  CONST CHAR8 *Component;
  CONST CHAR8 *Decision;
  EFI_STATUS Status;
  assert_string_equal (Format, "TPM %a: %a (%r)\r\n");
  va_start (Args, Format);
  Component = va_arg (Args, CONST CHAR8 *);
  Decision = va_arg (Args, CONST CHAR8 *);
  Status = va_arg (Args, EFI_STATUS);
  va_end (Args);
  return snprintf (Buffer, Size, "TPM %s: %s (%llu)\r\n", Component, Decision, (unsigned long long)Status);
}
UINTN EFIAPI SerialPortWrite (UINT8 *Buffer, UINTN Size) {
  assert_true (strlen (mSerial) + Size < sizeof (mSerial));
  strncat (mSerial, (CHAR8 *)Buffer, Size);
  return Size;
}
UINTN EFIAPI Print (CONST CHAR16 *Format, ...) { fail_msg ("console absent"); return 0; }
STATIC VOID Reset (VOID) {
  mHierarchyStatus = EFI_SUCCESS;
  mCapabilityStatus = EFI_SUCCESS;
  mCapStatus = EFI_SUCCESS;
  mProtocolAvailable = TRUE;
  mPresent = TRUE;
  mHaveHob = TRUE;
  mExpectStop = FALSE;
  mRandomizeHierarchy = TRUE;
  mCapCalls = mCloseCalls = 0;
  mFailPcr = 0;
  mSerial[0] = '\0';
  mBootServices.LocateProtocol = LocateProtocol;
  mBootServices.CloseEvent = CloseEvent;
  mTcg2.GetCapability = GetCapability;
  mTcg2.HashLogExtendEvent = Cap;
}
STATIC VOID DxeUnsupported (VOID **State) {
  Reset ();
  mHierarchyStatus = EFI_UNSUPPORTED;
  SmmReadyToLockEventCallBack ((VOID *)(UINTN)1, NULL);
  assert_int_equal (mCloseCalls, 1);
  assert_int_equal (mCapCalls, 0);
  assert_non_null (strstr (mSerial, "hierarchy protection unsupported, skipping"));
}
STATIC VOID DxeAbsent (VOID **State) {
  Reset ();
  mHierarchyStatus = EFI_DEVICE_ERROR;
  mPresent = FALSE;
  SmmReadyToLockEventCallBack ((VOID *)(UINTN)1, NULL);
  assert_int_equal (mCapCalls, 0);
  assert_int_equal (mCloseCalls, 1);
  assert_non_null (strstr (mSerial, "TPM absent, skipping hierarchy protection"));
}
STATIC VOID DxeNotFound (VOID **State) {
  Reset ();
  mHierarchyStatus = EFI_NOT_FOUND;
  SmmReadyToLockEventCallBack ((VOID *)(UINTN)1, NULL);
  assert_int_equal (mCloseCalls, 1);
  assert_int_equal (mCapCalls, 0);
  assert_non_null (strstr (mSerial, "TPM absent, skipping hierarchy protection"));
}
STATIC VOID DxeFailureCapped (VOID **State) {
  Reset ();
  mHierarchyStatus = EFI_DEVICE_ERROR;
  SmmReadyToLockEventCallBack ((VOID *)(UINTN)1, NULL);
  assert_int_equal (mCapCalls, 8);
  assert_int_equal (mCloseCalls, 1);
  assert_non_null (strstr (mSerial, "hierarchy protection failed, PCRs 0-7 capped, continuing"));
}
STATIC VOID DxeCapabilityFailureCapped (VOID **State) {
  Reset ();
  mHierarchyStatus = EFI_DEVICE_ERROR;
  mCapabilityStatus = EFI_DEVICE_ERROR;
  SmmReadyToLockEventCallBack ((VOID *)(UINTN)1, NULL);
  assert_int_equal (mCapCalls, 8);
  assert_int_equal (mCloseCalls, 1);
}
STATIC VOID DxeCapFailureStops (VOID **State) {
  UINTN Pcr;
  for (Pcr = 0; Pcr < 8; Pcr++) {
    Reset ();
    mHierarchyStatus = EFI_DEVICE_ERROR;
    mCapStatus = EFI_DEVICE_ERROR;
    mFailPcr = Pcr;
    mExpectStop = TRUE;
    if (setjmp (mStop) == 0) {
      SmmReadyToLockEventCallBack ((VOID *)(UINTN)1, NULL);
      fail_msg ("failed cap must stop");
    }
    assert_int_equal (mCapCalls, Pcr + 1);
    assert_int_equal (mCloseCalls, 0);
  }
}
STATIC VOID DxeNoProtocol (VOID **State) {
  Reset ();
  mHierarchyStatus = EFI_DEVICE_ERROR;
  mProtocolAvailable = FALSE;
  SmmReadyToLockEventCallBack ((VOID *)(UINTN)1, NULL);
  assert_int_equal (mCapCalls, 0);
  assert_int_equal (mCloseCalls, 1);
  assert_non_null (strstr (mSerial, "hierarchy protection failed, PCR cap unavailable, continuing"));
}
STATIC VOID DxeSuccessOutcomes (VOID **State) {
  Reset ();
  SmmReadyToLockEventCallBack ((VOID *)(UINTN)1, NULL);
  assert_non_null (strstr (mSerial, "hierarchy authorization replaced"));
  Reset ();
  mRandomizeHierarchy = FALSE;
  SmmReadyToLockEventCallBack ((VOID *)(UINTN)1, NULL);
  assert_non_null (strstr (mSerial, "platform hierarchy disabled"));
  assert_int_equal (mCapCalls, 0);
}
STATIC VOID PeiUnsupported (VOID **State) {
  Reset ();
  mHierarchyStatus = EFI_UNSUPPORTED;
  assert_int_equal (PlatformInitEndOfPei (NULL, NULL, NULL), EFI_SUCCESS);
  assert_non_null (strstr (mSerial, "hierarchy protection unsupported, skipping"));
}
STATIC VOID PeiFailureReported (VOID **State) {
  Reset ();
  mHierarchyStatus = EFI_DEVICE_ERROR;
  assert_int_equal (PlatformInitEndOfPei (NULL, NULL, NULL), EFI_DEVICE_ERROR);
  assert_non_null (strstr (mSerial, "hierarchy protection failed, PCR cap unavailable, continuing"));
}
STATIC VOID PeiNoResumeFailure (VOID **State) {
  Reset ();
  mHaveHob = FALSE;
  assert_int_equal (PlatformInitEndOfPei (NULL, NULL, NULL), EFI_SUCCESS);
  assert_string_equal (mSerial, "");
}
int main (void) {
  const struct CMUnitTest Tests[] = {
    cmocka_unit_test (DxeUnsupported), cmocka_unit_test (DxeAbsent),
    cmocka_unit_test (DxeNotFound),
    cmocka_unit_test (DxeFailureCapped), cmocka_unit_test (DxeCapabilityFailureCapped),
    cmocka_unit_test (DxeCapFailureStops), cmocka_unit_test (DxeNoProtocol),
    cmocka_unit_test (DxeSuccessOutcomes), cmocka_unit_test (PeiUnsupported),
    cmocka_unit_test (PeiFailureReported), cmocka_unit_test (PeiNoResumeFailure)
  };
  return cmocka_run_group_tests (Tests, NULL, NULL);
}
