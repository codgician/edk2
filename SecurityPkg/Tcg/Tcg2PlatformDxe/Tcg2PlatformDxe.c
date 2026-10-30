/** @file
  Platform specific TPM2 component for configuring the Platform Hierarchy.

  Copyright (c) 2017 - 2019, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PcdLib.h>
#include <Library/PrintLib.h>
#include <Library/SerialPortLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/TpmPlatformHierarchyLib.h>
#include <Protocol/DxeSmmReadyToLock.h>
#include <Protocol/Tcg2Protocol.h>

/** Emit a hierarchy decision even when DEBUG output is disabled. **/
STATIC
VOID
ReportHierarchyStatus (
  IN CONST CHAR8  *Decision,
  IN EFI_STATUS   Status
  )
{
  CHAR8  Line[192];
  UINTN  Length;

  Length = AsciiSPrint (Line, sizeof (Line), "TPM %a: %a (%r)\r\n", "Tcg2PlatformDxe", Decision, Status);
  SerialPortWrite ((UINT8 *)Line, Length);
  if ((gST != NULL) && (gST->ConOut != NULL)) {
    Print (L"%a", Line);
  }
}

/** Protect recovery boot from hierarchy failures using the checked cap request. **/
STATIC
VOID
HandleHierarchyStatus (
  IN EFI_STATUS  Status
  )
{
  EFI_STATUS                       CapStatus;
  EFI_TCG2_PROTOCOL                *Tcg2;
  EFI_TCG2_BOOT_SERVICE_CAPABILITY  Capability;
  UINT8                            EventBuffer[OFFSET_OF (EFI_TCG2_EVENT, Event) + sizeof (UINT32)];
  EFI_TCG2_EVENT                   *Event;
  UINT32                           Error;

  if (!EFI_ERROR (Status)) {
    ReportHierarchyStatus (
      PcdGetBool (PcdRandomizePlatformHierarchy) ? "hierarchy authorization replaced" : "platform hierarchy disabled",
      Status
      );
    return;
  }

  if (Status == EFI_UNSUPPORTED) {
    ReportHierarchyStatus ("hierarchy protection unsupported, skipping", Status);
    return;
  }

  if (Status == EFI_NOT_FOUND) {
    ReportHierarchyStatus ("TPM absent, skipping hierarchy protection", Status);
    return;
  }

  CapStatus = gBS->LocateProtocol (&gEfiTcg2ProtocolGuid, NULL, (VOID **)&Tcg2);
  if (EFI_ERROR (CapStatus)) {
    ReportHierarchyStatus ("hierarchy protection failed, PCR cap unavailable, continuing", Status);
    return;
  }

  ZeroMem (&Capability, sizeof (Capability));
  Capability.Size = sizeof (Capability);
  CapStatus       = Tcg2->GetCapability (Tcg2, &Capability);
  if (!EFI_ERROR (CapStatus) && !Capability.TPMPresentFlag) {
    ReportHierarchyStatus ("TPM absent, skipping hierarchy protection", Status);
    return;
  }

  // Request every PCR explicitly for compatibility with generic Tcg2 protocols.
  ZeroMem (EventBuffer, sizeof (EventBuffer));
  Event                       = (EFI_TCG2_EVENT *)EventBuffer;
  Event->Size                 = sizeof (EventBuffer);
  Event->Header.HeaderSize    = sizeof (Event->Header);
  Event->Header.HeaderVersion = EFI_TCG2_EVENT_HEADER_VERSION;
  Event->Header.EventType     = EV_SEPARATOR;
  Error                       = 1;
  CopyMem (Event->Event, &Error, sizeof (Error));
  for (Event->Header.PCRIndex = 0; Event->Header.PCRIndex < 8; Event->Header.PCRIndex++) {
    CapStatus = Tcg2->HashLogExtendEvent (
                        Tcg2,
                        EFI_TCG2_EXTEND_ONLY,
                        (EFI_PHYSICAL_ADDRESS)(UINTN)&Error,
                        sizeof (Error),
                        Event
                        );
    if (EFI_ERROR (CapStatus)) {
      ReportHierarchyStatus ("hierarchy protection failed", Status);
      ReportHierarchyStatus ("PCR cap failed, stopping", CapStatus);
      for (;;) {
        CpuDeadLoop ();
      }
    }
  }

  ReportHierarchyStatus ("hierarchy protection failed, PCRs 0-7 capped, continuing", Status);
}

/**
   This callback function will run at the SmmReadyToLock event.

   Configuration of the TPM's Platform Hierarchy Authorization Value (platformAuth)
   and Platform Hierarchy Authorization Policy (platformPolicy) can be defined through this function.

  @param  Event   Pointer to this event
  @param  Context Event hanlder private data
 **/
VOID
EFIAPI
SmmReadyToLockEventCallBack (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS  Status;
  VOID        *Interface;

  //
  // Try to locate it because EfiCreateProtocolNotifyEvent will trigger it once when registration.
  // Just return if it is not found.
  //
  Status = gBS->LocateProtocol (
                  &gEfiDxeSmmReadyToLockProtocolGuid,
                  NULL,
                  &Interface
                  );
  if (EFI_ERROR (Status)) {
    return;
  }

  Status = ConfigureTpmPlatformHierarchy ();
  HandleHierarchyStatus (Status);

  gBS->CloseEvent (Event);
}

/**
   The driver's entry point. Will register a function for callback during SmmReadyToLock event to
   configure the TPM's platform authorization.

   @param[in] ImageHandle  The firmware allocated handle for the EFI image.
   @param[in] SystemTable  A pointer to the EFI System Table.

   @retval EFI_SUCCESS     The entry point is executed successfully.
   @retval other           Some error occurs when executing this entry point.
**/
EFI_STATUS
EFIAPI
Tcg2PlatformDxeEntryPoint (
  IN    EFI_HANDLE        ImageHandle,
  IN    EFI_SYSTEM_TABLE  *SystemTable
  )
{
  VOID       *Registration;
  EFI_EVENT  Event;

  Event = EfiCreateProtocolNotifyEvent (
            &gEfiDxeSmmReadyToLockProtocolGuid,
            TPL_CALLBACK,
            SmmReadyToLockEventCallBack,
            NULL,
            &Registration
            );

  ASSERT (Event != NULL);

  return EFI_SUCCESS;
}
