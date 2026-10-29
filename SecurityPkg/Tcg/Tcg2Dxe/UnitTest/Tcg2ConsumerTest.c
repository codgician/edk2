/** @file Check that a latched TPM cannot become an absent measurement service.
   SPDX-License-Identifier: BSD-2-Clause-Patent
 **/
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <cmocka.h>
#include "TestAdapter.h"
#include <DxeTpm2MeasureBootLib.c>

EFI_GUID gEfiCcMeasurementProtocolGuid;

STATIC EFI_STATUS EFIAPI
LocateMeasureProtocol (
  EFI_GUID *Guid,
  VOID *Registration,
  VOID **Interface
  )
{
  assert_null (Registration);
  if (Guid == &gEfiTcg2ProtocolGuid) {
    *Interface = &mTcg2Protocol;
    return EFI_SUCCESS;
  }

  assert_ptr_equal (Guid, &gEfiCcMeasurementProtocolGuid);
  return EFI_NOT_FOUND;
}

UINTN EFIAPI
GetDevicePathSize (
  CONST EFI_DEVICE_PATH_PROTOCOL *Path
  )
{
  assert_null (Path);
  return 0;
}

STATIC VOID
LaterImageStillMeasured (
  VOID **State
  )
{
  MEASURE_BOOT_PROTOCOLS Protocols;
  EFI_STATUS             Status;
  UINT8                  Image[4] = {
    0
  };

  ResetFixture ();
  BootServices.LocateProtocol = LocateMeasureProtocol;
  assert_int_equal (GetMeasureBootProtocols (&Protocols), EFI_SUCCESS);
  assert_ptr_equal (Protocols.Tcg2Protocol, &mTcg2Protocol);
  InjectStatus                = EFI_UNSUPPORTED;
  Status                      = Tcg2MeasurePeImage (&Protocols, (UINTN)Image, sizeof (Image), 0,
                                                    EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION, NULL);
  assert_int_equal (Status, EFI_UNSUPPORTED);
  assert_int_equal (CapCalls, 8);
  assert_int_equal (HashCalls, 1);

  /* This is the consumer's old skip-measurement path: it MUST still find Tcg2. */
  assert_int_equal (GetMeasureBootProtocols (&Protocols), EFI_SUCCESS);
  assert_ptr_equal (Protocols.Tcg2Protocol, &mTcg2Protocol);
  Status = Tcg2MeasurePeImage (&Protocols, (UINTN)Image, sizeof (Image), 0,
                               EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION, NULL);
  assert_int_equal (Status, EFI_DEVICE_ERROR);
  assert_int_equal (HashCalls, 1);
  assert_int_equal (CapCalls, 8);
  printf ("image consumer: first failure -> 8 PCR caps -> later image EFI_DEVICE_ERROR; TPM remains present\n");
}

int
main (
  void
  )
{
  const struct CMUnitTest Tests[] = {
    cmocka_unit_test (LaterImageStillMeasured)
  };
  return cmocka_run_group_tests (Tests, NULL, NULL);
}
