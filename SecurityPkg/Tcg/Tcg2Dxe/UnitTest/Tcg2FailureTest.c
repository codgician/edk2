#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "TestAdapter.h"

static void
ExtendError (
  void **State
  )
{
  ResetFixture ();
  InjectStatus = EFI_DEVICE_ERROR;
  assert_int_equal (Measure (EFI_TCG2_EXTEND_ONLY, EV_EFI_BOOT_SERVICES_APPLICATION), EFI_DEVICE_ERROR);
  assert_int_equal (CapCalls, 8);
  assert_true (mTcgDxeData.BsCap.TPMPresentFlag);
  InjectStatus = EFI_SUCCESS;
  assert_int_equal (Measure (EFI_TCG2_EXTEND_ONLY, EV_EFI_BOOT_SERVICES_APPLICATION), EFI_DEVICE_ERROR);
  assert_int_equal (CapCalls, 8);
  assert_int_equal (HashCalls, 1);
}
static void
HashError (
  void **State
  )
{
  ResetFixture ();
  InjectStatus = EFI_OUT_OF_RESOURCES;
  assert_int_equal (Measure (EFI_TCG2_EXTEND_ONLY, EV_EFI_BOOT_SERVICES_APPLICATION), EFI_OUT_OF_RESOURCES);
  assert_int_equal (CapCalls, 8);
  assert_true (mTcgDxeData.BsCap.TPMPresentFlag);
}
static void
PeError (
  void **State
  )
{
  ResetFixture ();
  InjectStatus = EFI_UNSUPPORTED;
  assert_int_equal (Measure (PE_COFF_IMAGE, EV_EFI_BOOT_SERVICES_APPLICATION), EFI_UNSUPPORTED);
  assert_int_equal (CapCalls, 8);
}
static void
LogFull (
  void **State
  )
{
  ResetFixture ();
  mTcgDxeData.EventLogAreaStruct[1].Laml = 0;
  assert_int_equal (Measure (0, EV_EFI_BOOT_SERVICES_APPLICATION), EFI_VOLUME_FULL);
  assert_int_equal (CapCalls, 8);
}
static void
LogTruncated (
  void **State
  )
{
  ResetFixture ();
  mTcgDxeData.EventLogAreaStruct[1].EventLogTruncated = TRUE;
  assert_int_equal (Measure (0, EV_NO_ACTION), EFI_VOLUME_FULL);
  assert_int_equal (CapCalls, 8);
}
static void
FinalFull (
  void **State
  )
{
  ResetFixture ();
  mTcgDxeData.GetEventLogCalled[1]            = TRUE;
  mTcgDxeData.FinalEventsTable[1]             = &FinalTable;
  mTcgDxeData.FinalEventLogAreaStruct[1].Laml = 0;
  assert_int_equal (Measure (0, EV_EFI_BOOT_SERVICES_APPLICATION), EFI_VOLUME_FULL);
  assert_int_equal (CapCalls, 8);
}
static void
CapFailure (
  void **State
  )
{
  ResetFixture ();
  InjectStatus = EFI_DEVICE_ERROR;
  FailCap      = 3;
  ExpectStop   = TRUE;
  if (setjmp (Stop) == 0) {
    Measure (EFI_TCG2_EXTEND_ONLY, EV_EFI_BOOT_SERVICES_APPLICATION);
    fail_msg ("Unproven PCR cap returned to caller");
  }
  assert_int_equal (CapCalls, 3);
}
static void
AllBanks (
  void **State
  )
{
  ResetFixture ();
  ActualBanks  = 0x1f;
  InjectStatus = EFI_DEVICE_ERROR;
  Measure (EFI_TCG2_EXTEND_ONLY, EV_EFI_BOOT_SERVICES_APPLICATION);
  assert_int_equal (CapCalls, 8);
}
static void
InitialAbsence (
  void **State
  )
{
  ResetFixture ();
  mTcgDxeData.BsCap.TPMPresentFlag = FALSE;
  assert_int_equal (Measure (0, EV_EFI_BOOT_SERVICES_APPLICATION), EFI_DEVICE_ERROR);
  assert_int_equal (HashCalls, 0);
  assert_int_equal (CapCalls, 0);
}
static void
HeaderOverflow (
  void **State
  )
{
  EFI_TCG2_EVENT    Event;
  EFI_TCG2_PROTOCOL This;
  ResetFixture ();
  ZeroMem (&Event, sizeof(Event));
  Event.Size                 = sizeof(Event);
  Event.Header.HeaderSize    = MAX_UINT32;
  Event.Header.HeaderVersion = EFI_TCG2_EVENT_HEADER_VERSION;
  Event.Header.EventType     = EV_EFI_ACTION;
  assert_int_equal (Tcg2HashLogExtendEvent (&This, EFI_TCG2_EXTEND_ONLY, (UINTN)&Event, sizeof(Event), &Event), EFI_INVALID_PARAMETER);
  assert_int_equal (HashCalls, 0);
}
static void
ExplicitSeparator (
  void **State
  )
{
  struct {
    UINT32 Size;
    EFI_TCG2_EVENT_HEADER Header;
    UINT8 Data[4];
  }
  Event;
  ResetFixture ();
  ZeroMem (&Event, sizeof(Event));
  Event.Size                 = sizeof(UINT32) + sizeof(Event.Header) + sizeof(Event.Data);
  Event.Header.HeaderSize    = sizeof(Event.Header);
  Event.Header.HeaderVersion = EFI_TCG2_EVENT_HEADER_VERSION;
  Event.Header.EventType     = EV_SEPARATOR;
  Event.Data[0]              = 1;
  for (UINTN Pcr = 0; Pcr < 8; ++Pcr) {
    Event.Header.PCRIndex = Pcr;
    assert_int_equal (Tcg2HashLogExtendEvent (&mTcg2Protocol, EFI_TCG2_EXTEND_ONLY, (UINTN)Event.Data, 4, (EFI_TCG2_EVENT *)&Event), EFI_SUCCESS);
  }
  assert_int_equal (CapCalls, 8);
  assert_int_equal (HashCalls, 0);
  EFI_TCG2_BOOT_SERVICE_CAPABILITY Cap = {
    .Size = sizeof(Cap)
  };
  assert_int_equal (Tcg2GetCapability (&mTcg2Protocol, &Cap), EFI_SUCCESS);
  assert_true (Cap.TPMPresentFlag);
  assert_int_equal (Measure (0, EV_EFI_BOOT_SERVICES_APPLICATION), EFI_SUCCESS);
  assert_int_equal (HashCalls, 1);
  assert_int_equal (CapCalls, 8);
  InjectStatus = EFI_DEVICE_ERROR;
  assert_int_equal (Measure (EFI_TCG2_EXTEND_ONLY, EV_EFI_BOOT_SERVICES_APPLICATION), EFI_DEVICE_ERROR);
  assert_int_equal (CapCalls, 8);
  InjectStatus = EFI_SUCCESS;
  assert_int_equal (Measure (EFI_TCG2_EXTEND_ONLY, EV_EFI_BOOT_SERVICES_APPLICATION), EFI_DEVICE_ERROR);
  assert_int_equal (HashCalls, 2);
}
static void
BankFailures (
  void **State
  )
{
  for (UINTN Kind = 0; Kind < 5; ++Kind) {
    ResetFixture ();
    if (Kind == 0){
      CapabilityStatus = EFI_DEVICE_ERROR;
    }
    else if (Kind == 4){
      ActualBanks = 0;
    }
    else{
      BadSelection = Kind;
    }
    InjectStatus = EFI_DEVICE_ERROR;
    ExpectStop   = TRUE;
    if (setjmp (Stop) == 0) {
      Measure (EFI_TCG2_EXTEND_ONLY, EV_EFI_ACTION);
      fail_msg ("Unprovable bank selection released control");
    }
    assert_int_equal (CapCalls, 0);
  }
}
static void
InitLogFailure (
  void **State
  )
{
  ResetFixture ();
  AllowInit                                = TRUE;
  gEfiTpmDeviceInstanceTpm20DtpmGuid.Data1 = 1;
  assert_int_equal (DriverEntry (NULL, NULL), EFI_SUCCESS);
  assert_int_equal (CapCalls, 8);
  assert_true (ProtocolPublished);
  assert_true (mTcgDxeData.BsCap.TPMPresentFlag);
  assert_true (mTcgDxeData.MeasurementFailed);
  assert_int_equal (Measure (0, EV_EFI_BOOT_SERVICES_APPLICATION), EFI_DEVICE_ERROR);
  assert_int_equal (HashCalls, 0);
  assert_non_null (strstr (SerialOutput, "PCRs 0-7 capped"));
}
static void
InitAbsence (
  void **State
  )
{
  ResetFixture ();
  AllowInit                                = TRUE;
  RequestStatus                            = EFI_NOT_FOUND;
  gEfiTpmDeviceInstanceTpm20DtpmGuid.Data1 = 1;
  assert_int_equal (DriverEntry (NULL, NULL), EFI_NOT_FOUND);
  assert_int_equal (CapCalls, 0);
}

static void
InitSetupFailures (
  void **State
  )
{
  for (UINTN Failure = 1; Failure <= 8; ++Failure) {
    ResetFixture ();
    AllowInit = TRUE;
    FailPage = 0;
    FailEvent = Failure;
    if (Failure == 7) {
      TableStatus = EFI_OUT_OF_RESOURCES;
    } else if (Failure == 8) {
      FailPage = 2;
    }
    gEfiTpmDeviceInstanceTpm20DtpmGuid.Data1 = 1;
    assert_int_equal (DriverEntry (NULL, NULL), EFI_SUCCESS);
    assert_int_equal (CapCalls, 8);
    assert_true (ProtocolPublished);
    assert_true (mTcgDxeData.BsCap.TPMPresentFlag);
    assert_int_equal (Measure (0, EV_EFI_BOOT_SERVICES_APPLICATION), EFI_DEVICE_ERROR);
    assert_non_null (strstr (SerialOutput, "continuing"));
    OnReadyToBoot (NULL, NULL);
    OnExitBootServices (NULL, NULL);
    OnExitBootServicesFailed (NULL, NULL);
    MeasureSecureBootPolicy (NULL, NULL);
    assert_int_equal (HashCalls, 0);
  }
}

static void
InitDiscoveryRecovery (
  void **State
  )
{
  for (UINTN Failure = 0; Failure < 3; ++Failure) {
    ResetFixture ();
    AllowInit = TRUE;
    if (Failure == 0) {
      BitmapStatus = EFI_DEVICE_ERROR;
    } else if (Failure == 1) {
      RawFailures = 1;
    } else {
      PeiError = TRUE;
    }
    gEfiTpmDeviceInstanceTpm20DtpmGuid.Data1 = 1;
    assert_int_equal (DriverEntry (NULL, NULL), EFI_SUCCESS);
    assert_int_equal (CapCalls, 8);
    assert_true (ProtocolPublished);
    assert_int_equal (mTcgDxeData.BsCap.ActivePcrBanks, ActualBanks);
    assert_int_equal (mTcgDxeData.BsCap.SupportedEventLogs, 0);
    assert_int_equal (HashCalls, 0);
  }
}

static void
CapDiagnostic (
  void **State
  )
{
  ResetFixture ();
  InjectStatus = EFI_DEVICE_ERROR;
  FailCap = 3;
  ExpectStop = TRUE;
  if (setjmp (Stop) == 0) {
    Measure (EFI_TCG2_EXTEND_ONLY, EV_EFI_BOOT_SERVICES_APPLICATION);
    fail_msg ("Incomplete cap continued");
  }
  assert_non_null (strstr (SerialOutput, "TPM Tcg2Dxe:"));
  assert_non_null (strstr (SerialOutput, "stopping"));
}

static void
DegradedLogTruth (
  void **State
  )
{
  EFI_PHYSICAL_ADDRESS Location = 1;
  EFI_PHYSICAL_ADDRESS Last = 1;
  BOOLEAN Truncated = FALSE;
  ResetFixture ();
  AllowInit = TRUE;
  gEfiTpmDeviceInstanceTpm20DtpmGuid.Data1 = 1;
  assert_int_equal (DriverEntry (NULL, NULL), EFI_SUCCESS);
  assert_int_equal (mTcgDxeData.BsCap.SupportedEventLogs, 0);
  assert_int_equal (Tcg2GetEventLog (&mTcg2Protocol, EFI_TCG2_EVENT_LOG_FORMAT_TCG_2,
                                    &Location, &Last, &Truncated), EFI_DEVICE_ERROR);
  assert_int_equal (Location, 0);
  assert_int_equal (Last, 0);
  assert_true (Truncated);
}
static void
HobBoundary (
  void **State
  )
{
  UINT8 Event[50] = {
    0
  };
  ResetFixture ();
  WriteUnaligned32 ((UINT32 *)(Event + 8), 1);
  WriteUnaligned16 ((UINT16 *)(Event + 12), TPM_ALG_SHA256);
  WriteUnaligned32 ((UINT32 *)(Event + 46), 0);
  assert_int_equal (ValidateEventHob (EFI_TCG2_EVENT_LOG_FORMAT_TCG_2, Event, sizeof(Event)), EFI_SUCCESS);
  for (UINTN Size = 0; Size < sizeof(Event); ++Size){
    assert_int_equal (ValidateEventHob (EFI_TCG2_EVENT_LOG_FORMAT_TCG_2, Event, Size), EFI_COMPROMISED_DATA);
  }
}
/** PI HOB lengths include up to seven bytes of allocation padding. **/
STATIC VOID
HobAllocationPadding (
  VOID **State
  )
{
  UINT8 Event[64] = { 0 };

  ResetFixture ();
  WriteUnaligned32 ((UINT32 *)(Event + 8), 1);
  WriteUnaligned16 ((UINT16 *)(Event + 12), TPM_ALG_SHA256);
  WriteUnaligned32 ((UINT32 *)(Event + 46), 0);
  assert_int_equal (ValidateEventHob (EFI_TCG2_EVENT_LOG_FORMAT_TCG_2, Event, 56), EFI_SUCCESS);
  assert_int_equal (ValidateEventHob (EFI_TCG2_EVENT_LOG_FORMAT_TCG_2, Event, 64), EFI_COMPROMISED_DATA);

  ZeroMem (Event, sizeof (Event));
  WriteUnaligned32 ((UINT32 *)(Event + OFFSET_OF (TCG_PCR_EVENT_HDR, EventSize)), 1);
  assert_int_equal (ValidateEventHob (EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2, Event, 40), EFI_SUCCESS);
  assert_int_equal (ValidateEventHob (EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2, Event, 48), EFI_COMPROMISED_DATA);
}

static void
InitUnknownBank (
  void **State
  )
{
  ResetFixture ();
  AllowInit                                = TRUE;
  ExpectStop                               = TRUE;
  BadSelection                             = 1;
  gEfiTpmDeviceInstanceTpm20DtpmGuid.Data1 = 1;
  if (setjmp (Stop) == 0) {
    DriverEntry (NULL, NULL);
    fail_msg ("Unknown active bank released control");
  }
  assert_int_equal (PageCalls, 0);
  assert_int_equal (CapCalls, 0);
  assert_int_equal (HashCalls, 0);
  assert_true (mTcgDxeData.MeasurementFailed);
  assert_true (mTcgDxeData.BsCap.TPMPresentFlag);
}

static void
InitMetadataFailure (
  void **State
  )
{
  for (UINTN Failure = 0; Failure < 2; ++Failure) {
    ResetFixture ();
    AllowInit = TRUE;
    FailPage = 0;
    if (Failure == 0) {
      ManufactureStatus = EFI_DEVICE_ERROR;
    } else {
      MaxSizeStatus = EFI_DEVICE_ERROR;
    }
    gEfiTpmDeviceInstanceTpm20DtpmGuid.Data1 = 1;
    assert_int_equal (DriverEntry (NULL, NULL), EFI_SUCCESS);
    assert_int_equal (CapCalls, 8);
    assert_true (ProtocolPublished);
    assert_int_equal (Measure (0, EV_EFI_BOOT_SERVICES_APPLICATION), EFI_DEVICE_ERROR);
  }
}

static void
ConsoleDecisionVisible (
  void **State
  )
{
  EFI_SYSTEM_TABLE Table = { 0 };
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL Output = { 0 };

  ResetFixture ();
  Table.ConOut = &Output;
  gST = &Table;
  InjectStatus = EFI_DEVICE_ERROR;
  assert_int_equal (Measure (EFI_TCG2_EXTEND_ONLY, EV_EFI_BOOT_SERVICES_APPLICATION), EFI_DEVICE_ERROR);
  assert_string_equal (ConsoleOutput, SerialOutput);
  assert_non_null (strstr (ConsoleOutput, "measurement failed, PCRs 0-7 capped, continuing (Device Error)"));
  gST = NULL;
}

static void
ProtocolPublicationUnavailable (
  void **State
  )
{
  ResetFixture ();
  AllowInit = TRUE;
  FailPage = 0;
  FailPublish = TRUE;
  gEfiTpmDeviceInstanceTpm20DtpmGuid.Data1 = 1;
  assert_int_equal (DriverEntry (NULL, NULL), EFI_SUCCESS);
  assert_int_equal (CapCalls, 8);
  assert_false (ProtocolPublished);
  assert_true (mTcgDxeData.BsCap.TPMPresentFlag);
  assert_non_null (strstr (SerialOutput, "capped-degraded protocol unavailable"));
  OnReadyToBoot (NULL, NULL);
  assert_int_equal (HashCalls, 0);
}

int
main (
  void
  )
{
  const struct CMUnitTest Tests[] = {
    cmocka_unit_test (ExtendError), cmocka_unit_test (HashError), cmocka_unit_test (PeError),
    cmocka_unit_test (LogFull), cmocka_unit_test (LogTruncated), cmocka_unit_test (FinalFull),
    cmocka_unit_test (CapFailure), cmocka_unit_test (AllBanks), cmocka_unit_test (InitialAbsence),
    cmocka_unit_test (HeaderOverflow), cmocka_unit_test (ExplicitSeparator),
    cmocka_unit_test (BankFailures), cmocka_unit_test (InitLogFailure),
    cmocka_unit_test (InitAbsence), cmocka_unit_test (HobBoundary),
    cmocka_unit_test (InitUnknownBank), cmocka_unit_test (HobAllocationPadding),
    cmocka_unit_test (InitSetupFailures), cmocka_unit_test (InitDiscoveryRecovery),
    cmocka_unit_test (CapDiagnostic), cmocka_unit_test (DegradedLogTruth),
    cmocka_unit_test (InitMetadataFailure), cmocka_unit_test (ConsoleDecisionVisible),
    cmocka_unit_test (ProtocolPublicationUnavailable)
  };
  return cmocka_run_group_tests (Tests, NULL, NULL);
}
