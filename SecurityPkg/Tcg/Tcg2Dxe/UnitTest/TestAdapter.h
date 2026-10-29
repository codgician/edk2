#include <assert.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include "../Tcg2Dxe.c"
#include "../MeasureBootPeCoff.c"

EFI_GUID                           gTcgEventEntryHobGuid;
EFI_GUID                           gTcgEvent2EntryHobGuid;
EFI_GUID                           gEfiGlobalVariableGuid;
EFI_GUID                           gEfiImageSecurityDatabaseGuid;
EFI_BOOT_SERVICES *                gBS;
static EFI_BOOT_SERVICES           BootServices;
static EFI_STATUS                  InjectStatus;
static UINT32                      ActualBanks;
static UINTN                       HashCalls, CapCalls;
static INTN                        FailCap;
static jmp_buf                     Stop;
static BOOLEAN                     ExpectStop;
static UINT8                       Log[4096], FinalLog[4096];
static EFI_TCG2_FINAL_EVENTS_TABLE FinalTable;
static BOOLEAN                     AllowInit;
static EFI_STATUS                  RequestStatus, CapabilityStatus;
static UINTN                       BadSelection;
static UINTN                       PageCalls;
static EFI_STATUS EFIAPI
AllocatePagesFail (
  EFI_ALLOCATE_TYPE Type,
  EFI_MEMORY_TYPE Memory,
  UINTN Pages,
  EFI_PHYSICAL_ADDRESS *Address
  )
{
  assert (AllowInit);
  ++PageCalls;
  return EFI_OUT_OF_RESOURCES;
}

static EFI_TPL EFIAPI
Raise (
  EFI_TPL Tpl
  )
{
  return TPL_APPLICATION;
}
static VOID EFIAPI
Restore (
  EFI_TPL Tpl
  )
{
}
VOID EFIAPI
CpuDeadLoop (
  VOID
  )
{
  assert (ExpectStop);
  longjmp (Stop, 1);
}
EFI_STATUS EFIAPI
Tpm2GetCapabilitySupportedAndActivePcrs (
  UINT32 *Supported,
  UINT32 *Active
  )
{
  *Supported = *Active = ActualBanks;
  return EFI_SUCCESS;
}
EFI_STATUS EFIAPI
Tpm2GetCapabilityPcrs (
  TPML_PCR_SELECTION *Pcrs
  )
{
  static const TPMI_ALG_HASH Algs[] = { TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512, TPM_ALG_SM3_256 };
  if (EFI_ERROR (CapabilityStatus)){
    return CapabilityStatus;
  }
  ZeroMem (Pcrs, sizeof(*Pcrs));
  for (UINTN I = 0; I < 5; ++I) {
    if ((ActualBanks & GetHashMaskFromAlgo (Algs[I])) != 0) {
      TPMS_PCR_SELECTION *Selection = &Pcrs->pcrSelections[Pcrs->count++];
      Selection->hash         = Algs[I];
      Selection->sizeofSelect = 3;
      Selection->pcrSelect[0] = 0xff;
    }
  }
  if (BadSelection == 1){
    Pcrs->pcrSelections[0].hash = 0xffff;
  }
  if (BadSelection == 2){
    Pcrs->pcrSelections[0].pcrSelect[0] = 0x7f;
  }
  if (BadSelection == 3){
    Pcrs->count = HASH_COUNT + 1;
  }
  return EFI_SUCCESS;
}
EFI_STATUS EFIAPI
Tpm2PcrExtend (
  TPMI_DH_PCR Pcr,
  TPML_DIGEST_VALUES *Digests
  )
{
  UINT32 Seen = 0;
  static const UINT8 Sha256[] = {
    0x67, 0xab, 0xdd, 0x72, 0x10, 0x24, 0xf0, 0xff,
    0x4e, 0x0b, 0x3f, 0x4c, 0x2f, 0xc1, 0x3b, 0xc5,
    0xba, 0xd4, 0x2d, 0x0b, 0x78, 0x51, 0xd4, 0x56,
    0xd8, 0x8d, 0x20, 0x3d, 0x15, 0xaa, 0xa4, 0x50
  };
  static const UINT8 Sha384[] = {
    0x72, 0x10, 0xaf, 0x19, 0x14, 0x5e, 0xc2, 0xa8,
    0xe2, 0x50, 0xa7, 0xfe, 0x8e, 0x9e, 0xee, 0xac,
    0x13, 0x01, 0xe5, 0x24, 0xda, 0xab, 0x82, 0x36,
    0x6c, 0x36, 0xbe, 0x61, 0x4d, 0xc3, 0x54, 0x02,
    0xa2, 0x89, 0x10, 0x1e, 0x48, 0xca, 0xd6, 0x1c,
    0x45, 0x33, 0x7f, 0x2f, 0x32, 0xc1, 0x4f, 0xdc
  };
  assert (Pcr == CapCalls);
  assert (Digests->count > 0 && Digests->count <= HASH_COUNT);
  for (UINTN I = 0; I < Digests->count; ++I) {
    UINT32 Bit = GetHashMaskFromAlgo (Digests->digests[I].hashAlg);
    assert (Bit != 0 && (Seen & Bit) == 0);
    if (Digests->digests[I].hashAlg == TPM_ALG_SHA256) {
      assert (CompareMem (&Digests->digests[I].digest, Sha256, sizeof (Sha256)) == 0);
    } else if (Digests->digests[I].hashAlg == TPM_ALG_SHA384) {
      assert (CompareMem (&Digests->digests[I].digest, Sha384, sizeof (Sha384)) == 0);
    }
    Seen |= Bit;
  }
  assert (Seen == ActualBanks);
  ++CapCalls;
  return FailCap == (INTN)CapCalls ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}
EFI_STATUS EFIAPI
HashAndExtend (
  TPMI_DH_PCR Pcr,
  VOID *Data,
  UINTN Size,
  TPML_DIGEST_VALUES *Digests
  )
{
  ++HashCalls;
  ZeroMem (Digests, sizeof(*Digests));
  Digests->count              = 1;
  Digests->digests[0].hashAlg = TPM_ALG_SHA256;
  return InjectStatus;
}
RETURN_STATUS EFIAPI
PeCoffLoaderGetImageInfo (
  PE_COFF_LOADER_IMAGE_CONTEXT *Context
  )
{
  assert (InjectStatus == EFI_UNSUPPORTED);
  ++HashCalls;
  return InjectStatus;
}
EFI_STATUS EFIAPI
HashStart (
  HASH_HANDLE *Handle
  )
{
  abort ();
}
EFI_STATUS EFIAPI
HashUpdate (
  HASH_HANDLE Handle,
  VOID *Data,
  UINTN Size
  )
{
  abort ();
}
EFI_STATUS EFIAPI
HashCompleteAndExtend (
  HASH_HANDLE Handle,
  TPMI_DH_PCR Pcr,
  VOID *Data,
  UINTN Size,
  TPML_DIGEST_VALUES *Digests
  )
{
  abort ();
}
EFI_STATUS EFIAPI
ReportStatusCode (
  EFI_STATUS_CODE_TYPE Type,
  EFI_STATUS_CODE_VALUE Value
  )
{
  return EFI_SUCCESS;
}

static VOID
ResetFixture (
  VOID
  )
{
  ZeroMem (&mTcgDxeData, sizeof(mTcgDxeData));
  mTcgDxeData.BsCap.TPMPresentFlag            = TRUE;
  mTcgDxeData.BsCap.Size                      = sizeof(mTcgDxeData.BsCap);
  mTcgDxeData.BsCap.ActivePcrBanks            = EFI_TCG2_BOOT_HASH_ALG_SHA256;
  mTcgDxeData.BsCap.SupportedEventLogs        = EFI_TCG2_EVENT_LOG_FORMAT_TCG_2;
  mTcgDxeData.EventLogAreaStruct[1].Lasa      = (UINTN)Log;
  mTcgDxeData.EventLogAreaStruct[1].Laml      = sizeof(Log);
  mTcgDxeData.FinalEventLogAreaStruct[1].Lasa = (UINTN)FinalLog;
  mTcgDxeData.FinalEventLogAreaStruct[1].Laml = sizeof(FinalLog);
  ActualBanks                                 = EFI_TCG2_BOOT_HASH_ALG_SHA256 | EFI_TCG2_BOOT_HASH_ALG_SHA384;
  InjectStatus                                = EFI_SUCCESS;
  HashCalls                                   = CapCalls = 0;
  FailCap                                     = -1;
  ExpectStop                                  = FALSE;
  AllowInit                                   = FALSE;
  RequestStatus                               = CapabilityStatus = EFI_SUCCESS;
  BadSelection                                = 0;
  PageCalls                                   = 0;
  BootServices.AllocatePages                  = AllocatePagesFail;
  BootServices.RaiseTPL                       = Raise;
  BootServices.RestoreTPL                     = Restore;
  gBS                                         = &BootServices;
}
static EFI_STATUS
Measure (
  UINT64 Flags,
  UINT32 EventType
  )
{
  struct {
    UINT32 Size;
    EFI_TCG2_EVENT_HEADER Header;
    UINT8 Data[4];
  }
  Event;
  EFI_TCG2_PROTOCOL This;
  ZeroMem (&Event, sizeof(Event));
  Event.Size                 = sizeof(Event);
  Event.Header.HeaderSize    = sizeof(Event.Header);
  Event.Header.HeaderVersion = EFI_TCG2_EVENT_HEADER_VERSION;
  Event.Header.PCRIndex      = 4;
  Event.Header.EventType     = EventType;
  return Tcg2HashLogExtendEvent (&This, Flags, (UINTN)Event.Data, sizeof(Event.Data), (EFI_TCG2_EVENT *)&Event);
}
UINT16 EFIAPI
ReadUnaligned16 (
  CONST UINT16 *P
  )
{
  UINT16 V;
  CopyMem (&V, (CONST VOID *)(UINTN)P, 2);
  return V;
}
UINT32 EFIAPI
ReadUnaligned32 (
  CONST UINT32 *P
  )
{
  UINT32 V;
  CopyMem (&V, (CONST VOID *)(UINTN)P, 4);
  return V;
}
UINT32 EFIAPI
WriteUnaligned32 (
  UINT32 *P,
  UINT32 V
  )
{
  CopyMem ((VOID *)(UINTN)P, &V, 4);
  return V;
}
BOOLEAN EFIAPI
ReportProgressCodeEnabled (
  VOID
  )
{
  return FALSE;
}
BOOLEAN EFIAPI
ReportErrorCodeEnabled (
  VOID
  )
{
  return FALSE;
}
BOOLEAN EFIAPI
ReportDebugCodeEnabled (
  VOID
  )
{
  return FALSE;
}
EFI_STATUS EFIAPI
Tpm2SubmitCommand (
  UINT32 A,
  UINT8 *B,
  UINT32 *C,
  UINT8 *D
  )
{
  abort ();
}
UINT32 EFIAPI
Tcg2PhysicalPresenceLibSubmitRequestToPreOSFunction (
  UINT32 A,
  UINT32 B
  )
{
  abort ();
}
UINT32 EFIAPI
Tcg2PhysicalPresenceLibReturnOperationResponseToOsFunction (
  UINT32 *A,
  UINT32 *B
  )
{
  abort ();
}
EFI_GUID gEfiMpServiceProtocolGuid, gEfiVariableWriteArchProtocolGuid, gEfiResetNotificationProtocolGuid;
EFI_GUID gEfiTcg2ProtocolGuid, gEfiTcg2FinalEventsTableGuid, gTpmErrorHobGuid;
EFI_GUID gTpm2StartupLocalityHobGuid, gTcg800155PlatformIdEventHobGuid;
EFI_GUID gEfiTpmDeviceInstanceNoneGuid, gEfiTpmDeviceInstanceTpm12Guid, gEfiTpmDeviceInstanceTpm20DtpmGuid;
EFI_GUID gEfiEventExitBootServicesGuid, gEventExitBootServicesFailedGuid;
VOID *EFIAPI
GetHobList (
  VOID
  )
{
  assert (AllowInit);
  return &FinalTable;
}
VOID *EFIAPI
GetNextGuidHob (
  CONST EFI_GUID *Guid,
  CONST VOID *Hob
  )
{
  assert (AllowInit);
  return NULL;
}
VOID *EFIAPI
GetFirstGuidHob (
  CONST EFI_GUID *Guid
  )
{
  assert (AllowInit);
  return NULL;
}
EFI_STATUS EFIAPI
GetVariable2 (
  CONST CHAR16 *Name,
  CONST EFI_GUID *Guid,
  VOID **Value,
  UINTN *Size
  )
{
  abort ();
}
UINTN EFIAPI
UnicodeSPrint (
  CHAR16 *Buffer,
  UINTN Size,
  CONST CHAR16 *Format,
  ...
  )
{
  abort ();
}
BOOLEAN EFIAPI
PerformanceMeasurementEnabled (
  VOID
  )
{
  return FALSE;
}
RETURN_STATUS EFIAPI
StartPerformanceMeasurementEx (
  CONST VOID *H,
  CONST CHAR8 *T,
  CONST CHAR8 *M,
  UINT64 S,
  UINT32 I
  )
{
  abort ();
}
RETURN_STATUS EFIAPI
EndPerformanceMeasurementEx (
  CONST VOID *H,
  CONST CHAR8 *T,
  CONST CHAR8 *M,
  UINT64 S,
  UINT32 I
  )
{
  abort ();
}
EFI_STATUS EFIAPI
Tpm2Shutdown (
  TPM_SU Type
  )
{
  abort ();
}
EFI_STATUS EFIAPI
Tpm2RequestUseTpm (
  VOID
  )
{
  assert (AllowInit);
  return RequestStatus;
}
EFI_STATUS EFIAPI
Tpm2GetCapabilityManufactureID (
  UINT32 *Id
  )
{
  assert (AllowInit);
  *Id = 0;
  return EFI_SUCCESS;
}
EFI_STATUS EFIAPI
Tpm2GetCapabilityFirmwareVersion (
  UINT32 *A,
  UINT32 *B
  )
{
  assert (AllowInit);
  *A = *B = 0;
  return EFI_SUCCESS;
}
EFI_STATUS EFIAPI
Tpm2GetCapabilityMaxCommandResponseSize (
  UINT32 *A,
  UINT32 *B
  )
{
  assert (AllowInit);
  *A = *B = 4096;
  return EFI_SUCCESS;
}
EFI_EVENT EFIAPI
EfiCreateProtocolNotifyEvent (
  EFI_GUID *Guid,
  EFI_TPL Tpl,
  EFI_EVENT_NOTIFY Notify,
  VOID *Context,
  VOID **Registration
  )
{
  abort ();
}
EFI_STATUS EFIAPI
EfiCreateEventReadyToBootEx (
  EFI_TPL Tpl,
  EFI_EVENT_NOTIFY Notify,
  VOID *Context,
  EFI_EVENT *Event
  )
{
  abort ();
}
UINT16 EFIAPI
WriteUnaligned16 (
  UINT16 *P,
  UINT16 V
  )
{
  CopyMem ((VOID *)(UINTN)P, &V, 2);
  return V;
}
UINT16 EFIAPI
SwapBytes16 (
  UINT16 V
  )
{
  return __builtin_bswap16 (V);
}
UINT32 EFIAPI
SwapBytes32 (
  UINT32 V
  )
{
  return __builtin_bswap32 (V);
}
UINTN EFIAPI
StrLen (
  CONST CHAR16 *S
  )
{
  UINTN N = 0;
  while (S[N] != 0){
    ++N;
  }
  return N;
}
BOOLEAN EFIAPI
IsZeroBuffer (
  CONST VOID *Buffer,
  UINTN Length
  )
{
  CONST UINT8 *Bytes = Buffer;
  while (Length-- != 0){
    if (*Bytes++ != 0){
      return FALSE;
    }
  }
  return TRUE;
}
