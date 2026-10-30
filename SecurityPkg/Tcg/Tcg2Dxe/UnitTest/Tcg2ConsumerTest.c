/** @file
  Exercise measured-boot load authorization through the real Security2 chain.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <cmocka.h>
#define TCG2_CONSUMER_TEST
#include "TestAdapter.h"
#include <DxeSecurityManagementLib.c>
#include <Protocol/FirmwareVolumeBlock.h>
#include <Guid/MeasuredFvHob.h>

STATIC BOOLEAN  FailEventAllocation;
STATIC BOOLEAN  FailPathAllocation;
STATIC BOOLEAN  GptDevice;
STATIC BOOLEAN  CcDevice;
STATIC UINTN    DiskReads;
STATIC UINTN    VerificationCalls;
STATIC UINTN    CcCalls;
STATIC EFI_STATUS VerificationStatus;
STATIC UINTN FvFailure;
STATIC EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL Fvb;
STATIC MEASURED_HOB_DATA MeasuredFv;

STATIC EFI_STATUS EFIAPI
FvAddressFailure (
  CONST EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL *This,
  EFI_PHYSICAL_ADDRESS *Address
  )
{
  assert_ptr_equal (This, &Fvb);
  return EFI_DEVICE_ERROR;
}

STATIC VOID *
ConsumerAllocateZeroPool (
  UINTN Size
  )
{
  if (FailEventAllocation) {
    FailEventAllocation = FALSE;
    return NULL;
  }

  return AllocateZeroPool (Size);
}

STATIC EFI_DEVICE_PATH_PROTOCOL *
ConsumerDuplicateDevicePath (
  CONST EFI_DEVICE_PATH_PROTOCOL *Path
  )
{
  if (FailPathAllocation) {
    FailPathAllocation = FALSE;
    return NULL;
  }

  return DuplicateDevicePath (Path);
}

#define AllocateZeroPool ConsumerAllocateZeroPool
#define DuplicateDevicePath ConsumerDuplicateDevicePath
#include <DxeTpm2MeasureBootLib.c>
#undef AllocateZeroPool
#undef DuplicateDevicePath

EFI_GUID gEfiCcMeasurementProtocolGuid;
EFI_GUID gEfiBlockIoProtocolGuid;
EFI_GUID gEfiDiskIoProtocolGuid;
EFI_GUID gEfiFirmwareVolumeBlockProtocolGuid;
EFI_GUID gMeasuredFvHobGuid;

STATIC union {
  UINT64 Alignment;
  UINT8  Bytes[0x1000];
} Loader, Kernel;

STATIC struct {
  FILEPATH_DEVICE_PATH File;
  CHAR16               Name[32];
  EFI_DEVICE_PATH_PROTOCOL End;
} ImagePath;

STATIC struct {
  HARDDRIVE_DEVICE_PATH Disk;
  EFI_DEVICE_PATH_PROTOCOL End;
} GptPath;

STATIC EFI_BLOCK_IO_MEDIA Media;
STATIC EFI_BLOCK_IO_PROTOCOL BlockIo;
STATIC EFI_DISK_IO_PROTOCOL DiskIo;
STATIC EFI_CC_MEASUREMENT_PROTOCOL CcProtocol;

STATIC EFI_STATUS EFIAPI
CcCapability (
  EFI_CC_MEASUREMENT_PROTOCOL *This,
  EFI_CC_BOOT_SERVICE_CAPABILITY *Capability
  )
{
  Capability->CcType.Type = 1;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS EFIAPI
CcMap (
  EFI_CC_MEASUREMENT_PROTOCOL *This,
  UINT32 Pcr,
  EFI_CC_MR_INDEX *Mr
  )
{
  assert_int_equal (Pcr, 4);
  *Mr = 1;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS EFIAPI
CcMeasure (
  EFI_CC_MEASUREMENT_PROTOCOL *This,
  UINT64 Flags,
  EFI_PHYSICAL_ADDRESS Address,
  UINT64 Size,
  EFI_CC_EVENT *Event
  )
{
  assert_int_equal (Flags, PE_COFF_IMAGE);
  ++CcCalls;
  return InjectStatus;
}

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
  if (CcDevice) {
    *Interface = &CcProtocol;
    return EFI_SUCCESS;
  }

  return EFI_NOT_FOUND;
}

STATIC EFI_STATUS EFIAPI
LocateImageDevice (
  EFI_GUID *Guid,
  EFI_DEVICE_PATH_PROTOCOL **Path,
  EFI_HANDLE *Handle
  )
{
  assert_non_null (*Path);
  if ((Guid == &gEfiBlockIoProtocolGuid) || (Guid == &gEfiDiskIoProtocolGuid)) {
    if (GptDevice) {
      *Handle = &BlockIo;
      return EFI_SUCCESS;
    }

    return EFI_NOT_FOUND;
  }

  assert_ptr_equal (Guid, &gEfiFirmwareVolumeBlockProtocolGuid);
  if (FvFailure != 0) {
    *Handle = &Fvb;
    return EFI_SUCCESS;
  }
  return EFI_NOT_FOUND;
}

STATIC EFI_STATUS EFIAPI
ImageHandleProtocol (
  EFI_HANDLE Handle,
  EFI_GUID *Guid,
  VOID **Interface
  )
{
  if (FvFailure != 0) {
    assert_ptr_equal (Guid, &gEfiFirmwareVolumeBlockProtocolGuid);
    if (FvFailure == 1) {
      return EFI_DEVICE_ERROR;
    }
    *Interface = &Fvb;
    return EFI_SUCCESS;
  }
  assert_true (GptDevice);
  assert_ptr_equal (Handle, &BlockIo);
  if (Guid == &gEfiBlockIoProtocolGuid) {
    *Interface = &BlockIo;
  } else {
    assert_ptr_equal (Guid, &gEfiDiskIoProtocolGuid);
    *Interface = &DiskIo;
  }

  return EFI_SUCCESS;
}

STATIC EFI_STATUS EFIAPI
ReadGptFailure (
  EFI_DISK_IO_PROTOCOL *This,
  UINT32 MediaId,
  UINT64 Offset,
  UINTN Size,
  VOID *Buffer
  )
{
  assert_ptr_equal (This, &DiskIo);
  ++DiskReads;
  return EFI_DEVICE_ERROR;
}

STATIC EFI_STATUS EFIAPI
VerifyImage (
  UINT32 AuthenticationStatus,
  CONST EFI_DEVICE_PATH_PROTOCOL *File,
  VOID *Buffer,
  UINTN Size,
  BOOLEAN BootPolicy
  )
{
  ++VerificationCalls;
  return VerificationStatus;
}

/** Valid PE32+ applications, with loader- and unified-kernel-like sections. **/
STATIC VOID
MakeImage (
  UINT8 *Buffer,
  BOOLEAN IsKernel
  )
{
  EFI_IMAGE_DOS_HEADER *Dos;
  EFI_IMAGE_NT_HEADERS64 *Nt;
  EFI_IMAGE_SECTION_HEADER *Section;
  UINTN Index;
  CONST CHAR8 *Names[] = { ".text", ".linux", ".cmdline" };

  ZeroMem (Buffer, sizeof (Loader.Bytes));
  Dos = (VOID *)Buffer;
  Dos->e_magic = EFI_IMAGE_DOS_SIGNATURE;
  Dos->e_lfanew = 0x80;
  Nt = (VOID *)(Buffer + Dos->e_lfanew);
  Nt->Signature = EFI_IMAGE_NT_SIGNATURE;
  Nt->FileHeader.Machine = IMAGE_FILE_MACHINE_ARM64;
  Nt->FileHeader.NumberOfSections = IsKernel ? 3 : 1;
  Nt->FileHeader.SizeOfOptionalHeader = sizeof (Nt->OptionalHeader);
  Nt->FileHeader.Characteristics = EFI_IMAGE_FILE_EXECUTABLE_IMAGE;
  Nt->OptionalHeader.Magic = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  Nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
  Nt->OptionalHeader.BaseOfCode = 0x1000;
  Nt->OptionalHeader.ImageBase = 0x400000;
  Nt->OptionalHeader.SectionAlignment = 0x1000;
  Nt->OptionalHeader.FileAlignment = 0x200;
  Nt->OptionalHeader.SizeOfImage = 0x5000;
  Nt->OptionalHeader.SizeOfHeaders = 0x400;
  Nt->OptionalHeader.Subsystem = EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION;
  Nt->OptionalHeader.NumberOfRvaAndSizes = EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;
  Section = (VOID *)(Nt + 1);
  for (Index = 0; Index < Nt->FileHeader.NumberOfSections; ++Index) {
    CopyMem (Section[Index].Name, Names[Index], AsciiStrLen (Names[Index]));
    Section[Index].Misc.VirtualSize = 0x200;
    Section[Index].VirtualAddress = (UINT32)(0x1000 * (Index + 1));
    Section[Index].SizeOfRawData = 0x200;
    Section[Index].PointerToRawData = (UINT32)(0x400 + Index * 0x200);
    Section[Index].Characteristics = EFI_IMAGE_SCN_CNT_CODE | EFI_IMAGE_SCN_MEM_EXECUTE | EFI_IMAGE_SCN_MEM_READ;
    Buffer[Section[Index].PointerToRawData] = IsKernel ? 0x4b : 0x4c;
  }
}

STATIC VOID
ResetConsumer (
  VOID
  )
{
  ResetFixture ();
  FailEventAllocation = FailPathAllocation = GptDevice = CcDevice = FALSE;
  FvFailure = 0;
  ZeroMem (&Fvb, sizeof (Fvb));
  Fvb.GetPhysicalAddress = FvAddressFailure;
  DiskReads = VerificationCalls = CcCalls = 0;
  VerificationStatus = EFI_SUCCESS;
  mTcg2MeasureGptTableFlag = FALSE;
  mTcg2MeasureGptCount = 0;
  mTcg2CacheMeasuredHandle = NULL;
  mTcg2MeasuredHobData = NULL;
  ZeroMem (&ImagePath, sizeof (ImagePath));
  ImagePath.File.Header.Type = MEDIA_DEVICE_PATH;
  ImagePath.File.Header.SubType = MEDIA_FILEPATH_DP;
  SetDevicePathNodeLength (&ImagePath.File.Header, sizeof (ImagePath) - sizeof (ImagePath.End));
  SetDevicePathEndNode (&ImagePath.End);
  ZeroMem (&GptPath, sizeof (GptPath));
  GptPath.Disk.Header.Type = MEDIA_DEVICE_PATH;
  GptPath.Disk.Header.SubType = MEDIA_HARDDRIVE_DP;
  SetDevicePathNodeLength (&GptPath.Disk.Header, sizeof (GptPath.Disk));
  GptPath.Disk.MBRType = MBR_TYPE_EFI_PARTITION_TABLE_HEADER;
  GptPath.Disk.SignatureType = SIGNATURE_TYPE_GUID;
  SetDevicePathEndNode (&GptPath.End);
  ZeroMem (&Media, sizeof (Media));
  Media.BlockSize = 512;
  Media.LastBlock = 4095;
  BlockIo.Media = &Media;
  DiskIo.ReadDisk = ReadGptFailure;
  CcProtocol.GetCapability = CcCapability;
  CcProtocol.MapPcrToMrIndex = CcMap;
  CcProtocol.HashLogExtendEvent = CcMeasure;
  BootServices.LocateProtocol = LocateMeasureProtocol;
  BootServices.LocateDevicePath = LocateImageDevice;
  BootServices.HandleProtocol = ImageHandleProtocol;
  MakeImage (Loader.Bytes, FALSE);
  MakeImage (Kernel.Bytes, TRUE);
  if (mSecurity2Table != NULL) {
    FreePool (mSecurity2Table);
  }

  mSecurity2Table = NULL;
  mNumberOfSecurity2Handler = mMaxNumberOfSecurity2Handler = mCurrentAuthOperation2 = 0;
  assert_int_equal (RegisterSecurity2Handler (VerifyImage, EFI_AUTH_OPERATION_VERIFY_IMAGE), EFI_SUCCESS);
  AllowInit = TRUE;
  assert_int_equal (DxeTpm2MeasureBootLibConstructor (NULL, NULL), EFI_SUCCESS);
  AllowInit = FALSE;
}

STATIC EFI_STATUS
Authorize (
  UINT8 *Image
  )
{
  return ExecuteSecurity2Handlers (
           EFI_AUTH_OPERATION_VERIFY_IMAGE | EFI_AUTH_OPERATION_MEASURE_IMAGE,
           0,
           GptDevice ? &GptPath.Disk.Header : &ImagePath.File.Header,
           Image,
           sizeof (Loader.Bytes),
           FALSE
           );
}

STATIC VOID
FirstFailureAllowsLoaderAndKernel (
  VOID **State
  )
{
  ResetConsumer ();
  InjectStatus = EFI_DEVICE_ERROR;
  assert_int_equal (Authorize (Loader.Bytes), EFI_SUCCESS);
  assert_int_equal (CapCalls, 8);
  assert_int_equal (HashCalls, 1);
  assert_true (mTcgDxeData.MeasurementFailed);
  assert_non_null (strstr (SerialOutput, "TPM ImageMeasure: measurement failed, PCRs 0-7 capped, continuing (Device Error)"));
  assert_int_equal (Authorize (Kernel.Bytes), EFI_SUCCESS);
  assert_int_equal (CapCalls, 8);
  assert_int_equal (HashCalls, 1);
  assert_int_equal (VerificationCalls, 2);
}

STATIC VOID
DirectErrorsRemainHonest (
  VOID **State
  )
{
  MEASURE_BOOT_PROTOCOLS Protocols;

  ResetConsumer ();
  assert_int_equal (GetMeasureBootProtocols (&Protocols), EFI_SUCCESS);
  InjectStatus = EFI_OUT_OF_RESOURCES;
  assert_int_equal (Tcg2MeasurePeImage (&Protocols, (UINTN)Loader.Bytes, sizeof (Loader.Bytes), 0,
                    EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION, &ImagePath.File.Header), EFI_OUT_OF_RESOURCES);
  assert_int_equal (Tcg2MeasurePeImage (&Protocols, (UINTN)Kernel.Bytes, sizeof (Kernel.Bytes), 0,
                    EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION, &ImagePath.File.Header), EFI_DEVICE_ERROR);
  assert_int_equal (CapCalls, 8);
}

STATIC VOID
LogFullErrorRemainsHonest (
  VOID **State
  )
{
  MEASURE_BOOT_PROTOCOLS Protocols;

  ResetConsumer ();
  CcDevice = TRUE;
  InjectStatus = EFI_VOLUME_FULL;
  assert_int_equal (GetMeasureBootProtocols (&Protocols), EFI_SUCCESS);
  /* CC retains its historical log-full policy; TPM must not claim success. */
  assert_int_equal (Tcg2MeasurePeImage (&Protocols, (UINTN)Loader.Bytes, sizeof (Loader.Bytes), 0,
                    EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION, &ImagePath.File.Header), EFI_SUCCESS);
  Protocols.CcProtocol = NULL;
  Protocols.Tcg2Protocol = &mTcg2Protocol;
  mTcgDxeData.EventLogAreaStruct[1].EventLogTruncated = TRUE;
  assert_int_equal (Tcg2MeasurePeImage (&Protocols, (UINTN)Loader.Bytes, sizeof (Loader.Bytes), 0,
                    EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION, &ImagePath.File.Header), EFI_VOLUME_FULL);
}

STATIC VOID
PreparationFailureCapsBeforePermission (
  VOID **State
  )
{
  ResetConsumer ();
  FailEventAllocation = TRUE;
  assert_int_equal (Authorize (Loader.Bytes), EFI_SUCCESS);
  assert_int_equal (CapCalls, 8);
  assert_int_equal (HashCalls, 0);
  assert_non_null (strstr (SerialOutput, "TPM ImageMeasure: measurement failed, PCRs 0-7 capped, continuing (Out of Resources)"));
  InjectStatus = EFI_DEVICE_ERROR;
  assert_int_equal (Authorize (Kernel.Bytes), EFI_SUCCESS);
  assert_int_equal (CapCalls, 8);
}

STATIC VOID
DevicePathFailureCapsBeforePermission (
  VOID **State
  )
{
  ResetConsumer ();
  FailPathAllocation = TRUE;
  assert_int_equal (Authorize (Loader.Bytes), EFI_SUCCESS);
  assert_int_equal (CapCalls, 8);
  assert_int_equal (HashCalls, 0);
}

STATIC VOID
GptFailureCapsBeforePermission (
  VOID **State
  )
{
  ResetConsumer ();
  GptDevice = TRUE;
  InjectStatus = EFI_DEVICE_ERROR;
  assert_int_equal (Authorize (Loader.Bytes), EFI_SUCCESS);
  assert_true (DiskReads > 0);
  assert_int_equal (CapCalls, 8);
  assert_int_equal (HashCalls, 0);
  assert_false (mTcg2MeasureGptTableFlag);
}

STATIC VOID
LogInitializationFailureAllowsImages (
  VOID **State
  )
{
  ResetConsumer ();
  AllowInit = TRUE;
  gEfiTpmDeviceInstanceTpm20DtpmGuid.Data1 = 1;
  assert_int_equal (DriverEntry (NULL, NULL), EFI_SUCCESS);
  assert_int_equal (CapCalls, 8);
  assert_int_equal (Authorize (Loader.Bytes), EFI_SUCCESS);
  assert_int_equal (Authorize (Kernel.Bytes), EFI_SUCCESS);
  assert_int_equal (HashCalls, 0);
  assert_int_equal (CapCalls, 8);
}

STATIC VOID
AbsentTpmAllowsImagesWithoutCap (
  VOID **State
  )
{
  ResetConsumer ();
  mTcgDxeData.BsCap.TPMPresentFlag = FALSE;
  assert_int_equal (Authorize (Loader.Bytes), EFI_SUCCESS);
  assert_int_equal (Authorize (Kernel.Bytes), EFI_SUCCESS);
  assert_int_equal (CapCalls, 0);
  assert_int_equal (HashCalls, 0);
}

STATIC VOID
CapFailureStopsImageAuthorization (
  VOID **State
  )
{
  ResetConsumer ();
  FailEventAllocation = TRUE;
  FailCap = 3;
  ExpectStop = TRUE;
  if (setjmp (Stop) == 0) {
    Authorize (Loader.Bytes);
    fail_msg ("Image authorization returned without a proven PCR cap");
  }

  assert_int_equal (CapCalls, 3);
}

STATIC EFI_STATUS EFIAPI
RejectCapRequest (
  EFI_TCG2_PROTOCOL *This,
  UINT64 Flags,
  EFI_PHYSICAL_ADDRESS Address,
  UINT64 Size,
  EFI_TCG2_EVENT *Event
  )
{
  assert_int_equal (Flags, EFI_TCG2_EXTEND_ONLY);
  assert_int_equal (Event->Header.EventType, EV_SEPARATOR);
  assert_int_equal (ReadUnaligned32 ((UINT32 *)(UINTN)Address), 1);
  assert_int_equal (Size, sizeof (UINT32));
  return EFI_UNSUPPORTED;
}

STATIC VOID
UnprovenProtocolCapStopsAuthorization (
  VOID **State
  )
{
  EFI_TCG2_HASH_LOG_EXTEND_EVENT Original;

  ResetConsumer ();
  Original = mTcg2Protocol.HashLogExtendEvent;
  mTcg2Protocol.HashLogExtendEvent = RejectCapRequest;
  FailEventAllocation = TRUE;
  ExpectStop = TRUE;
  if (setjmp (Stop) == 0) {
    Authorize (Loader.Bytes);
    mTcg2Protocol.HashLogExtendEvent = Original;
    fail_msg ("Unconfirmed separator request authorized an image");
  }

  mTcg2Protocol.HashLogExtendEvent = Original;
  assert_int_equal (CapCalls, 0);
  assert_non_null (strstr (SerialOutput, "TPM ImageMeasure: PCR cap unproven, stopping (Unsupported)"));
}

STATIC VOID
SignatureErrorStillDenies (
  VOID **State
  )
{
  ResetConsumer ();
  InjectStatus = EFI_DEVICE_ERROR;
  assert_int_equal (Authorize (Loader.Bytes), EFI_SUCCESS);
  assert_int_equal (CapCalls, 8);
  VerificationStatus = EFI_SECURITY_VIOLATION;
  assert_int_equal (Authorize (Kernel.Bytes), EFI_SECURITY_VIOLATION);
  VerificationStatus = EFI_ACCESS_DENIED;
  assert_int_equal (Authorize (Kernel.Bytes), EFI_ACCESS_DENIED);
  assert_int_equal (VerificationCalls, 3);
  assert_int_equal (CapCalls, 8);
}

STATIC VOID
MalformedImageStillDeniedAfterCap (
  VOID **State
  )
{
  ResetConsumer ();
  InjectStatus = EFI_DEVICE_ERROR;
  assert_int_equal (Authorize (Loader.Bytes), EFI_SUCCESS);
  ZeroMem (Kernel.Bytes, sizeof (Kernel.Bytes));
  assert_true (EFI_ERROR (Authorize (Kernel.Bytes)));
  assert_int_equal (CapCalls, 8);
}

STATIC VOID
CcFailurePolicyUnchanged (
  VOID **State
  )
{
  ResetConsumer ();
  CcDevice = TRUE;
  InjectStatus = EFI_DEVICE_ERROR;
  assert_int_equal (Authorize (Loader.Bytes), EFI_DEVICE_ERROR);
  assert_int_equal (CcCalls, 1);
  assert_int_equal (CapCalls, 0);
  InjectStatus = EFI_VOLUME_FULL;
  assert_int_equal (Authorize (Kernel.Bytes), EFI_SUCCESS);
  assert_int_equal (CcCalls, 2);
  assert_int_equal (CapCalls, 0);
}

STATIC VOID
FvFailureCapsBeforePermission (
  VOID **State
  )
{
  for (UINTN Failure = 1; Failure <= 2; ++Failure) {
    ResetConsumer ();
    FvFailure = Failure;
    mTcg2MeasuredHobData = &MeasuredFv;
    assert_int_equal (Authorize (Loader.Bytes), EFI_SUCCESS);
    assert_int_equal (CapCalls, 8);
    assert_int_equal (HashCalls, 0);
  }
}

int
main (
  void
  )
{
  const struct CMUnitTest Tests[] = {
    cmocka_unit_test (FirstFailureAllowsLoaderAndKernel),
    cmocka_unit_test (DirectErrorsRemainHonest),
    cmocka_unit_test (LogFullErrorRemainsHonest),
    cmocka_unit_test (PreparationFailureCapsBeforePermission),
    cmocka_unit_test (DevicePathFailureCapsBeforePermission),
    cmocka_unit_test (GptFailureCapsBeforePermission),
    cmocka_unit_test (LogInitializationFailureAllowsImages),
    cmocka_unit_test (AbsentTpmAllowsImagesWithoutCap),
    cmocka_unit_test (CapFailureStopsImageAuthorization),
    cmocka_unit_test (UnprovenProtocolCapStopsAuthorization),
    cmocka_unit_test (SignatureErrorStillDenies),
    cmocka_unit_test (MalformedImageStillDeniedAfterCap),
    cmocka_unit_test (CcFailurePolicyUnchanged),
    cmocka_unit_test (FvFailureCapsBeforePermission)
  };
  return cmocka_run_group_tests (Tests, NULL, NULL);
}
