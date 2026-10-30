/** @file
  Load recovery images through the production DXE core and Security2 consumer.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#define main ConsumerTestMain
#include "Tcg2ConsumerTest.c"
#undef main
#include <DxeMain.h>
#include <Image/Image.c>

EFI_GUID gEfiLoadedImageProtocolGuid = { 101 };
EFI_GUID gEfiLoadedImageDevicePathProtocolGuid = { 102 };
EFI_GUID gEfiDevicePathProtocolGuid = { 103 };
EFI_GUID gEfiHiiPackageListProtocolGuid = { 104 };
EFI_GUID gEfiFirmwareVolume2ProtocolGuid = { 105 };
EFI_GUID gEfiSimpleFileSystemProtocolGuid = { 106 };
EFI_GUID gEfiLoadFile2ProtocolGuid = { 107 };
EFI_GUID gEfiLoadFileProtocolGuid = { 108 };
EFI_SYSTEM_TABLE *gDxeCoreST;
EFI_SECURITY_ARCH_PROTOCOL *gSecurity;
EFI_SECURITY2_ARCH_PROTOCOL *gSecurity2;
EFI_RUNTIME_ARCH_PROTOCOL *gRuntime;
EFI_TPL gEfiCurrentTpl = TPL_APPLICATION;
BOOLEAN gMemoryAttributesTableForwardCfi = TRUE;
STATIC LOADED_IMAGE_PRIVATE_DATA ParentImage;
STATIC UINTN LoadedImages;
STATIC UINTN ProtectedImages;
STATIC UINTN DebugImages;
STATIC VOID *Destination;

BOOLEAN EFIAPI
LogPerformanceMeasurementEnabled (
  CONST UINTN Type
  )
{
  return FALSE;
}

RETURN_STATUS EFIAPI
LogPerformanceMeasurement (
  CONST VOID *Caller,
  CONST VOID *Guid,
  CONST CHAR8 *String,
  UINT64 Address,
  UINT32 Identifier
  )
{
  fail_msg ("unexpected performance record");
  return RETURN_ABORTED;
}

STATIC EFI_STATUS EFIAPI
AuthenticateImage (
  CONST EFI_SECURITY2_ARCH_PROTOCOL *This,
  CONST EFI_DEVICE_PATH_PROTOCOL *Path,
  VOID *Buffer,
  UINTN Size,
  BOOLEAN BootPolicy
  )
{
  return ExecuteSecurity2Handlers (
           EFI_AUTH_OPERATION_VERIFY_IMAGE | EFI_AUTH_OPERATION_MEASURE_IMAGE,
           0, Path, Buffer, Size, BootPolicy);
}

EFI_STATUS EFIAPI
CoreLocateDevicePath (
  EFI_GUID *Guid,
  EFI_DEVICE_PATH_PROTOCOL **Path,
  EFI_HANDLE *Handle
  )
{
  assert_ptr_equal (Guid, &gEfiDevicePathProtocolGuid);
  return EFI_NOT_FOUND;
}

EFI_STATUS EFIAPI
CoreHandleProtocol (
  EFI_HANDLE Handle,
  EFI_GUID *Guid,
  VOID **Interface
  )
{
  assert_ptr_equal (Guid, &gEfiLoadedImageProtocolGuid);
  assert_ptr_equal (Handle, &ParentImage);
  *Interface = &ParentImage.Info;
  return EFI_SUCCESS;
}

EFI_STATUS
CoreInstallProtocolInterfaceNotify (
  EFI_HANDLE *Handle,
  EFI_GUID *Guid,
  EFI_INTERFACE_TYPE Type,
  VOID *Interface,
  BOOLEAN Notify
  )
{
  assert_ptr_equal (Guid, &gEfiLoadedImageProtocolGuid);
  assert_false (Notify);
  assert_int_equal (Type, EFI_NATIVE_INTERFACE);
  *Handle = BASE_CR (Interface, LOADED_IMAGE_PRIVATE_DATA, Info);
  ++LoadedImages;
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI
CoreInstallProtocolInterface (
  EFI_HANDLE *Handle,
  EFI_GUID *Guid,
  EFI_INTERFACE_TYPE Type,
  VOID *Interface
  )
{
  assert_ptr_equal (Guid, &gEfiLoadedImageDevicePathProtocolGuid);
  assert_non_null (*Handle);
  assert_non_null (Interface);
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI
CoreReinstallProtocolInterface (
  EFI_HANDLE Handle,
  EFI_GUID *Guid,
  VOID *Old,
  VOID *New
  )
{
  assert_ptr_equal (Guid, &gEfiLoadedImageProtocolGuid);
  assert_ptr_equal (Old, New);
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI
CoreAllocatePages (
  EFI_ALLOCATE_TYPE Type,
  EFI_MEMORY_TYPE Memory,
  UINTN Pages,
  EFI_PHYSICAL_ADDRESS *Address
  )
{
  assert_int_equal (Type, AllocateAddress);
  assert_int_equal (Memory, EfiLoaderCode);
  assert_true (Pages <= 6);
  assert_int_equal (*Address, (UINTN)Destination);
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI
CoreFreePages (
  EFI_PHYSICAL_ADDRESS Address,
  UINTN Pages
  )
{
  fail_msg ("unexpected page release");
  return EFI_ABORTED;
}

EFI_STATUS EFIAPI
CoreFreePool (
  VOID *Buffer
  )
{
  FreePool (Buffer);
  return EFI_SUCCESS;
}

VOID *EFIAPI
AllocateRuntimePool (
  UINTN Size
  )
{
  fail_msg ("application requested runtime pool");
  return NULL;
}

VOID
CoreNewDebugImageInfoEntry (
  UINT32 Type,
  EFI_LOADED_IMAGE_PROTOCOL *Image,
  EFI_HANDLE Handle
  )
{
  assert_int_equal (Type, EFI_DEBUG_IMAGE_INFO_TYPE_NORMAL);
  assert_non_null (Image->ImageBase);
  ++DebugImages;
}

VOID
CoreRemoveDebugImageInfoEntry (
  EFI_HANDLE Handle
  )
{
  assert_non_null (Handle);
}

VOID
ProtectUefiImage (
  EFI_LOADED_IMAGE_PROTOCOL *Image,
  EFI_DEVICE_PATH_PROTOCOL *Path
  )
{
  assert_non_null (Image->ImageBase);
  assert_non_null (Path);
  ++ProtectedImages;
}

VOID
UnprotectUefiImage (
  EFI_LOADED_IMAGE_PROTOCOL *Image,
  EFI_DEVICE_PATH_PROTOCOL *Path
  )
{
  assert_non_null (Image);
}

VOID *EFIAPI
InvalidateInstructionCacheRange (
  VOID *Address,
  UINTN Length
  )
{
  assert_ptr_equal (Address, Destination);
  assert_int_equal (Length, 0x5000);
  return Address;
}

VOID InsertImageRecord (EFI_RUNTIME_IMAGE_ENTRY *Image) { fail_msg ("runtime image"); }
VOID RemoveImageRecord (EFI_RUNTIME_IMAGE_ENTRY *Image) { fail_msg ("runtime image"); }
EFI_STATUS UnregisterMemoryProfileImage (LOADED_IMAGE_PRIVATE_DATA *Image) { fail_msg ("started image"); return EFI_ABORTED; }
EFI_STATUS EFIAPI CoreLocateHandleBuffer (EFI_LOCATE_SEARCH_TYPE Type, EFI_GUID *Guid, VOID *Key, UINTN *Count, EFI_HANDLE **Handles) { return EFI_NOT_FOUND; }
EFI_STATUS EFIAPI CoreProtocolsPerHandle (EFI_HANDLE Handle, EFI_GUID ***Guids, UINTN *Count) { fail_msg ("unexpected enumeration"); return EFI_ABORTED; }
EFI_STATUS EFIAPI CoreOpenProtocolInformation (EFI_HANDLE Handle, EFI_GUID *Guid, EFI_OPEN_PROTOCOL_INFORMATION_ENTRY **Info, UINTN *Count) { fail_msg ("unexpected enumeration"); return EFI_ABORTED; }
EFI_STATUS EFIAPI CoreCloseProtocol (EFI_HANDLE Handle, EFI_GUID *Guid, EFI_HANDLE Agent, EFI_HANDLE Controller) { fail_msg ("unexpected protocol close"); return EFI_ABORTED; }
EFI_STATUS EFIAPI CoreUninstallProtocolInterface (EFI_HANDLE Handle, EFI_GUID *Guid, VOID *Interface) { return EFI_SUCCESS; }
VOID *EFIAPI GetFileBufferByFilePath (BOOLEAN BootPolicy, CONST EFI_DEVICE_PATH_PROTOCOL *Path, UINTN *Size, UINT32 *Authentication) { fail_msg ("unexpected disk load"); return NULL; }

STATIC VOID
LoadRecoveryImages (
  VOID **State
  )
{
  EFI_SECURITY2_ARCH_PROTOCOL Security2 = { AuthenticateImage };
  EFI_HANDLE Handle;
  EFI_STATUS Status;
  EFI_IMAGE_NT_HEADERS64 *Nt;
  LOADED_IMAGE_PRIVATE_DATA *Image;

  for (UINTN Scenario = 0; Scenario < 3; ++Scenario) {
    ResetConsumer ();
    ZeroMem (&ParentImage, sizeof (ParentImage));
    ParentImage.Signature = LOADED_IMAGE_PRIVATE_DATA_SIGNATURE;
    InitializeListHead (&mAvailableEmulators);
    gSecurity2 = &Security2;
    BootServices.LoadImage = CoreLoadImage;
    LoadedImages = ProtectedImages = DebugImages = 0;
    InjectStatus = EFI_DEVICE_ERROR;
    if (Scenario == 1) {
      AllowInit = TRUE;
      gEfiTpmDeviceInstanceTpm20DtpmGuid.Data1 = 1;
      assert_int_equal (DriverEntry (NULL, NULL), EFI_SUCCESS);
      assert_int_equal (CapCalls, 8);
    } else if (Scenario == 2) {
      AllowInit = TRUE;
      RequestStatus = EFI_NOT_FOUND;
      gEfiTpmDeviceInstanceTpm20DtpmGuid.Data1 = 1;
      assert_int_equal (DriverEntry (NULL, NULL), EFI_NOT_FOUND);
    }

    for (UINTN Index = 0; Index < 2; ++Index) {
      UINT8 *Source = Index == 0 ? Loader.Bytes : Kernel.Bytes;
      Destination = aligned_alloc (EFI_PAGE_SIZE, 6 * EFI_PAGE_SIZE);
      assert_non_null (Destination);
      Nt = (VOID *)(Source + 0x80);
      Nt->FileHeader.Characteristics |= EFI_IMAGE_FILE_RELOCS_STRIPPED;
      Nt->OptionalHeader.ImageBase = (UINTN)Destination;
      Handle = NULL;
      Status = gBS->LoadImage (FALSE, &ParentImage, &ImagePath.File.Header,
                              Source, sizeof (Loader.Bytes), &Handle);
      assert_int_equal (Status, EFI_SUCCESS);
      assert_non_null (Handle);
      Image = Handle;
      assert_ptr_equal (Image->Info.ImageBase, Destination);
      assert_int_equal (Image->Info.ImageSize, 0x5000);
      assert_int_equal (*((UINT8 *)Image->Info.ImageBase + 0x1000), Index == 0 ? 0x4c : 0x4b);
      assert_int_equal (Image->LoadImageStatus, EFI_SUCCESS);
      CoreUnloadAndCloseImage (Image, FALSE);
      free (Destination);
    }
    assert_int_equal (CapCalls, Scenario == 2 ? 0 : 8);
    assert_int_equal (LoadedImages, 2);
    assert_int_equal (ProtectedImages, 2);
    assert_int_equal (DebugImages, 2);
    printf ("LoadImage scenario=%lu: loader and kernel loaded, caps=%lu, TPM-present=%u\n",
            (unsigned long)Scenario, (unsigned long)CapCalls, mTcgDxeData.BsCap.TPMPresentFlag);
    if (Scenario == 0) {
      Destination = aligned_alloc (EFI_PAGE_SIZE, 6 * EFI_PAGE_SIZE);
      assert_non_null (Destination);
      Nt = (VOID *)(Kernel.Bytes + 0x80);
      Nt->OptionalHeader.ImageBase = (UINTN)Destination;
      VerificationStatus = EFI_ACCESS_DENIED;
      Handle = (EFI_HANDLE)(UINTN)1;
      assert_int_equal (gBS->LoadImage (FALSE, &ParentImage, &ImagePath.File.Header,
                                       Kernel.Bytes, sizeof (Kernel.Bytes), &Handle), EFI_ACCESS_DENIED);
      assert_null (Handle);
      assert_int_equal (LoadedImages, 2);
      VerificationStatus = EFI_SECURITY_VIOLATION;
      assert_int_equal (gBS->LoadImage (FALSE, &ParentImage, &ImagePath.File.Header,
                                       Kernel.Bytes, sizeof (Kernel.Bytes), &Handle), EFI_SECURITY_VIOLATION);
      assert_non_null (Handle);
      assert_int_equal (((LOADED_IMAGE_PRIVATE_DATA *)Handle)->LoadImageStatus, EFI_SECURITY_VIOLATION);
      CoreUnloadAndCloseImage (Handle, FALSE);
      free (Destination);
      printf ("LoadImage signature-policy rejections preserved: Access Denied, Security Violation\n");
    }
  }
  FreePool (mSecurity2Table);
  mSecurity2Table = NULL;
}

int
main (
  void
  )
{
  const struct CMUnitTest Tests[] = { cmocka_unit_test (LoadRecoveryImages) };
  return cmocka_run_group_tests (Tests, NULL, NULL);
}
