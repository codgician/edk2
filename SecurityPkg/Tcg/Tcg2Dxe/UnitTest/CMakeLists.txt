set(TCG2_SOURCES
  ${EDK_ROOT}/SecurityPkg/Library/Tpm2CommandLib/Tpm2Help.c
  ${EDK_ROOT}/MdePkg/Library/BaseLib/BitField.c
  ${EDK_ROOT}/MdePkg/Library/BaseLib/Math64.c
  ${EDK_ROOT}/MdePkg/Library/BaseLib/RShiftU64.c)
sky1_host_test(tcg2_failure_latch PRELUDE TestPcd.h
  SOURCES Tcg2FailureTest.c ${TCG2_SOURCES})
sky1_host_fuzz(tcg2_event_boundary_fuzz PRELUDE TestPcd.h
  SOURCES Tcg2EventFuzz.c ${TCG2_SOURCES})

# Malformed PE images and device paths would trip library ASSERTs.
set(CONSUMER_SOURCES ${TCG2_SOURCES}
  ${EDK_ROOT}/SecurityPkg/Library/DxeTpm2MeasureBootLib/DxeTpm2MeasureBootLibSanitization.c
  ${EDK_ROOT}/MdePkg/Library/BaseSafeIntLib/SafeIntLib.c
  ${EDK_ROOT}/MdePkg/Library/BaseSafeIntLib/SafeIntLib64.c
  ${EDK_ROOT}/MdePkg/Library/BasePeCoffLib/BasePeCoff.c
  ${EDK_ROOT}/MdePkg/Library/BasePeCoffLib/PeCoffLoaderEx.c
  ${EDK_ROOT}/MdePkg/Library/BaseLib/MultU64x32.c
  ${EDK_ROOT}/MdePkg/Library/BaseLib/DivU64x32.c
  ${EDK_ROOT}/MdePkg/Library/UefiDevicePathLib/DevicePathUtilities.c
  ${EDK_ROOT}/MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.c
  ${EDK_ROOT}/MdePkg/Library/UefiDevicePathLib/DevicePathUtilitiesDxeSmm.c
  ${EDK_ROOT}/MdePkg/Library/UefiDevicePathLib/DevicePathToText.c
  ${EDK_ROOT}/MdeModulePkg/Library/GptLib/Gpt.c)
set(CONSUMER_INCLUDES
  ${EDK_ROOT}/SecurityPkg/Library/DxeTpm2MeasureBootLib
  ${EDK_ROOT}/MdeModulePkg/Library/DxeSecurityManagementLib)
sky1_host_test(tcg2_image_consumer PRELUDE TestPcd.h DEFINES MDEPKG_NDEBUG
  SOURCES Tcg2ConsumerTest.c ${CONSUMER_SOURCES}
  INCLUDES ${CONSUMER_INCLUDES})
sky1_host_test(tcg2_image_load PRELUDE TestPcd.h DEFINES MDEPKG_NDEBUG
  SOURCES Tcg2LoadTest.c ${CONSUMER_SOURCES}
    ${EDK_ROOT}/MdePkg/Library/BaseLib/LinkedList.c
    ${EDK_ROOT}/MdePkg/Library/BasePeCoffExtraActionLibNull/PeCoffExtraActionLib.c
  INCLUDES ${CONSUMER_INCLUDES} ${EDK_ROOT}/MdeModulePkg/Core/Dxe)
