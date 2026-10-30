sky1_host_test(tcg2_failure_latch
  SOURCES Tcg2FailureTest.c ${EDK_ROOT}/SecurityPkg/Library/Tpm2CommandLib/Tpm2Help.c
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(tcg2_failure_latch PRIVATE -ffunction-sections -fdata-sections "SHELL:-include ${CMAKE_CURRENT_SOURCE_DIR}/TestPcd.h")
target_link_options(tcg2_failure_latch PRIVATE -Wl,--gc-sections)

sky1_host_fuzz(tcg2_event_boundary_fuzz
  SOURCES Tcg2EventFuzz.c ${EDK_ROOT}/SecurityPkg/Library/Tpm2CommandLib/Tpm2Help.c
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(tcg2_event_boundary_fuzz PRIVATE -ffunction-sections -fdata-sections "SHELL:-include ${CMAKE_CURRENT_SOURCE_DIR}/TestPcd.h")
target_link_options(tcg2_event_boundary_fuzz PRIVATE -Wl,--gc-sections)

sky1_host_fuzz(tcg2_hob_boundary_fuzz
  SOURCES Tcg2HobFuzz.c ${EDK_ROOT}/SecurityPkg/Library/Tpm2CommandLib/Tpm2Help.c
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(tcg2_hob_boundary_fuzz PRIVATE -ffunction-sections -fdata-sections "SHELL:-include ${CMAKE_CURRENT_SOURCE_DIR}/TestPcd.h")
target_link_options(tcg2_hob_boundary_fuzz PRIVATE -Wl,--gc-sections)

sky1_host_test(tcg2_image_consumer
  SOURCES Tcg2ConsumerTest.c
    ${EDK_ROOT}/SecurityPkg/Library/Tpm2CommandLib/Tpm2Help.c
    ${EDK_ROOT}/SecurityPkg/Library/DxeTpm2MeasureBootLib/DxeTpm2MeasureBootLibSanitization.c
    ${EDK_ROOT}/MdePkg/Library/BaseSafeIntLib/SafeIntLib.c
    ${EDK_ROOT}/MdePkg/Library/BasePeCoffLib/BasePeCoff.c
    ${EDK_ROOT}/MdePkg/Library/BaseSafeIntLib/SafeIntLib64.c
    ${EDK_ROOT}/MdePkg/Library/BaseLib/MultU64x32.c
    ${EDK_ROOT}/MdePkg/Library/BaseLib/DivU64x32.c
    ${EDK_ROOT}/MdePkg/Library/BaseLib/Math64.c
    ${EDK_ROOT}/MdePkg/Library/BasePeCoffLib/PeCoffLoaderEx.c
    ${EDK_ROOT}/MdePkg/Library/UefiDevicePathLib/DevicePathUtilities.c
    ${EDK_ROOT}/MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.c
    ${EDK_ROOT}/MdePkg/Library/UefiDevicePathLib/DevicePathUtilitiesDxeSmm.c
    ${EDK_ROOT}/MdeModulePkg/Library/GptLib/Gpt.c
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}
    ${EDK_ROOT}/SecurityPkg/Library/DxeTpm2MeasureBootLib
    ${EDK_ROOT}/MdeModulePkg/Library/DxeSecurityManagementLib)
target_compile_options(tcg2_image_consumer PRIVATE -ffunction-sections -fdata-sections "SHELL:-include ${CMAKE_CURRENT_SOURCE_DIR}/TestPcd.h")
target_compile_definitions(tcg2_image_consumer PRIVATE MDEPKG_NDEBUG)
target_link_options(tcg2_image_consumer PRIVATE -Wl,--gc-sections)

foreach(Target tcg2_failure_latch tcg2_image_consumer tcg2_event_boundary_fuzz tcg2_hob_boundary_fuzz)
  target_sources(${Target} PRIVATE
    ${EDK_ROOT}/MdePkg/Library/BasePrintLib/PrintLib.c
    ${EDK_ROOT}/MdePkg/Library/BasePrintLib/PrintLibInternal.c
    ${EDK_ROOT}/MdePkg/Library/BaseLib/DivU64x32Remainder.c
    ${EDK_ROOT}/MdePkg/Library/BaseLib/Math64.c)
endforeach()

target_sources(tcg2_image_consumer PRIVATE
  ${EDK_ROOT}/MdePkg/Library/UefiDevicePathLib/DevicePathToText.c)

get_target_property(ConsumerSources tcg2_image_consumer SOURCES)
list(REMOVE_ITEM ConsumerSources Tcg2ConsumerTest.c)
sky1_host_test(tcg2_image_load
  SOURCES Tcg2LoadTest.c ${ConsumerSources}
    ${EDK_ROOT}/MdePkg/Library/BaseLib/LinkedList.c
    ${EDK_ROOT}/MdePkg/Library/BasePeCoffExtraActionLibNull/PeCoffExtraActionLib.c
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}
    ${EDK_ROOT}/SecurityPkg/Library/DxeTpm2MeasureBootLib
    ${EDK_ROOT}/MdeModulePkg/Library/DxeSecurityManagementLib
    ${EDK_ROOT}/MdeModulePkg/Core/Dxe)
target_compile_options(tcg2_image_load PRIVATE -ffunction-sections -fdata-sections "SHELL:-include ${CMAKE_CURRENT_SOURCE_DIR}/TestPcd.h")
target_compile_definitions(tcg2_image_load PRIVATE MDEPKG_NDEBUG)
target_link_options(tcg2_image_load PRIVATE -Wl,--gc-sections)

get_target_property(FailureSources tcg2_failure_latch SOURCES)
sky1_host_test(tcg2_failure_latch_release
  SOURCES ${FailureSources}
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(tcg2_failure_latch_release PRIVATE -ffunction-sections -fdata-sections "SHELL:-include ${CMAKE_CURRENT_SOURCE_DIR}/TestPcd.h")
target_compile_definitions(tcg2_failure_latch_release PRIVATE MDEPKG_NDEBUG)
target_link_options(tcg2_failure_latch_release PRIVATE -Wl,--gc-sections)
