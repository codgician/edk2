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
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}
    ${EDK_ROOT}/SecurityPkg/Library/DxeTpm2MeasureBootLib)
target_compile_options(tcg2_image_consumer PRIVATE -ffunction-sections -fdata-sections "SHELL:-include ${CMAKE_CURRENT_SOURCE_DIR}/TestPcd.h")
target_link_options(tcg2_image_consumer PRIVATE -Wl,--gc-sections)
