# SPDX-License-Identifier: BSD-2-Clause-Patent
sky1_host_test(hierarchy_test
  SOURCES HierarchyTest.c HostBase.c ../PeiDxeTpmPlatformHierarchyLib.c)
target_compile_options(hierarchy_test PRIVATE "SHELL:-include ${CMAKE_CURRENT_SOURCE_DIR}/HierarchyPcd.h")
target_link_options(hierarchy_test PRIVATE -Wl,--wrap=ZeroMem)

# The shared harness only discovers Platform/CIX and SecurityPkg tests.
get_filename_component(RNG_TEST_DIR
  "${PLAT_ROOT}/Silicon/CIX/Sky1/Library/RngLib/UnitTest" ABSOLUTE)
if(EXISTS "${RNG_TEST_DIR}/CMakeLists.txt")
  add_subdirectory("${RNG_TEST_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/RngLib")
endif()
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/Capability/CMakeLists.txt")
  add_subdirectory(Capability)
endif()
