# SPDX-License-Identifier: BSD-2-Clause-Patent
sky1_host_test(hierarchy_test PRELUDE HierarchyPcd.h
  SOURCES HierarchyTest.c ../PeiDxeTpmPlatformHierarchyLib.c
    ${EDK_ROOT}/SecurityPkg/Library/Tpm2CommandLib/Tpm2Help.c)
target_link_options(hierarchy_test PRIVATE -Wl,--wrap=ZeroMem)
