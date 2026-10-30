sky1_host_test(tcg2_hierarchy_callers
  SOURCES HierarchyCallersTest.c ../Tcg2PlatformDxe.c ../../Tcg2PlatformPei/Tcg2PlatformPei.c)
target_compile_options(tcg2_hierarchy_callers PRIVATE
  "SHELL:-include ${CMAKE_CURRENT_SOURCE_DIR}/TestAdapter.h")
