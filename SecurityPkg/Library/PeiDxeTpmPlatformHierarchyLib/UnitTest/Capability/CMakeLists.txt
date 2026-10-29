set(CAPABILITY_SOURCE "${EDK_ROOT}/SecurityPkg/Library/Tpm2CommandLib/Tpm2Capability.c")
sky1_host_test(capability_response_test
  SOURCES CapabilityTest.c CapabilityMock.c ../HostBase.c "${CAPABILITY_SOURCE}")
sky1_host_fuzz(capability_response_fuzz
  SOURCES CapabilityFuzz.c CapabilityMock.c ../HostBase.c "${CAPABILITY_SOURCE}")
