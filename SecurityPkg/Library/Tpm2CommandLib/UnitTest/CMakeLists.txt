sky1_host_test(capability_response_test SOURCES CapabilityTest.c CapabilityMock.c ../Tpm2Capability.c)
sky1_host_fuzz(capability_response_fuzz SOURCES CapabilityFuzz.c CapabilityMock.c ../Tpm2Capability.c)
