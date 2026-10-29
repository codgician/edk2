#include <stdint.h>
#include "TestAdapter.h"
int
LLVMFuzzerTestOneInput (
  const uint8_t *Data,
  size_t Size
  )
{
  struct {
    UINT32 Size;
    EFI_TCG2_EVENT_HEADER Header;
    UINT8 Payload[128];
  }
  Event;
  EFI_TCG2_PROTOCOL This;
  EFI_STATUS        Status;
  ResetFixture ();
  ZeroMem (&Event, sizeof(Event));
  /* The caller owns a buffer of Event.Size bytes; fuzz every header field. */
  CopyMem (&Event.Header, Data, MIN (Size, sizeof(Event.Header)));
  Event.Size = sizeof(Event);
  Status     = Tcg2HashLogExtendEvent (&This, 0, (UINTN)Event.Payload, sizeof(Event.Payload), (EFI_TCG2_EVENT *)&Event);
  assert (CapCalls == 0 || CapCalls == 8);
  assert (mTcgDxeData.BsCap.TPMPresentFlag);
  if (Event.Header.HeaderSize != sizeof(Event.Header) ||
      Event.Size < sizeof(UINT32) + sizeof(Event.Header) ||
      Event.Header.HeaderVersion != EFI_TCG2_EVENT_HEADER_VERSION) {
    assert (Status == EFI_INVALID_PARAMETER);
    assert (HashCalls == 0);
  }
  return 0;
}
