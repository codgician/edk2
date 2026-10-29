#include <stdint.h>
#include "TestAdapter.h"
int
LLVMFuzzerTestOneInput (
  const uint8_t *Data,
  size_t Size
  )
{
  EFI_STATUS Status;
  UINT8 *    Copy;
  UINT8      Temp[sizeof(TPML_DIGEST_VALUES)];
  UINT32     Mask;
  ResetFixture ();
  /* Keep the producer's actual extent; no clamping of embedded sizes. */
  for (UINTN Format = 1; Format <= 2; ++Format) {
    Status = ValidateEventHob (Format, Data, Size);
    if (!EFI_ERROR (Status) && Format == EFI_TCG2_EVENT_LOG_FORMAT_TCG_2) {
      Copy = malloc (Size);
      assert (Copy != NULL);
      CopyMem (Copy, Data, Size);
      UINT32 DigestSize = GetDigestListBinSize (Copy + 8);
      assert (DigestSize <= sizeof(Temp));
      CopyDigestListBinToBuffer (Temp, Copy + 8, mTcgDxeData.BsCap.ActivePcrBanks, &Mask);
      assert (Mask == mTcgDxeData.BsCap.ActivePcrBanks);
      free (Copy);
    }
  }
  assert (CapCalls == 0 && HashCalls == 0);
  return 0;
}
