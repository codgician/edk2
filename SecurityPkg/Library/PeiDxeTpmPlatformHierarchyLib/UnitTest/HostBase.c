/** @file Slice-local BaseLib adapters. SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>

UINT16 EFIAPI SwapBytes16 (IN UINT16 Value) { return __builtin_bswap16 (Value); }
UINT32 EFIAPI SwapBytes32 (IN UINT32 Value) { return __builtin_bswap32 (Value); }
UINT16 EFIAPI
ReadUnaligned16 (IN CONST UINT16 *Buffer)
{
  CONST volatile UINT8 *Bytes = (CONST volatile UINT8 *)Buffer;
  return (UINT16)(Bytes[0] | ((UINT16)Bytes[1] << 8));
}

UINT32 EFIAPI
ReadUnaligned32 (IN CONST UINT32 *Buffer)
{
  CONST volatile UINT8 *Bytes = (CONST volatile UINT8 *)Buffer;
  return Bytes[0] | ((UINT32)Bytes[1] << 8) | ((UINT32)Bytes[2] << 16) | ((UINT32)Bytes[3] << 24);
}

UINT16 EFIAPI
WriteUnaligned16 (OUT UINT16 *Buffer, IN UINT16 Value)
{
  volatile UINT8 *Bytes = (volatile UINT8 *)Buffer;
  Bytes[0] = (UINT8)Value;
  Bytes[1] = (UINT8)(Value >> 8);
  return Value;
}

UINT32 EFIAPI
WriteUnaligned32 (OUT UINT32 *Buffer, IN UINT32 Value)
{
  volatile UINT8 *Bytes = (volatile UINT8 *)Buffer;
  Bytes[0] = (UINT8)Value;
  Bytes[1] = (UINT8)(Value >> 8);
  Bytes[2] = (UINT8)(Value >> 16);
  Bytes[3] = (UINT8)(Value >> 24);
  return Value;
}
BOOLEAN EFIAPI IsZeroBuffer (IN CONST VOID *Buffer, IN UINTN Length) {
  CONST UINT8 *Bytes = Buffer;
  UINTN Index;
  for (Index = 0; Index < Length; Index++) { if (Bytes[Index] != 0) { return FALSE; } }
  return TRUE;
}
