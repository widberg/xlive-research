#include "xe_keys_obfuscate.hpp"

#include <cassert>
#include <cstdlib>
#include <cstring>

#include "c_small_buffer.hpp"
#include "panorama.hpp"

// ?XeKeysObfuscate@@YGJHPAEK0PAK@Z
NTSTATUS XeKeysObfuscate(int one, unsigned char *plain, unsigned long plain_size, unsigned char *cypher, unsigned long *p_cypher_size) {
  __SecureBufferHandleStruct *plain_buf; // eax
  SB_PTR<unsigned char> cypher_without_extra_buf; // [esp-Ch] [ebp-54h]
  CSBPseudoPtr cypher_csb; // [esp+Ch] [ebp-3Ch] BYREF
  CSBPseudoPtr plain_csb; // [esp+14h] [ebp-34h] BYREF
  unsigned long cypher_size_without_extra; // [esp+20h] [ebp-28h] BYREF
  HRESULT result; // [esp+24h] [ebp-24h]
  char tmp[24]; // [esp+2Ch] [ebp-1Ch] BYREF

  // For my own peace of mind
  assert(one == 1);
  assert(g_pcbcObfuscation != nullptr);

  if ( !plain || !plain_size || !cypher || !p_cypher_size )
    return STATUS_INVALID_PARAMETER;
  memset(tmp, 0, sizeof(tmp));
  memcpy(cypher, tmp, sizeof(tmp));
  cypher_size_without_extra = *p_cypher_size - 0x18;
  result = STATUS_UNSUCCESSFUL;
  cypher_csb.obfuscation_data = 0;
  cypher_csb.ptr = cypher + 0x18;
  cypher_without_extra_buf = SB_PTR<unsigned char> {(__SecureBufferHandleStruct *)cypher_csb, 0};
  plain_csb.obfuscation_data = 0;
  plain_csb.ptr = plain;
  plain_buf = (__SecureBufferHandleStruct *)plain_csb;
  if ( !g_pcbcObfuscation->Encrypt(
          SB_PTR<unsigned char> {plain_buf,0},
          plain_size,
          cypher_without_extra_buf,
          &cypher_size_without_extra) )
  {
    *p_cypher_size = cypher_size_without_extra + 0x18;
    result = STATUS_SUCCESS;
  }
  return result;
}

// ?XeKeysUnObfuscate@@YGHHPAEK0PAK@Z
BOOL XeKeysUnObfuscate(int one, unsigned char *cypher, unsigned long cypher_size, unsigned char *plain, unsigned long *p_plain_size) {
  unsigned char *tmp; // ebx
  unsigned long plain_size; // eax MAPDST
  __SecureBufferHandleStruct *cypher_buf; // eax
  bool cond; // cf
  SB_PTR<unsigned char> tmp_buf; // [esp-Ch] [ebp-3Ch]
  CSBPseudoPtr cypher_csb; // [esp+Ch] [ebp-24h] BYREF
  CSBPseudoPtr tmp_csb; // [esp+14h] [ebp-1Ch] BYREF
  int cypher_size_without_extra; // [esp+1Ch] [ebp-14h]
  BOOL result; // [esp+28h] [ebp-8h]

  // For my own peace of mind
  assert(one == 1);
  assert(g_pcbcObfuscation != nullptr);

  if ( cypher && cypher_size && plain && p_plain_size )
  {
    result = FALSE;
    if ( cypher_size < 0x18 )
      return result;
    tmp = (unsigned char *)malloc(*p_plain_size);
    memset(tmp, 0, *p_plain_size);
    plain_size = *p_plain_size;
    tmp_csb.obfuscation_data = 0;
    cypher_size_without_extra = cypher_size - 0x18;
    tmp_csb.ptr = tmp;
    tmp_buf = SB_PTR<unsigned char> {(__SecureBufferHandleStruct*)tmp_csb, 0};
    cypher_csb.obfuscation_data = 0;
    cypher_csb.ptr = cypher + 0x18;
    cypher_buf = (__SecureBufferHandleStruct *)cypher_csb;
    if ( !g_pcbcObfuscation->Decrypt(
            SB_PTR<unsigned char> {cypher_buf, 0},
            cypher_size_without_extra,
            tmp_buf,
            &plain_size) )
    {
      if ( plain_size == 0x17C )
      {
        *p_plain_size = 0x17C;
        memcpy(plain, tmp, 0x17Cu);
LABEL_11:
        result = TRUE;
        goto LABEL_12;
      }
      cond = *p_plain_size < plain_size;
      *p_plain_size = plain_size;
      if ( !cond )
      {
        memcpy(plain, tmp, plain_size);
        goto LABEL_11;
      }
    }
LABEL_12:
    free(tmp);
    return result;
  }
  return FALSE;
}
