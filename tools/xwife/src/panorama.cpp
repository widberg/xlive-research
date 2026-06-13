#include "panorama.hpp"

#include "aes.hpp"

#include <cstdlib>
#include <ctime>
#include <slerror.h>

// helper for simplified random fills
void GenerateRandomBytes(unsigned char *buffer, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        buffer[i] = rand() & 0xFF;
    }
}

// ??0PanoramaCryptoCBC@@QAE@XZ
PanoramaCryptoCBC::PanoramaCryptoCBC() {
    InitializeCriticalSection(&this->critical_section);
}

// ??1PanoramaCryptoCBC@@QAE@XZ
PanoramaCryptoCBC::~PanoramaCryptoCBC() {
    DeleteCriticalSection(&this->critical_section);
    this->iv.Destroy();
    this->cbc_input_block.Destroy();
}

// ?BlockEncrypt@PanoramaCryptoCBC@@AAEJV?$SB_PTR@E@@K0@Z
HRESULT PanoramaCryptoCBC::BlockEncrypt(SB_PTR<unsigned char> plain, unsigned long sixteen, SB_PTR<unsigned char> cypher) {
    switch (this->key_set) {
    case SP_CRYPTO_VAULT_TYPE::OBFUSCATE:
        return ObfuscationEncryptBlock(plain, cypher, sixteen);
    case SP_CRYPTO_VAULT_TYPE::SYSTEM_LINK:
        return SystemLinkEncryptBlock(plain, cypher, sixteen);
    case SP_CRYPTO_VAULT_TYPE::DRM:
        return DRMEncryptBlock(plain, cypher, sixteen);
    case SP_CRYPTO_VAULT_TYPE::USER_DATA:
        return UserDataEncryptBlock(plain, cypher, sixteen);
    default:
        break;
    }
    return SL_REMAPPING_SP_STATUS_INVALIDARG;
}

// ?BlockDecrypt@PanoramaCryptoCBC@@AAEJV?$SB_PTR@E@@K0@Z
HRESULT PanoramaCryptoCBC::BlockDecrypt(SB_PTR<unsigned char> cypher, unsigned long sixteen, SB_PTR<unsigned char> plain) {
    switch (this->key_set) {
    case SP_CRYPTO_VAULT_TYPE::OBFUSCATE:
        return ObfuscationDecryptBlock(cypher, plain, sixteen);
    case SP_CRYPTO_VAULT_TYPE::SYSTEM_LINK:
        return SystemLinkDecryptBlock(cypher, plain, sixteen);
    case SP_CRYPTO_VAULT_TYPE::DRM:
        return DRMDecryptBlock(cypher, plain, sixteen);
    case SP_CRYPTO_VAULT_TYPE::USER_DATA:
        return UserDataDecryptBlock(cypher, plain, sixteen);
    default:
        break;
    }
    return SL_REMAPPING_SP_STATUS_INVALIDARG;
}

// ?SetPadding@PanoramaCryptoCBC@@QAEJW4SP_CRYPTO_CIPHER_PADDING_TYPE@@@Z
HRESULT PanoramaCryptoCBC::SetPadding(SP_CRYPTO_CIPHER_PADDING_TYPE padding)
{
    this->padding = padding;
    return ERROR_SUCCESS;
}

// ?SetIV@PanoramaCryptoCBC@@QAEJPBEK@Z
HRESULT PanoramaCryptoCBC::SetIV(unsigned char const *data, unsigned long sixteen) {
    if ( sixteen > 16 )
        return SL_REMAPPING_SP_STATUS_INVALIDARG;
    if ( !this->iv.ptr() )
        return ERROR_OUTOFMEMORY;
    this->iv.size = sixteen;
    memcpy(this->iv.ptr(), data, sixteen);
    return ERROR_SUCCESS;
}

// ?GenerateAndSetRandomIV@PanoramaCryptoCBC@@QAEJPAE@Z
HRESULT PanoramaCryptoCBC::GenerateAndSetRandomIV(unsigned char *iv) {
    // Simplified
    GenerateRandomBytes(iv, 16);
    return this->SetIV(iv, 16);
}

// ?InitInternals@PanoramaCryptoCBC@@AAEJXZ
HRESULT PanoramaCryptoCBC::InitInternals() {
    if ( !this->cbc_input_block.alloc(32) )
        return ERROR_OUTOFMEMORY;
    if ( !this->iv.alloc(16) )
        return ERROR_OUTOFMEMORY;
    memset(this->iv.ptr(), 0, 16);
    return ERROR_SUCCESS;
}

// ?EncryptUpdate@PanoramaCryptoCBC@@AAEJV?$SB_PTR@E@@K0PAK@Z
HRESULT PanoramaCryptoCBC::EncryptUpdate(SB_PTR<unsigned char> plain, unsigned long plain_size, SB_PTR<unsigned char> cypher, unsigned long *p_cypher_size) {
  int result;                                        // eax
  unsigned int cypher_size;                          // ecx
  unsigned int v9;                                         // eax
  unsigned int v10;                                  // eax
  __SecureBufferHandleStruct *cbc_input_block_buf;   // eax MAPDST
  unsigned int v12;                                  // ebx
  unsigned int v13;                                  // edi
  int v14;                                           // eax
  unsigned int v15;                                  // ebx
  unsigned int v16;                                  // edi
  unsigned char *cbc_input_block_ptr;                // eax
  __SecureBufferHandleStruct *cbc_input_block_buf_1; // eax
  unsigned int v19;                                  // ecx
  unsigned int v20;                                        // edi
  char v21;                                          // bl
  unsigned int j;                                    // esi
  char iv_buf_tmp;                                   // bl
  CSBPseudoPtr cbc_input_block_csb_1;                // [esp+Ch] [ebp-40h] BYREF
  CSBPseudoPtr iv_csb;                           // [esp+14h] [ebp-38h] BYREF
  CSBPseudoPtr cbc_input_block_csb;              // [esp+1Ch] [ebp-30h] BYREF
  unsigned int v28;                              // [esp+28h] [ebp-24h]
  __SecureBufferHandleStruct *iv_buf;            // [esp+2Ch] [ebp-20h]
  unsigned int v30;                                    // [esp+30h] [ebp-1Ch]
  CSmallBufferNoDestruct<unsigned char[16]> *iv; // [esp+34h] [ebp-18h]
  int k;                                         // [esp+38h] [ebp-14h]
  unsigned int v33;                              // [esp+3Ch] [ebp-10h]
  unsigned int v34;                              // [esp+40h] [ebp-Ch]
  unsigned int v35;                              // [esp+44h] [ebp-8h]
  unsigned int i;                                // [esp+48h] [ebp-4h]
  char cypher_3;                                 // [esp+5Fh] [ebp+13h]
  char cypher_3a;                                // [esp+5Fh] [ebp+13h]

  cbc_input_block_csb.obfuscation_data = 0;
  iv_csb.obfuscation_data = 0;
  if (!p_cypher_size)
    return SL_REMAPPING_SP_STATUS_INVALIDARG;
  if (!plain.ptr || !plain_size)
    return 0;
  cypher_size = *p_cypher_size;
  v9 = plain_size + this->cbc_input_block.size;
  if (v9 < plain_size)
    return SL_REMAPPING_SP_STATUS_INSUFFICIENT_BUFFER;
  v33 = v9 >> 4;
  v10 = 16 * (v9 >> 4);
  v35 = v10;
  if (cypher_size < v10 || !cypher.ptr || v10 < 0x10 && v10) {
    *p_cypher_size = v10;
    return cypher.ptr != 0 ? SL_REMAPPING_SP_STATUS_INSUFFICIENT_BUFFER : ERROR_SUCCESS;
  }
  cbc_input_block_csb.ptr = this->cbc_input_block.ptr();
  cbc_input_block_buf = (__SecureBufferHandleStruct *)cbc_input_block_csb;
  v28 = 0;
  iv = &this->iv;
  iv_csb.ptr = this->iv.ptr();
  iv_buf = (__SecureBufferHandleStruct *)iv_csb;
  v30 = 0;
  v34 = 0;
  for (i = 0; this->cbc_input_block.size < 0x10 && i < plain_size; ++i) {
    cypher_3 = SBufferGetByte(plain.ptr, i + plain.begin);
    this->cbc_input_block.ptr()[this->cbc_input_block.size] = cypher_3;
    ++this->cbc_input_block.size;
  }
  v12 = plain_size - i - v35;
  v35 = 0;
  this->cbc_input_block.size += v12;
  if (!v33) {
  LABEL_21:
    v20 = 0;
    for (*p_cypher_size = v34; v20 < this->cbc_input_block.size; ++v20) {
      v21 = SBufferGetByte(cbc_input_block_buf, v28 + v20);
      this->cbc_input_block.ptr()[v20] = v21;
    }
    for (j = 0; j < 0x10; ++j) {
      iv_buf_tmp = SBufferGetByte(iv_buf, v30 + j);
      iv->ptr()[j] = iv_buf_tmp;
    }
    return 0;
  }
  while (1) {
    v13 = 0;
    v14 = v28 - v30;
    for (k = v28 - v30;; v14 = k) {
      v15 = v30 + v13;
      cypher_3a = SBufferGetByte(cbc_input_block_buf, v14 + v30 + v13);
      this->cbc_input_block.ptr()[v13++] =
          cypher_3a ^ SBufferGetByte(iv_buf, v15);
      if (v13 >= 0x10)
        break;
    }
    v16 = cypher.begin + v34;
    iv_buf = cypher.ptr;
    v30 = cypher.begin + v34;
    cbc_input_block_ptr = this->cbc_input_block.ptr();
    cbc_input_block_csb_1.obfuscation_data = 0;
    cbc_input_block_csb_1.ptr = cbc_input_block_ptr;
    cbc_input_block_buf_1 = (__SecureBufferHandleStruct *)cbc_input_block_csb_1;
    result = this->BlockEncrypt(SB_PTR<unsigned char> {cbc_input_block_buf_1, 0},
                                16, SB_PTR<unsigned char> {cypher.ptr, v16});
    if (result)
      return result;
    v19 = i;
    i += 16;
    v34 += 16;
    ++v35;
    v28 = v19 + plain.begin;
    cbc_input_block_buf = plain.ptr;
    if (v35 >= v33)
      goto LABEL_21;
  }
}

// ?EncryptFinal@PanoramaCryptoCBC@@AAEJV?$SB_PTR@E@@PAK@Z
HRESULT PanoramaCryptoCBC::EncryptFinal(SB_PTR<unsigned char> cypher, unsigned long *p_cypher_size) {
  SP_CRYPTO_CIPHER_PADDING_TYPE padding; // ecx
  HRESULT v5; // ebx
  unsigned int i; // edi
  char remaining; // bl
  unsigned int j; // edi
  unsigned char *cbc_input_block_j_p; // ebx
  __SecureBufferHandleStruct *cbc_input_block_buf; // eax
  char *iv_csb; // eax
  CSBPseudoPtr cbc_input_block_csb; // [esp+Ch] [ebp-8h] BYREF
  CSmallBufferNoDestruct<unsigned char[16]> *iv; // [esp+24h] [ebp+10h]

  padding = this->padding;
  v5 = E_FAIL;
  if ( padding == SP_CRYPTO_CIPHER_PADDING_TYPE::NONE )
    return this->cbc_input_block.size != 0 ? E_FAIL : ERROR_SUCCESS;
  if ( padding == SP_CRYPTO_CIPHER_PADDING_TYPE::PKCS5 )
  {
    if ( *p_cypher_size < 0x10u || !cypher.ptr )
    {
      *p_cypher_size = 16;
      return cypher.ptr != 0 ? SL_REMAPPING_SP_STATUS_INSUFFICIENT_BUFFER : ERROR_SUCCESS;
    }
    for ( i = this->cbc_input_block.size; i < 0x10; ++i )
    {
      remaining = 16 - LOBYTE(this->cbc_input_block.size);
      this->cbc_input_block.ptr()[i] = remaining;
    }
    j = 0;
    iv = &this->iv;
    do
    {
      cbc_input_block_j_p = &this->cbc_input_block.ptr()[j];
      *cbc_input_block_j_p ^= iv->ptr()[j++];
    }
    while ( j < 0x10 );
    cbc_input_block_csb.obfuscation_data = 0;
    cbc_input_block_csb.ptr = this->cbc_input_block.ptr();
    cbc_input_block_buf = (__SecureBufferHandleStruct *)cbc_input_block_csb;
    v5 = this->BlockEncrypt(SB_PTR<unsigned char> { cbc_input_block_buf, 0}, 16, cypher);
    if ( !v5 )
    {
      this->cbc_input_block.size = 0;
      memset(iv->ptr(), 0, 16);
    }
  }
  return v5;
}

// ?Encrypt@PanoramaCryptoCBC@@QAEJV?$SB_PTR@E@@K0PAK@Z
HRESULT PanoramaCryptoCBC::Encrypt(SB_PTR<unsigned char> plain, unsigned long plain_size, SB_PTR<unsigned char> cypher, unsigned long *p_cypher_size) {
  HRESULT result;                          // eax MAPDST
  unsigned long old_cypher_size;       // esi
  CRITICAL_SECTION *lpCriticalSection; // [esp+8h] [ebp-4h]
  unsigned long cypher_size;           // [esp+28h] [ebp+1Ch] FORCED BYREF

  lpCriticalSection = &this->critical_section;
  EnterCriticalSection(&this->critical_section);
  if (!p_cypher_size)
    return SL_REMAPPING_SP_STATUS_INVALIDARG;
  cypher_size = *p_cypher_size;
  result = this->EncryptUpdate(plain, plain_size, cypher, &cypher_size);
  if (!result) {
    old_cypher_size = cypher_size;
    if (*p_cypher_size < cypher_size && cypher.ptr) {
      result = SL_REMAPPING_SP_STATUS_INSUFFICIENT_BUFFER;
    } else {
      cypher_size = *p_cypher_size - cypher_size;
      if (cypher.ptr)
        cypher.begin += old_cypher_size;
      result = this->EncryptFinal(cypher, &cypher_size);
      *p_cypher_size = old_cypher_size + cypher_size;
      LeaveCriticalSection(lpCriticalSection);
    }
  }
  return result;
}

// ?DecryptUpdateNoPad@PanoramaCryptoCBC@@AAEJV?$SB_PTR@E@@K0PAK@Z
HRESULT PanoramaCryptoCBC::DecryptUpdateNoPad(SB_PTR<unsigned char> cypher, unsigned long cypher_size, SB_PTR<unsigned char> plain, unsigned long *p_plain_size) {
  unsigned int v7; // edi
  unsigned int v8; // eax
  HRESULT result; // eax
  unsigned int v10; // eax MAPDST
  __SecureBufferHandleStruct *v11; // eax
  unsigned int v12; // ebx
  int v13; // eax
  unsigned int v14; // eax
  unsigned int i; // edi
  char iv_tmp; // bl
  unsigned int j; // edi
  char cbc_input_block_tmp; // bl
  CSBPseudoPtr v19; // [esp+Ch] [ebp-44h] BYREF
  CSBPseudoPtr v20; // [esp+14h] [ebp-3Ch] BYREF
  SB_PTR<unsigned char> v22; // [esp+24h] [ebp-2Ch]
  SB_PTR<unsigned char> v23; // [esp+2Ch] [ebp-24h]
  char a3; // [esp+34h] [ebp-1Ch]
  int v25; // [esp+38h] [ebp-18h]
  unsigned int v27; // [esp+40h] [ebp-10h]
  int v28; // [esp+44h] [ebp-Ch]
  unsigned int v29; // [esp+48h] [ebp-8h]
  int a2; // [esp+4Ch] [ebp-4h]
  char cypher_size_3; // [esp+63h] [ebp+13h]
  char cypher_size_3a; // [esp+63h] [ebp+13h]

  v7 = 0;
  v8 = cypher_size + this->cbc_input_block.size;
  v20.obfuscation_data = 0;
  v19.obfuscation_data = 0;
  if ( v8 < cypher_size )
    return SL_REMAPPING_SP_STATUS_INSUFFICIENT_BUFFER;
  v27 = v8 >> 4;
  v10 = 16 * (v8 >> 4);
  if ( *p_plain_size >= v10 && plain.ptr && v10 >= 0x10 )
  {
    v20.ptr = this->cbc_input_block.ptr();
    v11 = (__SecureBufferHandleStruct *)v20;
    v23.begin = 0;
    v23.ptr = v11;
    v19.ptr = this->iv.ptr();
    v22 = SB_PTR<unsigned char> {(__SecureBufferHandleStruct *)v19, 0};
    while ( this->cbc_input_block.size < 0x10 && v7 < cypher_size )
    {
      cypher_size_3 = SBufferGetByte(cypher.ptr, cypher.begin + v7);
      this->cbc_input_block.ptr()[this->cbc_input_block.size] = cypher_size_3;
      ++this->cbc_input_block.size;
      ++v7;
    }
    v29 = 0;
    this->cbc_input_block.size += cypher_size - v7 - v10;
    v12 = plain.begin;
    if ( v27 )
    {
      while ( 1 )
      {
        result = this->BlockDecrypt(v23, 16, SB_PTR<unsigned char> {plain.ptr, v12});
        if ( result )
          break;
        v13 = v22.begin - v12;
        a2 = v12;
        v25 = v22.begin - v12;
        v28 = 16;
        while ( 1 )
        {
          cypher_size_3a = SBufferGetByte(v22.ptr, v13 + a2);
          a3 = cypher_size_3a ^ SBufferGetByte(plain.ptr, a2);
          SBufferSetByte(plain.ptr, a2++, a3);
          if ( !--v28 )
            break;
          v13 = v25;
        }
        v22 = v23;
        v14 = v7 + cypher.begin;
        v12 += 16;
        v7 += 16;
        ++v29;
        v23.begin = v14;
        v23.ptr = cypher.ptr;
        if ( v29 >= v27 )
          goto LABEL_16;
      }
    }
    else
    {
LABEL_16:
      *p_plain_size = v10;
      for ( i = 0; i < 0x10; ++i )
      {
        iv_tmp = SBufferGetByte(v22.ptr, v22.begin + i);
        this->iv.ptr()[i] = iv_tmp;
      }
      for ( j = 0; j < this->cbc_input_block.size; ++j )
      {
        cbc_input_block_tmp = SBufferGetByte(v23.ptr, v23.begin + j);
        this->cbc_input_block.ptr()[j] = cbc_input_block_tmp;
      }
      result = 0;
    }
  }
  else
  {
    *p_plain_size = v10;
    result = plain.ptr != 0 ? SL_REMAPPING_SP_STATUS_INSUFFICIENT_BUFFER : ERROR_SUCCESS;
  }
  return result;
}

// ?DecryptUpdatePKCS5Pad@PanoramaCryptoCBC@@AAEJV?$SB_PTR@E@@K0PAK@Z
HRESULT PanoramaCryptoCBC::DecryptUpdatePKCS5Pad(SB_PTR<unsigned char> cypher, unsigned long cypher_size, SB_PTR<unsigned char> plain, unsigned long *p_plain_size) {
  unsigned int v6; // ecx
  unsigned int v8; // ebx
  int result; // eax
  unsigned char *v10; // eax
  unsigned int v11; // eax
  unsigned int v12; // edi
  __SecureBufferHandleStruct *v13; // eax
  unsigned int v14; // edi
  __SecureBufferHandleStruct *v15; // eax
  bool v16; // zf
  int v17; // eax
  unsigned int i; // ebx
  unsigned int j; // ebx
  CSBPseudoPtr v20; // [esp+Ch] [ebp-38h] BYREF
  CSBPseudoPtr v21; // [esp+14h] [ebp-30h] OVERLAPPED BYREF
  __SecureBufferHandleStruct *a1; // [esp+1Ch] [ebp-28h]
  int a2; // [esp+20h] [ebp-24h]
  SB_PTR<unsigned char> v25; // [esp+24h] [ebp-20h]
  unsigned __int8 value; // [esp+2Ch] [ebp-18h]
  int v27; // [esp+30h] [ebp-14h]
  char a3; // [esp+34h] [ebp-10h] OVERLAPPED
  int v29; // [esp+34h] [ebp-10h] FORCED
  unsigned int v30; // [esp+38h] [ebp-Ch]
  unsigned int index; // [esp+3Ch] [ebp-8h]
  unsigned int v32; // [esp+40h] [ebp-4h]
  char cypher_sizea; // [esp+54h] [ebp+10h]
  char cypher_size_3; // [esp+57h] [ebp+13h]
  char cypher_size_3a; // [esp+57h] [ebp+13h]
  char cypher_size_3b; // [esp+57h] [ebp+13h]
  char p_plain_size_3; // [esp+63h] [ebp+1Fh]
  char p_plain_size_3a; // [esp+63h] [ebp+1Fh]

  v6 = this->cbc_input_block.size;
  v8 = 0;
  v20.obfuscation_data = 0;
  if ( v6 + cypher_size < cypher_size )
    return SL_REMAPPING_SP_STATUS_INSUFFICIENT_BUFFER;
  if ( !plain.ptr )
  {
    *p_plain_size = 16 * ((v6 + cypher_size + 15) >> 4);
    return 0;
  }
  if ( v6 + cypher_size <= 0x10 )
  {
    if ( cypher_size )
    {
      do
      {
        cypher_size_3 = SBufferGetByte(cypher.ptr, cypher.begin + v8);
        v10 = &this->cbc_input_block.ptr()[v8++];
        v10[this->cbc_input_block.size] = cypher_size_3;
      }
      while ( v8 < cypher_size );
    }
    this->cbc_input_block.size += cypher_size;
    *p_plain_size = 0;
    return 0;
  }
  v30 = ((v6 + cypher_size + 15) >> 4) - 1;
  v11 = 16 * v30;
  v32 = 16 * v30;
  if ( *p_plain_size < 16 * v30 )
  {
    *p_plain_size = v11;
    return SL_REMAPPING_SP_STATUS_INSUFFICIENT_BUFFER;
  }
  if ( v6 < 0x10 )
  {
    do
    {
      if ( v8 >= cypher_size )
        break;
      cypher_size_3a = SBufferGetByte(cypher.ptr, cypher.begin + v8);
      this->cbc_input_block.ptr()[this->cbc_input_block.size] = cypher_size_3a;
      ++this->cbc_input_block.size;
      v11 = v32;
      ++v8;
    }
    while ( this->cbc_input_block.size < 0x10 );
  }
  this->cbc_input_block.size += cypher_size - v11 - v8;
  v12 = 0;
  v21.obfuscation_data = 0;
  v21.ptr = this->cbc_input_block.ptr();
  v13 = (__SecureBufferHandleStruct *)v21;
  result = this->BlockDecrypt(SB_PTR<unsigned char> {v13, 0}, 16, plain);
  if ( !result )
  {
    do
    {
      a1 = plain.ptr;
      a2 = v12 + plain.begin;
      cypher_sizea = this->iv.ptr()[v12];
      a3 = cypher_sizea ^ SBufferGetByte(plain.ptr, a2);
      SBufferSetByte(a1, a2, a3);
      ++v12;
    }
    while ( v12 < 0x10 );
    v25.ptr = cypher.ptr;
    v25.begin = v8 + cypher.begin;
    v14 = plain.begin + 16;
    v20.ptr = this->cbc_input_block.ptr();
    v15 = (__SecureBufferHandleStruct *)v20;
    v16 = v30-- == 1;
    a1 = v15;
    a2 = 0;
    v32 = 0;
    if ( v16 )
    {
LABEL_21:
      *p_plain_size = 16 * (v30 + 1);
      for ( i = 0; i < 0x10; ++i )
      {
        p_plain_size_3 = SBufferGetByte(a1, a2 + i);
        this->iv.ptr()[i] = p_plain_size_3;
      }
      for ( j = 0; j < this->cbc_input_block.size; ++j )
      {
        p_plain_size_3a = SBufferGetByte(v25.ptr, v25.begin + j);
        this->cbc_input_block.ptr()[j] = p_plain_size_3a;
      }
      return 0;
    }
    while ( 1 )
    {
      result = this->BlockDecrypt(v25, 16, SB_PTR<unsigned char> {plain.ptr, v14});
      if ( result )
        break;
      v17 = a2 - v14;
      index = v14;
      v27 = a2 - v14;
      v29 = 16;
      while ( 1 )
      {
        cypher_size_3b = SBufferGetByte(a1, v17 + index);
        value = cypher_size_3b ^ SBufferGetByte(plain.ptr, index);
        SBufferSetByte(plain.ptr, index++, value);
        if ( !--v29 )
          break;
        v17 = v27;
      }
      a1 = v25.ptr;
      a2 = v25.begin;
      v8 += 16;
      v14 += 16;
      ++v32;
      v25.begin = v8 + cypher.begin;
      v25.ptr = cypher.ptr;
      if ( v32 >= v30 )
        goto LABEL_21;
    }
  }
  return result;
}

// ?DecryptUpdate@PanoramaCryptoCBC@@AAEJV?$SB_PTR@E@@K0PAK@Z
HRESULT PanoramaCryptoCBC::DecryptUpdate(SB_PTR<unsigned char> cypher, unsigned long cypher_size, SB_PTR<unsigned char> plain, unsigned long *p_plain_size) {
  if ( !p_plain_size )
    return E_INVALIDARG;
  if ( this->padding == SP_CRYPTO_CIPHER_PADDING_TYPE::NONE )
    return this->DecryptUpdateNoPad(cypher, cypher_size, plain, p_plain_size);
  if ( this->padding == SP_CRYPTO_CIPHER_PADDING_TYPE::PKCS5 )
    return this->DecryptUpdatePKCS5Pad(cypher, cypher_size, plain, p_plain_size);
  return E_FAIL;
}

// ?DecryptFinalNoPad@PanoramaCryptoCBC@@AAEJV?$SB_PTR@E@@PAK@Z
HRESULT PanoramaCryptoCBC::DecryptFinalNoPad(SB_PTR<unsigned char> plain, unsigned long *p_plain_size) {
  HRESULT result; // eax

  if ( !p_plain_size )
    return SL_REMAPPING_SP_STATUS_INVALIDARG;
  result = this->cbc_input_block.size != 0 ? E_FAIL : ERROR_SUCCESS;
  *p_plain_size = 0;
  return result;
}

// ?DecryptFinalPKCS5Pad@PanoramaCryptoCBC@@AAEJV?$SB_PTR@E@@PAK@Z
HRESULT PanoramaCryptoCBC::DecryptFinalPKCS5Pad(SB_PTR<unsigned char> plain, unsigned long *p_plain_size) {
  unsigned int v3; // ebx
  unsigned int v6; // eax
  unsigned char *v7; // esi MAPDST
  unsigned char *v8; // esi
  unsigned char *v9; // eax
  __SecureBufferHandleStruct *v10; // eax
  unsigned int v11; // eax
  unsigned char *v12; // eax
  unsigned char *v13; // eax
  unsigned int v14; // eax
  unsigned char *v15; // ecx
  int v16; // edx
  unsigned int i; // edi
  SB_PTR<unsigned char> v19; // [esp-8h] [ebp-64h]
  CSBPseudoPtr v20; // [esp+Ch] [ebp-50h] BYREF
  CSBPseudoPtr v21; // [esp+14h] [ebp-48h] BYREF
  unsigned int plain_size; // [esp+1Ch] [ebp-40h]
  HRESULT v25; // [esp+28h] [ebp-34h]
  unsigned char *v26; // [esp+2Ch] [ebp-30h]
  unsigned int v27; // [esp+2Ch] [ebp-30h] FORCED
  unsigned __int8 v28; // [esp+33h] [ebp-29h]
  CSmallBufferNoDestruct<unsigned char[32]> v29; // [esp+34h] [ebp-28h] BYREF

  v3 = 0;
  v25 = 0;
  v29.zero_init = 0;
  if ( !p_plain_size )
    return SL_REMAPPING_SP_STATUS_INVALIDARG;
  plain_size = *p_plain_size;
  if ( !plain.ptr )
  {
    *p_plain_size = 16;
    return 0;
  }
  v6 = this->cbc_input_block.size;
  if ( v6 && (v6 & 0xF) == 0 && v6 <= 0x20 )
  {
    v26 = this->iv.ptr();
    v7 = v29.alloc(0x20u);
    if ( v7 )
    {
      if ( this->cbc_input_block.size )
      {
        do
        {
          v20.obfuscation_data = 0;
          v8 = &v7[v3];
          v20.ptr = v8;
          v19 = SB_PTR<unsigned char> { (__SecureBufferHandleStruct *)v20, 0};
          v9 = this->cbc_input_block.ptr();
          v21.obfuscation_data = 0;
          v21.ptr = &v9[v3];
          v10 = (__SecureBufferHandleStruct *)v21;
          v11 = this->BlockDecrypt(SB_PTR<unsigned char> { v10, 0}, 16, v19);
          v25 = v11;
          if ( v11 )
            goto LABEL_24;
          do
          {
            v8[v11] ^= v26[v11];
            ++v11;
          }
          while ( v11 < 0x10 );
          v12 = this->cbc_input_block.ptr();
          v13 = &v12[v3];
          v3 += 16;
          v26 = v13;
        }
        while ( v3 < this->cbc_input_block.size );
      }
      v14 = this->cbc_input_block.size;
      v15 = &v7[v14 - 1];
      v28 = *v15;
      v16 = v28;
      if ( v28 <= 0x10u )
      {
        v27 = 0;
        if ( !v28 )
        {
LABEL_18:
          *p_plain_size = v14 - v28;
          if ( plain_size >= this->cbc_input_block.size - v16 )
          {
            for ( i = 0; i < *p_plain_size; ++i )
              SBufferSetByte(plain.ptr, plain.begin + i, v7[i]);
          }
          else
          {
            v25 = plain.ptr != 0 ? SL_REMAPPING_SP_STATUS_INSUFFICIENT_BUFFER : ERROR_SUCCESS;
          }
          goto LABEL_24;
        }
        while ( *v15 == v28 )
        {
          ++v27;
          --v15;
          if ( v27 >= v28 )
            goto LABEL_18;
        }
      }
      v25 = SL_REMAPPING_SP_STATUS_INVALIDDATA;
    }
    else
    {
      v25 = E_OUTOFMEMORY;
    }
LABEL_24:
    v29.Destroy();
    return v25;
  }
  return E_INVALIDARG;
}

// ?DecryptFinal@PanoramaCryptoCBC@@AAEJV?$SB_PTR@E@@PAK@Z
HRESULT PanoramaCryptoCBC::DecryptFinal(SB_PTR<unsigned char> plain, unsigned long *p_plain_size) {
  HRESULT result; // ebx MAPDST

    result = E_FAIL;
    if ( !p_plain_size )
        return E_INVALIDARG;
    if ( this->padding == SP_CRYPTO_CIPHER_PADDING_TYPE::NONE )
        result = this->DecryptFinalNoPad(plain, p_plain_size);
    if ( this->padding == SP_CRYPTO_CIPHER_PADDING_TYPE::PKCS5 )
        result = this->DecryptFinalPKCS5Pad(plain, p_plain_size);
    this->cbc_input_block.size = 0;
    memset(this->iv.ptr(), 0, 16);
    return result;
}

// ?SetBlockCipher@PanoramaCryptoCBC@@QAEJW4SP_CRYPTO_VAULT_TYPE@@@Z
HRESULT PanoramaCryptoCBC::SetBlockCipher(SP_CRYPTO_VAULT_TYPE key_set) {
    HRESULT result;

    result = this->InitInternals();
    if (result == ERROR_SUCCESS)
        this->key_set = key_set;
    return result;
}

// ?Decrypt@PanoramaCryptoCBC@@QAEJV?$SB_PTR@E@@K0PAK@Z
HRESULT PanoramaCryptoCBC::Decrypt(SB_PTR<unsigned char> cypher, unsigned long cypher_size, SB_PTR<unsigned char> plain, unsigned long *p_plain_size) {
  HRESULT result; // eax MAPDST
  unsigned int old_plain_size; // esi
  CRITICAL_SECTION *lpCriticalSection; // [esp+8h] [ebp-4h]
  unsigned long plain_size; // [esp+28h] [ebp+1Ch] FORCED BYREF

  lpCriticalSection = &this->critical_section;
  EnterCriticalSection(&this->critical_section);
  if ( !p_plain_size )
    return SL_REMAPPING_SP_STATUS_INVALIDARG;
  plain_size = *p_plain_size;
  result = this->DecryptUpdate(cypher, cypher_size, plain, &plain_size);
  if ( !result )
  {
    old_plain_size = plain_size;
    if ( *p_plain_size < plain_size && plain.ptr )
    {
      result = SL_REMAPPING_SP_STATUS_INSUFFICIENT_BUFFER;
    }
    else
    {
      plain_size = *p_plain_size - plain_size;
      if ( plain.ptr )
        plain.begin += old_plain_size;
      result = this->DecryptFinal(plain, &plain_size);
      *p_plain_size = old_plain_size + plain_size;
      LeaveCriticalSection(lpCriticalSection);
    }
  }
  return result;
}

// ?g_pcbcObfuscation@@3PAVPanoramaCryptoCBC@@A
PanoramaCryptoCBC *g_pcbcObfuscation = nullptr;

// ?g_pcbcXLiveDRM@@3PAVPanoramaCryptoCBC@@A
PanoramaCryptoCBC *g_pcbcXLiveDRM = nullptr;

// ?g_pcbcSystemLink@@3PAVPanoramaCryptoCBC@@A
PanoramaCryptoCBC *g_pcbcSystemLink = nullptr;

// ?g_pcbcXLiveUserData@@3PAVPanoramaCryptoCBC@@A
PanoramaCryptoCBC *g_pcbcXLiveUserData = nullptr;

// ?InitializeKeyVaults@@YGJXZ
HRESULT InitializeKeyVaults() {
    // Seeding the RNG here is just convenient for this standalone build; the
    // real dll does not do this as part of vault initialization.
    srand((unsigned)time(nullptr));

    g_pcbcObfuscation = new PanoramaCryptoCBC;
    g_pcbcObfuscation->SetBlockCipher(SP_CRYPTO_VAULT_TYPE::OBFUSCATE);

    g_pcbcSystemLink = new PanoramaCryptoCBC;
    g_pcbcSystemLink->SetBlockCipher(SP_CRYPTO_VAULT_TYPE::SYSTEM_LINK);

    g_pcbcXLiveDRM = new PanoramaCryptoCBC;
    g_pcbcXLiveDRM->SetBlockCipher(SP_CRYPTO_VAULT_TYPE::DRM);

    g_pcbcXLiveUserData = new PanoramaCryptoCBC;
    g_pcbcXLiveUserData->SetBlockCipher(SP_CRYPTO_VAULT_TYPE::USER_DATA);

    return ERROR_SUCCESS;
}

// ?ShutDownKeyVaults@@YGXXZ
void ShutDownKeyVaults() {
    delete g_pcbcObfuscation;
    g_pcbcObfuscation = nullptr;
  
    delete g_pcbcSystemLink;
    g_pcbcSystemLink = nullptr;

    delete g_pcbcXLiveDRM;
    g_pcbcXLiveDRM = nullptr;

    delete g_pcbcXLiveUserData;
    g_pcbcXLiveUserData = nullptr;
}
