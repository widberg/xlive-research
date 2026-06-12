#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "c_small_buffer.hpp"

// enum SP_CRYPTO_CIPHER_PADDING_TYPE
enum class SP_CRYPTO_CIPHER_PADDING_TYPE : int {
    NONE = 0,
    PKCS5 = 1
};

// enum SP_CRYPTO_VAULT_TYPE
enum class SP_CRYPTO_VAULT_TYPE : int {
    NONE = 0,
    OBFUSCATE = 1,
    SYSTEM_LINK = 2,
    // DRM = 3,
    USER_DATA = 4
};

class PanoramaCryptoCBC {
    SP_CRYPTO_CIPHER_PADDING_TYPE padding = SP_CRYPTO_CIPHER_PADDING_TYPE::PKCS5;
    CSmallBufferNoDestruct<unsigned char[32]> cbc_input_block;
    CSmallBufferNoDestruct<unsigned char[16]> iv;
    SP_CRYPTO_VAULT_TYPE key_set = SP_CRYPTO_VAULT_TYPE::NONE;
    CRITICAL_SECTION critical_section;
public:
    PanoramaCryptoCBC();
    ~PanoramaCryptoCBC();
    HRESULT BlockEncrypt(SB_PTR<unsigned char> plain, unsigned long sixteen, SB_PTR<unsigned char> cypher);
    HRESULT BlockDecrypt(SB_PTR<unsigned char> cypher, unsigned long sixteen, SB_PTR<unsigned char> plain);
    HRESULT SetPadding(SP_CRYPTO_CIPHER_PADDING_TYPE padding);
    HRESULT SetIV(unsigned char const *data, unsigned long sixteen);
    HRESULT GenerateAndSetRandomIV(unsigned char *iv);
    HRESULT InitInternals();
    HRESULT EncryptUpdate(SB_PTR<unsigned char> plain, unsigned long plain_size, SB_PTR<unsigned char> cypher, unsigned long *p_cypher_size);
    HRESULT EncryptFinal(SB_PTR<unsigned char> cypher, unsigned long *p_cypher_size);
    HRESULT Encrypt(SB_PTR<unsigned char> plain, unsigned long plain_size, SB_PTR<unsigned char> cypher, unsigned long *p_cypher_size);
    HRESULT DecryptUpdateNoPad(SB_PTR<unsigned char> cypher, unsigned long cypher_size, SB_PTR<unsigned char> plain, unsigned long *p_plain_size);
    HRESULT DecryptUpdatePKCS5Pad(SB_PTR<unsigned char> cypher, unsigned long cypher_size, SB_PTR<unsigned char> plain, unsigned long *p_plain_size);
    HRESULT DecryptUpdate(SB_PTR<unsigned char> cypher, unsigned long cypher_size, SB_PTR<unsigned char> plain, unsigned long *p_plain_size);
    HRESULT DecryptFinalNoPad(SB_PTR<unsigned char> plain, unsigned long *p_plain_size);
    HRESULT DecryptFinalPKCS5Pad(SB_PTR<unsigned char> plain, unsigned long *p_plain_size);
    HRESULT DecryptFinal(SB_PTR<unsigned char> plain, unsigned long *p_plain_size);
    HRESULT SetBlockCipher(SP_CRYPTO_VAULT_TYPE key_set);
    HRESULT Decrypt(SB_PTR<unsigned char> cypher, unsigned long cypher_size, SB_PTR<unsigned char> plain, unsigned long *p_plain_size);
};

extern PanoramaCryptoCBC *g_pcbcObfuscation;
// extern PanoramaCryptoCBC *g_pcbcXLiveDRM;
extern PanoramaCryptoCBC *g_pcbcSystemLink;
extern PanoramaCryptoCBC *g_pcbcXLiveUserData;

void GenerateRandomBytes(unsigned char *buffer, size_t size);

HRESULT InitializeKeyVaults();
void ShutDownKeyVaults();
