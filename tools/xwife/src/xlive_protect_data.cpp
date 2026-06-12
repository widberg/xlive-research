#include "xlive_protect_data.hpp"

#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <cstring>

#include "panorama.hpp"
#include "syncrosoft.hpp"
#include "sha.hpp"

#define STATIC_ASSERT_OFFSET(type, member, offset, ...) static_assert(offsetof(type, member) == offset, __VA_ARGS__)

// On-disk layout of the protected output buffer. The four MIInt value blobs
// carry the encoded IV (cq0/cq1) and title-id check (cq2/cq3); `data` holds the
// encrypted payload. `data_offset` doubles as a magic value: it always equals
// the size of this header.
struct ProtectedBlob {
    DWORD data_offset;
    unsigned char cq0[0x48];
    unsigned char cq1[0x48];
    unsigned char cq2[0x48];
    unsigned char cq3[0x48];
    DWORD plain_size;
    unsigned char data[];
};

STATIC_ASSERT_OFFSET(ProtectedBlob, data_offset, 0x00, "ProtectedBlob.data_offset moved");
STATIC_ASSERT_OFFSET(ProtectedBlob, cq0, 0x04, "ProtectedBlob.cq0 moved");
STATIC_ASSERT_OFFSET(ProtectedBlob, cq1, 0x4C, "ProtectedBlob.cq1 moved");
STATIC_ASSERT_OFFSET(ProtectedBlob, cq2, 0x94, "ProtectedBlob.cq2 moved");
STATIC_ASSERT_OFFSET(ProtectedBlob, cq3, 0xDC, "ProtectedBlob.cq3 moved");
STATIC_ASSERT_OFFSET(ProtectedBlob, plain_size, 0x124, "ProtectedBlob.plain_size moved");
STATIC_ASSERT_OFFSET(ProtectedBlob, data, 0x128, "ProtectedBlob.data moved");

// Layout of the pre-encryption payload (the `tmp` scratch buffer). A SHA-256
// digest of everything from `xuid` onward is stored in `digest`; `data` holds
// the plain payload, zero-padded out to the rounded size.
struct ProtectedPayload {
    unsigned char digest[0x20];
    XUID xuid;
    XUID signin_xuid;
    DWORD title_id;
    unsigned char data[];
};

STATIC_ASSERT_OFFSET(ProtectedPayload, digest, 0x00, "ProtectedPayload.digest moved");
STATIC_ASSERT_OFFSET(ProtectedPayload, xuid, 0x20, "ProtectedPayload.xuid moved");
STATIC_ASSERT_OFFSET(ProtectedPayload, signin_xuid, 0x28, "ProtectedPayload.signin_xuid moved");
STATIC_ASSERT_OFFSET(ProtectedPayload, title_id, 0x30, "ProtectedPayload.title_id moved");
STATIC_ASSERT_OFFSET(ProtectedPayload, data, 0x34, "ProtectedPayload.data moved");

// modified signatures so they work better standalone

// _XLiveProtectData@20
HRESULT XLiveProtectData(unsigned char *plain, unsigned long plain_size, unsigned char *cypher, unsigned long *p_cypher_size, DWORD dwTitleID, XUID _XamUserGetXUID_12, XUID _XamUserGetSigninInfo_12, bool randomize) {
    MIIntQW1 cq0{};
    MIIntQW2 cq1{};
    MIIntQW3 cq2{};
    MIIntQW4 cq3{};
    unsigned char iv[16];
    unsigned char title_id_enc[16] = {};
    unsigned char title_id_in[16] = {};

    // In the real dll these are stack variables that don't get initialized.
    // The uninitialized data gets used in the unimportant bits of the encoded
    // data. This makes the encoded IV non-deterministic. Very annoying. I'd
    // rather use random bytes than uninitialized stack. When randomize is false
    // the cqX blobs stay zero-initialized and a zero IV is used below, so the
    // whole output is reproducible for golden-file testing.
    if (randomize) {
        GenerateRandomBytes(cq0.value_skJ35dF4i2, sizeof(cq0.value_skJ35dF4i2));
        GenerateRandomBytes(cq1.value_skJ35dF4i2, sizeof(cq1.value_skJ35dF4i2));
        GenerateRandomBytes(cq2.value_skJ35dF4i2, sizeof(cq2.value_skJ35dF4i2));
        GenerateRandomBytes(cq3.value_skJ35dF4i2, sizeof(cq3.value_skJ35dF4i2));
    }

    // for my peace of mind
    assert(p_cypher_size != nullptr);

    HRESULT result = ERROR_SUCCESS;

    unsigned long plain_size_rounded = (plain_size + 67) & 0xFFFFFFF0;
    unsigned long cypher_total = sizeof(ProtectedBlob) + plain_size_rounded;

    if (cypher == nullptr || *p_cypher_size < cypher_total) {
        *p_cypher_size = cypher_total;
        return E_NOT_SUFFICIENT_BUFFER;
    }

    ProtectedBlob *blob = reinterpret_cast<ProtectedBlob *>(cypher);

    if (randomize) {
        result = g_pcbcXLiveUserData->GenerateAndSetRandomIV(iv);
    } else {
        // Zero IV for reproducible output.
        memset(iv, 0, sizeof(iv));
        result = g_pcbcXLiveUserData->SetIV(iv, sizeof(iv));
    }

    EncodeIV(iv, cq0, cq1);

    memset(iv, 0, sizeof(iv));

    if (result != ERROR_SUCCESS)
        return E_FAIL;

    *((DWORD *)&title_id_in[0]) = dwTitleID;

    g_pcbcXLiveUserData->SetPadding(SP_CRYPTO_CIPHER_PADDING_TYPE::NONE);

    unsigned long title_enc_size = 16;

    CSBPseudoPtr title_id_enc_csb;
    title_id_enc_csb.ptr = &title_id_enc[0];

    CSBPseudoPtr title_id_in_csb;
    title_id_in_csb.ptr = &title_id_in[0];

    if (g_pcbcXLiveUserData->Encrypt(SB_PTR<unsigned char> { (__SecureBufferHandleStruct *)title_id_in_csb, 0 }, 16, SB_PTR<unsigned char> { (__SecureBufferHandleStruct *)title_id_enc_csb, 0 }, &title_enc_size) != ERROR_SUCCESS)
        return E_FAIL;

    EncodeTitleID(title_id_enc, cq2, cq3);

    blob->data_offset = sizeof(ProtectedBlob);
    memcpy(blob->cq0, cq0.value_skJ35dF4i2, sizeof(blob->cq0));
    memcpy(blob->cq1, cq1.value_skJ35dF4i2, sizeof(blob->cq1));
    memcpy(blob->cq2, cq2.value_skJ35dF4i2, sizeof(blob->cq2));
    memcpy(blob->cq3, cq3.value_skJ35dF4i2, sizeof(blob->cq3));
    blob->plain_size = plain_size;

    unsigned char *tmp = (unsigned char *)malloc(plain_size_rounded);
    if (tmp == nullptr)
        return E_OUTOFMEMORY;
    ProtectedPayload *payload = reinterpret_cast<ProtectedPayload *>(tmp);

    payload->xuid = _XamUserGetXUID_12;
    payload->signin_xuid = _XamUserGetSigninInfo_12;
    payload->title_id = dwTitleID;
    memcpy(payload->data, plain, plain_size);
    memset(payload->data + plain_size, 0, plain_size_rounded - offsetof(ProtectedPayload, data) - plain_size);

    result = XLivepComputeSHA256Digest((unsigned char *)&payload->xuid, plain_size_rounded - offsetof(ProtectedPayload, xuid), payload->digest);
    if (result < 0) {
        free(tmp);
        tmp = nullptr;
        return result;
    }

    g_pcbcXLiveUserData->SetPadding(SP_CRYPTO_CIPHER_PADDING_TYPE::NONE);

    CSBPseudoPtr data_protected_csb;
    data_protected_csb.ptr = blob->data;

    CSBPseudoPtr payload_csb;
    payload_csb.ptr = tmp;

    if (g_pcbcXLiveUserData->Encrypt(SB_PTR<unsigned char> { (__SecureBufferHandleStruct *)payload_csb, 0 }, plain_size_rounded, SB_PTR<unsigned char> { (__SecureBufferHandleStruct *)data_protected_csb, 0 }, &plain_size_rounded)) {
        free(tmp);
        tmp = nullptr;
        return E_FAIL;
    }

    *p_cypher_size = cypher_total;

    free(tmp);
    tmp = nullptr;
    return result;
}

// _XLiveUnprotectData@20
HRESULT XLiveUnprotectData(unsigned char *cypher, unsigned long cypher_size, unsigned char *plain, unsigned long *p_plain_size, DWORD dwTitleID, XUID *_XamUserGetXUID_12, XUID *_XamUserGetSigninInfo_12, DWORD *pdwTitleID, bool *p_title_id_ok) {
    MIIntQW1 cq0{};
    MIIntQW2 cq1{};
    MIIntQW3 cq2{};
    MIIntQW4 cq3{};
    unsigned char iv[16];
    unsigned char title_id_enc[16];
    unsigned char title_id_input[16] = {};
    unsigned char digest[32];

    // for my peace of mind
    assert(p_plain_size != nullptr && _XamUserGetXUID_12 != nullptr && _XamUserGetSigninInfo_12 != nullptr && pdwTitleID != nullptr && p_title_id_ok != nullptr);

    *_XamUserGetXUID_12 = INVALID_XUID;
    *_XamUserGetSigninInfo_12 = INVALID_XUID;
    *pdwTitleID = 0;
    *p_title_id_ok = false;

    HRESULT result = ERROR_SUCCESS;

    ProtectedBlob *blob = reinterpret_cast<ProtectedBlob *>(cypher);

    if (blob->data_offset != sizeof(ProtectedBlob))
        return ERROR_INVALID_DATA;

    unsigned long plain_size = blob->plain_size;
    unsigned long plain_size_rounded = (plain_size + 67) & 0xFFFFFFF0;

    if (plain == nullptr || *p_plain_size < plain_size_rounded) {
        *p_plain_size = plain_size_rounded;
        return E_NOT_SUFFICIENT_BUFFER;
    }

    memcpy(cq0.value_skJ35dF4i2, blob->cq0, sizeof(cq0.value_skJ35dF4i2));
    memcpy(cq1.value_skJ35dF4i2, blob->cq1, sizeof(cq1.value_skJ35dF4i2));
    memcpy(cq2.value_skJ35dF4i2, blob->cq2, sizeof(cq2.value_skJ35dF4i2));
    memcpy(cq3.value_skJ35dF4i2, blob->cq3, sizeof(cq3.value_skJ35dF4i2));

    DecodeIV(cq0, cq1, iv);

    result = g_pcbcXLiveUserData->SetIV(iv, sizeof(iv));

    memset(iv, 0, sizeof(iv));

    if (result != ERROR_SUCCESS)
        return E_FAIL;

    *((DWORD *)&title_id_input[0]) = dwTitleID;
    g_pcbcXLiveUserData->SetPadding(SP_CRYPTO_CIPHER_PADDING_TYPE::NONE);
    unsigned long title_enc_size = 16;

    CSBPseudoPtr title_enc_csb;
    title_enc_csb.ptr = title_id_enc;

    CSBPseudoPtr title_id_csb;
    title_id_csb.ptr = title_id_input;

    if (g_pcbcXLiveUserData->Encrypt(SB_PTR<unsigned char> { (__SecureBufferHandleStruct *)title_id_csb, 0 }, 16, SB_PTR<unsigned char> { (__SecureBufferHandleStruct *)title_enc_csb, 0 }, &title_enc_size) != ERROR_SUCCESS)
        return E_FAIL;

    // A wrong title id is fatal (it also drives the payload IV chain), but
    // record it in the out param first so the caller can report it precisely.
    *p_title_id_ok = !CheckTitleID(title_id_enc, cq2, cq3);
    if (!*p_title_id_ok)
        return E_FAIL;

    unsigned char *tmp = (unsigned char *)malloc(plain_size_rounded);
    if (tmp == nullptr)
        return E_OUTOFMEMORY;
    ProtectedPayload *payload = reinterpret_cast<ProtectedPayload *>(tmp);

    unsigned long out_size = plain_size_rounded;

    g_pcbcXLiveUserData->SetPadding(SP_CRYPTO_CIPHER_PADDING_TYPE::NONE);

    CSBPseudoPtr payload_csb;
    payload_csb.ptr = tmp;

    CSBPseudoPtr data_protected_csb;
    data_protected_csb.ptr = blob->data;

    if (g_pcbcXLiveUserData->Decrypt(SB_PTR<unsigned char> { (__SecureBufferHandleStruct *)data_protected_csb, 0 }, plain_size_rounded, SB_PTR<unsigned char> { (__SecureBufferHandleStruct *)payload_csb, 0 }, &out_size) != ERROR_SUCCESS
    || out_size != plain_size_rounded || out_size <= offsetof(ProtectedPayload, xuid)) {
        free(tmp);
        tmp = nullptr;
        return E_FAIL;
    }

    result = XLivepComputeSHA256Digest((unsigned char *)&payload->xuid, out_size - offsetof(ProtectedPayload, xuid), digest);
    if (result < 0) {
        free(tmp);
        tmp = nullptr;
        return result;
    }

    if (memcmp(digest, payload->digest, sizeof(digest)) != 0) {
        free(tmp);
        tmp = nullptr;
        return ERROR_INVALID_DATA;
    }

    *_XamUserGetXUID_12 = payload->xuid;
    *_XamUserGetSigninInfo_12 = payload->signin_xuid;
    *pdwTitleID = payload->title_id;
    memcpy(plain, payload->data, plain_size);
    *p_plain_size = plain_size;

    // real dll would create a context here
    free(tmp);
    tmp = nullptr;
    return result;
}
