#pragma once

#include <cstddef>

struct __SecureBufferHandleStruct;

template<typename T>
class SB_PTR {
public:
    __SecureBufferHandleStruct *ptr;
    unsigned long begin;
};

unsigned char SBufferGetByte(struct __SecureBufferHandleStruct *the, unsigned long index);
void SBufferSetByte(struct __SecureBufferHandleStruct *the, unsigned long index,unsigned char value);

// This is basically their version of llvm::SmallVector. I've left out the
// complicated stuff since we don't need it.

template<typename T>
class CSmallBufferNoDestruct {
public:
    T data;
    bool _24;
    bool _25;
    bool _26;
    bool zero_init = 0;
    // 32-bit on purpose. The API mangles every length as K (unsigned long,
    // 32-bit on Win64), and the decompiled CBC code relies on this counter
    // wrapping at 32 bits, e.g. EncryptUpdate's `size += plain_size - i - v35`
    // is meant to wrap back to 0, and `v9 = plain_size + size` feeds a 32-bit
    // overflow check. A 64-bit size_t here turns those wraps into huge values
    // and overruns the buffer.
    unsigned long size = 0;

    // ?ptr@?$CSmallBufferNoDestruct@$$BY0BA@E@@QAEPAXXZ
    // ?ptr@?$CSmallBufferNoDestruct@$$BY0CA@E@@QAEPAXXZ
    // ABI returns void* (PAX); exposed as unsigned char* because the inline
    // storage is always unsigned char[N] and every caller indexes it as bytes.
    unsigned char *ptr() {
        return &this->data[0];
    }

    // ?alloc@?$CSmallBufferNoDestruct@$$BY0BA@E@@QAEPAXK@Z
    // ?alloc@?$CSmallBufferNoDestruct@$$BY0CA@E@@QAEPAXK@Z
    unsigned char *alloc(unsigned long size) {
        return &this->data[0];
    }

    // ?Destroy@?$CSmallBufferNoDestruct@$$BY0BA@E@@QAEXXZ
    // ?Destroy@?$CSmallBufferNoDestruct@$$BY0CA@E@@QAEXXZ
    void Destroy() {
        this->zero_init = 0;
    }
};

class CSBPseudoPtr {
public:
    unsigned char *ptr = nullptr;
    void *obfuscation_data = nullptr;

    // ??BCSBPseudoPtr@@QBEPAU__SecureBufferHandleStruct@@XZ
    operator __SecureBufferHandleStruct *() const;
};
