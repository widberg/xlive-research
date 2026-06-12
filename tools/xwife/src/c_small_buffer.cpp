#include "c_small_buffer.hpp"

// These functions are way more complicated in the real dll. But there's no
// reason to mirror that here.

// ?SBufferGetByte@@YIEPAU__SecureBufferHandleStruct@@K@Z
unsigned char SBufferGetByte(struct __SecureBufferHandleStruct *the, unsigned long index) {
    CSBPseudoPtr *pseudo = (CSBPseudoPtr *)the;
    return pseudo->ptr[index];
}

// ?SBufferSetByte@@YIXPAU__SecureBufferHandleStruct@@KE@Z
void SBufferSetByte(struct __SecureBufferHandleStruct *the, unsigned long index,unsigned char value) {
    CSBPseudoPtr *pseudo = (CSBPseudoPtr *)the;
    pseudo->ptr[index] = value;
}

CSBPseudoPtr::operator __SecureBufferHandleStruct *()const {
    return (__SecureBufferHandleStruct *)this;
}
