#pragma once

// The four MIIntQW classes share a layout: a CriticalSectionWrapper pointer
// followed by the 0x48-byte value buffer. They are kept as distinct types so the
// overloaded Copy/Xor/Add/CopyCollect signatures match their mangled names.
struct MIIntQW1 { void *csw = nullptr; unsigned char value_skJ35dF4i2[0x48] = {}; };
struct MIIntQW2 { void *csw = nullptr; unsigned char value_skJ35dF4i2[0x48] = {}; };
struct MIIntQW3 { void *csw = nullptr; unsigned char value_skJ35dF4i2[0x48] = {}; };
struct MIIntQW4 { void *csw = nullptr; unsigned char value_skJ35dF4i2[0x48] = {}; };

void EncodeIV(const unsigned char *iv, MIIntQW1 &cq0, MIIntQW2 &cq1);
void DecodeIV(const MIIntQW1 &cq0, const MIIntQW2 &cq1, unsigned char *iv);
void EncodeTitleID(const unsigned char *title_id_enc, MIIntQW3 &cq2, MIIntQW4 &cq3);
bool CheckTitleID(const unsigned char *title_id_enc, MIIntQW3 &cq2, MIIntQW4 &cq3);
