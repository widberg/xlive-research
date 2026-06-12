import std.mem;
import std.sys;
import xlive;

struct XLiveProtectedDataPayload {
    // Release: digest of all bytes after this field before cypher
    // Debug: zeroed
    u8 sha256_digest[0x20]; // SHA2 size 256 rounds 64 on cyber chef
    XUID _XamUserGetXUID_12;
    XUID _XamUserGetSigninInfo_12; // XUSER_GET_SIGNIN_INFO_ONLINE_XUID_ONLY
    u32 dwTitleId;
    u8 pabDataToProtect[parent.dwSizeOfDataToProtect];
    // Release: aligned to 16 before cypher, filler bytes are 0
};

struct XLiveProtectedData {
    u32 size; // bytes until sha256_digest // debug: 1 // release: 296
    // PanoramaCryptoCBC::GenerateAndSetRandomIV
    // IV, swizzled to shit with help from Syncrosoft
    // Release: bytes in the range [0, 3]
    // Debug: zeroed
    u8 cq0[0x48];
    u8 cq1[0x48];
    // Title ID encrypted with g_pcbcXLiveUserData
    // swizzled to shit with help from Syncrosoft
    // Release: bytes in the range [0, 3]
    // Debug: zeroed
    u8 cq2[0x48];
    u8 cq3[0x48];
    u32 dwSizeOfDataToProtect;
    // Release: begin cypher, encrypted with the same context left over from the title ID
    XLiveProtectedDataPayload payload;
    // release: end cypher
};

XLiveProtectedData xlive_protected_data @ 0x0;

std::assert(std::mem::eof(), "Whole input not consumed!");
