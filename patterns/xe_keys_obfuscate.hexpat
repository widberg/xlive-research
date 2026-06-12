import std.mem;
import std.sys;
import xlive;

struct XeKeysObfuscate {
    u8 zero[0x18];
    std::assert(all_eq(zero, 0), "zero isn't zero");
    // Release: encrypted with g_pcbcObfuscation, PKCS5 padding
    // Debug: encryption calls are memcpy pass through but still do padding
    u8 data[while (!std::mem::eof())];
};

XeKeysObfuscate xe_keys_obfuscate @ 0x0;

std::assert(std::mem::eof(), "Whole input not consumed!");
