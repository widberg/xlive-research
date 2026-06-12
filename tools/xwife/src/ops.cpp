#include "ops.hpp"

#include <cstdint>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "panorama.hpp"
#include "xe_keys_obfuscate.hpp"
#include "xlive_protect_data.hpp"

namespace {

bool ParseHex(const std::string& text, uint64_t& out) {
    if (text.empty())
        return false;
    try {
        size_t consumed = 0;
        out = std::stoull(text, &consumed, 16);
        return consumed == text.size();
    } catch (...) {
        return false;
    }
}

bool ReadFile(const std::string& path, std::vector<unsigned char>& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "error: could not open input file: " << path << '\n';
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

bool WriteFile(const std::string& path, const unsigned char* data, size_t size) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        std::cerr << "error: could not open output file: " << path << '\n';
        return false;
    }
    out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    if (!out) {
        std::cerr << "error: could not write output file: " << path << '\n';
        return false;
    }
    return true;
}

}  // namespace

int RunCrypto(bool encrypt, SP_CRYPTO_VAULT_TYPE cipher,
              SP_CRYPTO_CIPHER_PADDING_TYPE padding,
              const std::string& in_path, const std::string& out_path) {
    std::ifstream in(in_path, std::ios::binary);
    if (!in) {
        std::cerr << "error: could not open input file: " << in_path << '\n';
        return 1;
    }
    std::vector<unsigned char> input((std::istreambuf_iterator<char>(in)),
                                     std::istreambuf_iterator<char>());

    // Size the output buffer exactly. For encryption the ciphertext is a whole
    // number of 16-byte blocks: with PKCS5 a full padding block is always
    // appended (even when the input is already block-aligned), otherwise the
    // input must already be block-aligned and the size is unchanged. For
    // decryption the plaintext is never larger than the ciphertext.
    size_t out_capacity;
    if (encrypt && padding == SP_CRYPTO_CIPHER_PADDING_TYPE::PKCS5)
        out_capacity = (input.size() / 16 + 1) * 16;
    else
        out_capacity = input.size();
    std::vector<unsigned char> output(out_capacity);

    PanoramaCryptoCBC cbc;
    cbc.SetBlockCipher(cipher);
    cbc.SetPadding(padding);

    CSBPseudoPtr in_csb;
    in_csb.ptr = input.data();
    CSBPseudoPtr out_csb;
    out_csb.ptr = output.data();

    SB_PTR<unsigned char> in_sb{(__SecureBufferHandleStruct*)in_csb, 0};
    SB_PTR<unsigned char> out_sb{(__SecureBufferHandleStruct*)out_csb, 0};

    unsigned long out_size = static_cast<unsigned long>(output.size());
    HRESULT hr = encrypt
                     ? cbc.Encrypt(in_sb, static_cast<unsigned long>(input.size()),
                                   out_sb, &out_size)
                     : cbc.Decrypt(in_sb, static_cast<unsigned long>(input.size()),
                                   out_sb, &out_size);
    if (hr != ERROR_SUCCESS) {
        std::cerr << "error: " << (encrypt ? "encrypt" : "decrypt")
                  << " failed (hr=0x" << std::hex << static_cast<unsigned long>(hr)
                  << ")\n";
        return 1;
    }

    std::ofstream out(out_path, std::ios::binary);
    if (!out) {
        std::cerr << "error: could not open output file: " << out_path << '\n';
        return 1;
    }
    out.write(reinterpret_cast<const char*>(output.data()), out_size);
    if (!out) {
        std::cerr << "error: could not write output file: " << out_path << '\n';
        return 1;
    }
    return 0;
}

int RunObfuscate(bool obfuscate, const std::string& in_path,
                 const std::string& out_path) {
    std::ifstream in(in_path, std::ios::binary);
    if (!in) {
        std::cerr << "error: could not open input file: " << in_path << '\n';
        return 1;
    }
    std::vector<unsigned char> input((std::istreambuf_iterator<char>(in)),
                                     std::istreambuf_iterator<char>());

    std::vector<unsigned char> output;
    unsigned long out_size = 0;
    if (obfuscate) {
        // Output is a 0x18-byte header followed by the obfuscation cipher's
        // ciphertext. g_pcbcObfuscation uses PKCS5 padding, so the ciphertext
        // is the input rounded up to the next 16-byte block plus a full pad
        // block.
        size_t capacity = 0x18 + (input.size() / 16 + 1) * 16;
        output.resize(capacity);
        out_size = static_cast<unsigned long>(capacity);
        NTSTATUS status =
            XeKeysObfuscate(1, input.data(), static_cast<unsigned long>(input.size()),
                            output.data(), &out_size);
        if (status != STATUS_SUCCESS) {
            std::cerr << "error: obfuscate failed (status=0x" << std::hex
                      << static_cast<unsigned long>(status) << ")\n";
            return 1;
        }
    } else {
        if (input.size() < 0x18) {
            std::cerr << "error: input too small to be obfuscated data "
                         "(need at least 24 bytes)\n";
            return 1;
        }
        size_t capacity = input.size() - 0x18;
        output.resize(capacity);
        out_size = static_cast<unsigned long>(capacity);
        if (!XeKeysUnObfuscate(1, input.data(),
                               static_cast<unsigned long>(input.size()),
                               output.data(), &out_size)) {
            std::cerr << "error: unobfuscate failed\n";
            return 1;
        }
    }

    std::ofstream out(out_path, std::ios::binary);
    if (!out) {
        std::cerr << "error: could not open output file: " << out_path << '\n';
        return 1;
    }
    out.write(reinterpret_cast<const char*>(output.data()), out_size);
    if (!out) {
        std::cerr << "error: could not write output file: " << out_path << '\n';
        return 1;
    }
    return 0;
}

// XLiveProtectData over a whole file. Probes for the required ciphertext size
// first, then performs the protect. Uses g_pcbcXLiveUserData (needs vaults).
int RunProtect(const std::string& title_id_str, const std::string& xuid_str,
               const std::string& signin_xuid_str, const std::string& in_path,
               const std::string& out_path, bool randomize) {
    uint64_t title_id_v = 0, xuid = 0, signin_xuid = 0;
    if (!ParseHex(title_id_str, title_id_v) || title_id_v > 0xFFFFFFFFull) {
        std::cerr << "error: invalid title id (expected <= 8 hex digits): "
                  << title_id_str << '\n';
        return 1;
    }
    if (!ParseHex(xuid_str, xuid)) {
        std::cerr << "error: invalid xuid (expected hex): " << xuid_str << '\n';
        return 1;
    }
    if (!ParseHex(signin_xuid_str, signin_xuid)) {
        std::cerr << "error: invalid signin xuid (expected hex): "
                  << signin_xuid_str << '\n';
        return 1;
    }

    std::vector<unsigned char> input;
    if (!ReadFile(in_path, input))
        return 1;

    // Probe: a null output buffer makes XLiveProtectData report the required
    // size and return E_NOT_SUFFICIENT_BUFFER.
    unsigned long cypher_size = 0;
    HRESULT hr = XLiveProtectData(
        input.data(), static_cast<unsigned long>(input.size()), nullptr,
        &cypher_size, static_cast<DWORD>(title_id_v), xuid, signin_xuid,
        randomize);
    if (hr != E_NOT_SUFFICIENT_BUFFER) {
        std::cerr << "error: protect size probe failed (hr=0x" << std::hex
                  << static_cast<unsigned long>(hr) << ")\n";
        return 1;
    }

    std::vector<unsigned char> output(cypher_size);
    hr = XLiveProtectData(
        input.data(), static_cast<unsigned long>(input.size()), output.data(),
        &cypher_size, static_cast<DWORD>(title_id_v), xuid, signin_xuid,
        randomize);
    if (hr != ERROR_SUCCESS) {
        std::cerr << "error: protect failed (hr=0x" << std::hex
                  << static_cast<unsigned long>(hr) << ")\n";
        return 1;
    }

    return WriteFile(out_path, output.data(), cypher_size) ? 0 : 1;
}

int RunUnprotect(const std::string& title_id_str, const std::string& in_path,
                 const std::string& out_path) {
    uint64_t title_id_v = 0;
    if (!ParseHex(title_id_str, title_id_v) || title_id_v > 0xFFFFFFFFull) {
        std::cerr << "error: invalid title id (expected <= 8 hex digits): "
                  << title_id_str << '\n';
        return 1;
    }

    std::vector<unsigned char> input;
    if (!ReadFile(in_path, input))
        return 1;

    if (input.size() < 0x128) {
        std::cerr << "error: input too small to be protected data "
                     "(need at least 296 bytes)\n";
        return 1;
    }

    XUID xuid = INVALID_XUID, signin_xuid = INVALID_XUID;
    DWORD out_title_id = 0;
    bool title_id_ok = false;

    // Probe: a null output buffer makes XLiveUnprotectData report the required
    // size and return E_NOT_SUFFICIENT_BUFFER.
    unsigned long plain_size = 0;
    HRESULT hr = XLiveUnprotectData(
        input.data(), static_cast<unsigned long>(input.size()), nullptr,
        &plain_size, static_cast<DWORD>(title_id_v), &xuid, &signin_xuid,
        &out_title_id, &title_id_ok);
    if (hr != E_NOT_SUFFICIENT_BUFFER) {
        std::cerr << "error: unprotect size probe failed (hr=0x" << std::hex
                  << static_cast<unsigned long>(hr) << ")\n";
        return 1;
    }

    std::vector<unsigned char> output(plain_size);
    hr = XLiveUnprotectData(
        input.data(), static_cast<unsigned long>(input.size()), output.data(),
        &plain_size, static_cast<DWORD>(title_id_v), &xuid, &signin_xuid,
        &out_title_id, &title_id_ok);
    if (hr != ERROR_SUCCESS) {
        if (!title_id_ok)
            std::cerr << "error: title id check failed\n";
        else
            std::cerr << "error: unprotect failed (hr=0x" << std::hex
                      << static_cast<unsigned long>(hr) << ")\n";
        return 1;
    }

    // All-caps, zero-padded, no spaces: XUIDs are 16 hex digits, title id is 8.
    std::cout << std::uppercase << std::hex << std::setfill('0');
    std::cout << "XUID: " << std::setw(16) << xuid << '\n';
    std::cout << "SigninXUID: " << std::setw(16) << signin_xuid << '\n';
    std::cout << "TitleID: " << std::setw(8)
              << static_cast<uint32_t>(out_title_id) << '\n';
    std::cout << "TitleID check: " << (title_id_ok ? "passed" : "failed") << '\n';

    return WriteFile(out_path, output.data(), plain_size) ? 0 : 1;
}
