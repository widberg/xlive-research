#pragma once

#include <string>

#include "panorama.hpp"

// File-level operations behind each CLI subcommand. Each reads an input file,
// performs the operation, and writes an output file, returning 0 on success or
// 1 on error (with a message printed to stderr). Shared by the CLI and tests.

int RunCrypto(bool encrypt, SP_CRYPTO_VAULT_TYPE cipher,
              SP_CRYPTO_CIPHER_PADDING_TYPE padding,
              const std::string& in_path, const std::string& out_path);

int RunObfuscate(bool obfuscate, const std::string& in_path,
                 const std::string& out_path);

int RunProtect(const std::string& title_id_str, const std::string& xuid_str,
               const std::string& signin_xuid_str, const std::string& in_path,
               const std::string& out_path, bool randomize);

int RunUnprotect(const std::string& title_id_str, const std::string& in_path,
                 const std::string& out_path);
