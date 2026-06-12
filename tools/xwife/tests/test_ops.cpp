#include <catch2/catch_session.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include "ops.hpp"
#include "panorama.hpp"

namespace fs = std::filesystem;

// Injected by CMake; points at the checked-in tests/data directory.
#ifndef TEST_DATA_DIR
#define TEST_DATA_DIR "."
#endif

namespace {

const fs::path kDataDir = TEST_DATA_DIR;
const fs::path kInputsDir = kDataDir / "inputs";
const fs::path kGoldenDir = kDataDir / "golden";

// Set by the --regen command-line flag (see main): rewrite golden files from
// the current output instead of comparing against them.
bool g_regen = false;
bool regen_enabled() { return g_regen; }

std::vector<unsigned char> read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    REQUIRE(in.good());
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(in),
                                      std::istreambuf_iterator<char>());
}

void write_file(const fs::path& path, const std::vector<unsigned char>& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    REQUIRE(out.good());
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    REQUIRE(out.good());
}

// A unique temp output path, removed on destruction.
struct Temp {
    fs::path path;
    Temp() {
        static std::atomic<unsigned long long> n{0};
        path = fs::temp_directory_path() /
               ("the_test_" + std::to_string(n++) + ".bin");
    }
    ~Temp() {
        std::error_code ec;
        fs::remove(path, ec);
    }
    std::string str() const { return path.string(); }
};

// Compare `actual` against the named golden file, or rewrite it in regen mode.
void check_golden(const std::string& name,
                  const std::vector<unsigned char>& actual) {
    const fs::path golden = kGoldenDir / name;
    if (regen_enabled()) {
        write_file(golden, actual);
        SUCCEED("regenerated " + golden.string());
        return;
    }
    INFO("golden file: " << golden);
    REQUIRE(fs::exists(golden));
    const std::vector<unsigned char> expected = read_file(golden);
    REQUIRE(actual.size() == expected.size());
    size_t first_diff = actual.size();
    for (size_t i = 0; i < actual.size(); ++i) {
        if (actual[i] != expected[i]) {
            first_diff = i;
            break;
        }
    }
    INFO("first differing byte at offset " << first_diff);
    REQUIRE(first_diff == actual.size());
}

fs::path input_path(const std::string& name) {
    return kInputsDir / (name + ".bin");
}

struct UnprotectResult {
    int rc;
    std::string out;  // captured stdout
    std::string err;  // captured stderr
};

UnprotectResult run_unprotect_capture(const std::string& title,
                                      const std::string& in,
                                      const std::string& out_path) {
    std::ostringstream cap_out, cap_err;
    std::streambuf* old_out = std::cout.rdbuf(cap_out.rdbuf());
    std::streambuf* old_err = std::cerr.rdbuf(cap_err.rdbuf());
    int rc = RunUnprotect(title, in, out_path);
    std::cout.rdbuf(old_out);
    std::cerr.rdbuf(old_err);
    return {rc, cap_out.str(), cap_err.str()};
}

struct CipherCase {
    const char* name;
    SP_CRYPTO_VAULT_TYPE cipher;
};
struct PadCase {
    const char* name;
    SP_CRYPTO_CIPHER_PADDING_TYPE padding;
};

// Fixed identities for the protect tests.
const std::string kTitle = "FEDC1234";
const std::string kXuid = "9B0000DEADBEEF";
const std::string kSignin = "9B0000CAFEF00D";

}  // namespace

TEST_CASE("encrypt golden + decrypt round-trip", "[crypto]") {
    const CipherCase cc = GENERATE(
        CipherCase{"obfuscate", SP_CRYPTO_VAULT_TYPE::OBFUSCATE},
        CipherCase{"system_link", SP_CRYPTO_VAULT_TYPE::SYSTEM_LINK},
        CipherCase{"user_data", SP_CRYPTO_VAULT_TYPE::USER_DATA});
    const PadCase pc =
        GENERATE(PadCase{"none", SP_CRYPTO_CIPHER_PADDING_TYPE::NONE},
                 PadCase{"pkcs5", SP_CRYPTO_CIPHER_PADDING_TYPE::PKCS5});

    // `none` requires block-aligned input; `pkcs5` accepts any size.
    const std::vector<std::string> inputs =
        pc.padding == SP_CRYPTO_CIPHER_PADDING_TYPE::NONE
            ? std::vector<std::string>{"a16", "a32", "a48"}
            : std::vector<std::string>{"v17", "v100", "v380"};

    for (const std::string& in_name : inputs) {
        DYNAMIC_SECTION(cc.name << "_" << pc.name << "_" << in_name) {
            const fs::path input = input_path(in_name);
            Temp enc, dec;

            REQUIRE(RunCrypto(true, cc.cipher, pc.padding, input.string(),
                              enc.str()) == 0);
            check_golden("encrypt_" + std::string(cc.name) + "_" + pc.name + "_" +
                             in_name + ".bin",
                         read_file(enc.path));

            REQUIRE(RunCrypto(false, cc.cipher, pc.padding, enc.str(),
                              dec.str()) == 0);
            CHECK(read_file(dec.path) == read_file(input));
        }
    }
}

TEST_CASE("obfuscate golden + unobfuscate round-trip", "[obfuscate]") {
    const std::string in_name = GENERATE("v17", "v100", "v380");
    const fs::path input = input_path(in_name);
    Temp obf, un;

    REQUIRE(RunObfuscate(true, input.string(), obf.str()) == 0);
    check_golden("obfuscate_" + in_name + ".bin", read_file(obf.path));

    REQUIRE(RunObfuscate(false, obf.str(), un.str()) == 0);
    CHECK(read_file(un.path) == read_file(input));
}

TEST_CASE("protect (no-random) golden + unprotect round-trip", "[protect]") {
    const std::string in_name = GENERATE("v17", "v100", "v380");
    const fs::path input = input_path(in_name);
    Temp prot, un;

    REQUIRE(RunProtect(kTitle, kXuid, kSignin, input.string(), prot.str(),
                       /*randomize=*/false) == 0);
    check_golden("protect_norandom_" + in_name + ".bin", read_file(prot.path));

    const UnprotectResult r = run_unprotect_capture(kTitle, prot.str(), un.str());
    REQUIRE(r.rc == 0);
    CHECK(read_file(un.path) == read_file(input));
    CHECK(r.out.find("TitleID check: passed") != std::string::npos);
    CHECK(r.out.find("XUID: 009B0000DEADBEEF") != std::string::npos);
    CHECK(r.out.find("SigninXUID: 009B0000CAFEF00D") != std::string::npos);
    CHECK(r.out.find("TitleID: FEDC1234") != std::string::npos);
}

TEST_CASE("protect (random) round-trips", "[protect]") {
    const std::string in_name = GENERATE("v17", "v100", "v380");
    const fs::path input = input_path(in_name);
    Temp prot, un;

    REQUIRE(RunProtect(kTitle, kXuid, kSignin, input.string(), prot.str(),
                       /*randomize=*/true) == 0);
    const UnprotectResult r = run_unprotect_capture(kTitle, prot.str(), un.str());
    REQUIRE(r.rc == 0);
    CHECK(read_file(un.path) == read_file(input));
    CHECK(r.out.find("TitleID check: passed") != std::string::npos);
}

TEST_CASE("no-random protect is deterministic; random is not", "[protect]") {
    const fs::path input = input_path("v100");
    Temp a, b, c, d;

    REQUIRE(RunProtect(kTitle, kXuid, kSignin, input.string(), a.str(), false) == 0);
    REQUIRE(RunProtect(kTitle, kXuid, kSignin, input.string(), b.str(), false) == 0);
    CHECK(read_file(a.path) == read_file(b.path));

    REQUIRE(RunProtect(kTitle, kXuid, kSignin, input.string(), c.str(), true) == 0);
    REQUIRE(RunProtect(kTitle, kXuid, kSignin, input.string(), d.str(), true) == 0);
    CHECK(read_file(c.path) != read_file(d.path));
}

TEST_CASE("unprotect with wrong title id is a hard error", "[protect]") {
    const fs::path input = input_path("v100");
    Temp prot, un;

    REQUIRE(RunProtect(kTitle, kXuid, kSignin, input.string(), prot.str(),
                       /*randomize=*/false) == 0);

    // The title id also drives the payload IV chain, so a wrong one is fatal.
    // The out param lets the caller report it precisely instead of a raw hr.
    const std::string wrong_title = "00000001";
    const UnprotectResult r =
        run_unprotect_capture(wrong_title, prot.str(), un.str());
    CHECK(r.rc != 0);
    CHECK(r.err.find("title id check failed") != std::string::npos);
}

int main(int argc, char** argv) {
    Catch::Session session;

    bool regen = false;
    auto cli = session.cli() |
               Catch::Clara::Opt(regen)["--regen"](
                   "rewrite golden files from the current output");
    session.cli(cli);

    if (const int rc = session.applyCommandLine(argc, argv); rc != 0)
        return rc;
    g_regen = regen;

    InitializeKeyVaults();
    const int result = session.run();
    ShutDownKeyVaults();
    return result;
}
