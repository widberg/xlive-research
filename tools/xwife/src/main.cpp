#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <string>

#include <CLI/CLI.hpp>

#include "ops.hpp"
#include "panorama.hpp"

namespace {

void AddCryptoCommand(CLI::App& app, const char* name, bool encrypt,
                      std::function<int()>& action) {
    static const std::map<std::string, SP_CRYPTO_VAULT_TYPE> cipher_map{
        {"obfuscate", SP_CRYPTO_VAULT_TYPE::OBFUSCATE},
        {"system_link", SP_CRYPTO_VAULT_TYPE::SYSTEM_LINK},
        // {"drm", SP_CRYPTO_VAULT_TYPE::DRM},
        {"user_data", SP_CRYPTO_VAULT_TYPE::USER_DATA},
    };
    static const std::map<std::string, SP_CRYPTO_CIPHER_PADDING_TYPE> padding_map{
        {"none", SP_CRYPTO_CIPHER_PADDING_TYPE::NONE},
        {"pkcs5", SP_CRYPTO_CIPHER_PADDING_TYPE::PKCS5},
    };

    struct Options {
        SP_CRYPTO_VAULT_TYPE cipher = SP_CRYPTO_VAULT_TYPE::NONE;
        SP_CRYPTO_CIPHER_PADDING_TYPE padding = SP_CRYPTO_CIPHER_PADDING_TYPE::PKCS5;
        std::string input;
        std::string output;
    };
    auto opt = std::make_shared<Options>();

    CLI::App* sub = app.add_subcommand(
        name, std::string(name) + " a file with the given block cipher");
    sub->add_option("-c,--cipher", opt->cipher, "block cipher / key vault")
        ->required()
        ->transform(CLI::CheckedTransformer(cipher_map, CLI::ignore_case));
    sub->add_option("-p,--padding", opt->padding, "padding type")
        ->required()
        ->transform(CLI::CheckedTransformer(padding_map, CLI::ignore_case));
    sub->add_option("input", opt->input, "input file")
        ->required()
        ->check(CLI::ExistingFile);
    sub->add_option("output", opt->output, "output file")->required();

    sub->callback([opt, encrypt, &action]() {
        action = [opt, encrypt]() {
            return RunCrypto(encrypt, opt->cipher, opt->padding, opt->input,
                             opt->output);
        };
    });
}

void AddObfuscateCommand(CLI::App& app, const char* name, bool obfuscate,
                         std::function<int()>& action) {
    struct Options {
        std::string input;
        std::string output;
    };
    auto opt = std::make_shared<Options>();

    CLI::App* sub = app.add_subcommand(
        name, std::string(name) + " a file with the xlive obfuscation key");
    sub->add_option("input", opt->input, "input file")
        ->required()
        ->check(CLI::ExistingFile);
    sub->add_option("output", opt->output, "output file")->required();

    sub->callback([opt, obfuscate, &action]() {
        action = [opt, obfuscate]() {
            return RunObfuscate(obfuscate, opt->input, opt->output);
        };
    });
}

void AddProtectCommand(CLI::App& app, std::function<int()>& action) {
    struct Options {
        std::string title_id;
        std::string xuid;
        std::string signin_xuid;
        std::string input;
        std::string output;
        bool randomize = true;
    };
    auto opt = std::make_shared<Options>();

    CLI::App* sub =
        app.add_subcommand("protect", "protect a file with XLiveProtectData");
    sub->add_option("-t,--title-id", opt->title_id, "title id (hex)")->required();
    sub->add_option("-x,--xuid", opt->xuid, "user xuid (hex)")->required();
    sub->add_option("-s,--signin-xuid", opt->signin_xuid, "signin xuid (hex)")
        ->required();
    sub->add_flag("--random,!--no-random", opt->randomize,
                  "randomize the cqX padding and IV (default); --no-random "
                  "zero-fills them for reproducible output");
    sub->add_option("input", opt->input, "input file")
        ->required()
        ->check(CLI::ExistingFile);
    sub->add_option("output", opt->output, "output file")->required();

    sub->callback([opt, &action]() {
        action = [opt]() {
            return RunProtect(opt->title_id, opt->xuid, opt->signin_xuid,
                              opt->input, opt->output, opt->randomize);
        };
    });
}

void AddUnprotectCommand(CLI::App& app, std::function<int()>& action) {
    struct Options {
        std::string title_id;
        std::string input;
        std::string output;
    };
    auto opt = std::make_shared<Options>();

    CLI::App* sub = app.add_subcommand(
        "unprotect", "unprotect a file with XLiveUnprotectData");
    sub->add_option("-t,--title-id", opt->title_id, "title id (hex)")->required();
    sub->add_option("input", opt->input, "input file")
        ->required()
        ->check(CLI::ExistingFile);
    sub->add_option("output", opt->output, "output file")->required();

    sub->callback([opt, &action]() {
        action = [opt]() {
            return RunUnprotect(opt->title_id, opt->input, opt->output);
        };
    });
}

}  // namespace

int main(int argc, char** argv) {
    CLI::App app{"the"};
    argv = app.ensure_utf8(argv);
    app.require_subcommand(0, 1);

    // The selected subcommand's callback records its work here during parsing.
    std::function<int()> action;

    AddCryptoCommand(app, "encrypt", true, action);
    AddCryptoCommand(app, "decrypt", false, action);
    AddObfuscateCommand(app, "obfuscate", true, action);
    AddObfuscateCommand(app, "unobfuscate", false, action);
    AddProtectCommand(app, action);
    AddUnprotectCommand(app, action);

    CLI11_PARSE(app, argc, argv);

    if (!action) {
        std::cout << app.help();
        return 0;
    }

    InitializeKeyVaults();
    int rc = action();
    ShutDownKeyVaults();
    return rc;
}
