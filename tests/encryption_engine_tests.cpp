#include "encryption_engine.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {
    class TestWorkspace {
    public:
        TestWorkspace() {
            const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
            path = std::filesystem::temp_directory_path() /
                   ("kasa-engine-tests-" + std::to_string(stamp));
            std::filesystem::create_directories(path);
        }

        ~TestWorkspace() {
            std::error_code error;
            std::filesystem::remove_all(path, error);
        }

        std::filesystem::path path;
    };

    bool writeBytes(const std::filesystem::path& path,
                    const std::vector<std::uint8_t>& bytes) {
        std::ofstream output(path, std::ios::binary);
        output.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
        return output.good();
    }

    std::vector<std::uint8_t> readBytes(const std::filesystem::path& path) {
        std::ifstream input(path, std::ios::binary);
        return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    }

    bool tamperWithCiphertext(const std::filesystem::path& path) {
        std::fstream file(path, std::ios::binary | std::ios::in | std::ios::out);
        if (!file) return false;

        constexpr std::streamoff ciphertext_offset = 32;
        file.seekg(ciphertext_offset);
        char value = 0;
        file.read(&value, 1);
        if (!file) return false;

        value ^= 0x40;
        file.seekp(ciphertext_offset);
        file.write(&value, 1);
        return file.good();
    }

    bool expect(bool condition, const std::string& message) {
        if (!condition) std::cerr << "FAIL: " << message << '\n';
        return condition;
    }

    bool runRoundTrip(CipherType cipher, const std::string& label,
                      const std::vector<std::uint8_t>& content) {
        TestWorkspace workspace;
        encryption_engine engine;
        const auto source = workspace.path / (label + ".bin");
        const auto encrypted = workspace.path / (label + ".bin.kasa");
        const auto decrypted = workspace.path / (label + "-restored.bin");

        if (!expect(writeBytes(source, content), label + ": create source")) return false;
        if (!expect(engine.process_file(source, "correct horse battery staple",
                                        ActionType::ENCRYPT, cipher, false, encrypted),
                    label + ": encrypt")) return false;
        const std::optional<KasaFileInfo> info = engine.inspect_file(encrypted);
        if (!expect(info.has_value(), label + ": inspect KASA footer")) return false;
        if (!expect(info->format_version == 1 && info->cipher == cipher,
                    label + ": report cipher and format version")) return false;
        if (!expect(std::filesystem::exists(source), label + ": preserve source")) return false;
        if (!expect(engine.process_file(encrypted, "correct horse battery staple",
                                        ActionType::DECRYPT, CipherType::AES256, false, decrypted),
                    label + ": decrypt with automatic cipher detection")) return false;
        return expect(readBytes(decrypted) == content, label + ": preserve every byte");
    }

    bool runWrongPasswordTest(CipherType cipher, const std::string& label) {
        TestWorkspace workspace;
        encryption_engine engine;
        const auto source = workspace.path / (label + ".txt");
        const auto encrypted = workspace.path / (label + ".txt.kasa");
        const auto rejected = workspace.path / (label + "-rejected.txt");
        const std::vector<std::uint8_t> content(4096, 0x5a);

        if (!writeBytes(source, content)) return false;
        if (!engine.process_file(source, "right-password", ActionType::ENCRYPT,
                                 cipher, false, encrypted)) return false;
        const bool accepted = engine.process_file(encrypted, "wrong-password",
                                                  ActionType::DECRYPT, CipherType::AES256,
                                                  false, rejected);
        return expect(!accepted && !std::filesystem::exists(rejected),
                      label + ": reject a wrong password without leaving output");
    }

    bool runTamperTest(CipherType cipher, const std::string& label) {
        TestWorkspace workspace;
        encryption_engine engine;
        const auto source = workspace.path / (label + ".dat");
        const auto encrypted = workspace.path / (label + ".dat.kasa");
        const auto rejected = workspace.path / (label + "-tampered.dat");
        const std::vector<std::uint8_t> content(8192, 0xa5);

        if (!writeBytes(source, content)) return false;
        if (!engine.process_file(source, "tamper-test-password", ActionType::ENCRYPT,
                                 cipher, false, encrypted)) return false;
        if (!expect(tamperWithCiphertext(encrypted), label + ": modify encrypted data")) return false;

        const bool accepted = engine.process_file(encrypted, "tamper-test-password",
                                                  ActionType::DECRYPT, CipherType::AES256,
                                                  false, rejected);
        return expect(!accepted && !std::filesystem::exists(rejected),
                      label + ": reject modified data without leaving output");
    }

    bool runInvalidFooterTest() {
        TestWorkspace workspace;
        encryption_engine engine;
        const auto fake_kasa = workspace.path / "not-really-encrypted.kasa";
        const std::vector<std::uint8_t> content(128, 0x2a);
        if (!writeBytes(fake_kasa, content)) return false;
        return expect(!engine.inspect_file(fake_kasa).has_value(),
                      "Footer inspection: reject an unsupported .kasa file");
    }
}

int main() {
    const std::vector<std::uint8_t> binary_data {
        0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff, 0x0a, 0x0d, 0x00
    };

    bool passed = true;
    passed &= runRoundTrip(CipherType::AES256, "AES binary round-trip", binary_data);
    passed &= runRoundTrip(CipherType::AES256, "AES empty-file round-trip", {});
    passed &= runWrongPasswordTest(CipherType::AES256, "AES wrong password");
    passed &= runTamperTest(CipherType::AES256, "AES tamper detection");
    passed &= runRoundTrip(CipherType::XOR, "XOR binary round-trip", binary_data);
    passed &= runWrongPasswordTest(CipherType::XOR, "XOR wrong password");
    passed &= runTamperTest(CipherType::XOR, "XOR tamper detection");
    passed &= runInvalidFooterTest();

    if (!passed) return 1;
    std::cout << "All KASA encryption engine tests passed.\n";
    return 0;
}
