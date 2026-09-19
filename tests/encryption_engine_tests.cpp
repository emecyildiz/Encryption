#include "encryption_engine.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>

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
        auto temporary = rejected;
        temporary += ".tmp";
        return expect(!accepted && !std::filesystem::exists(rejected) &&
                          !std::filesystem::exists(temporary),
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
        auto temporary = rejected;
        temporary += ".tmp";
        return expect(!accepted && !std::filesystem::exists(rejected) &&
                          !std::filesystem::exists(temporary),
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

    bool runUnicodePathTest() {
        TestWorkspace workspace;
        encryption_engine engine;
        const auto source = workspace.path / std::filesystem::path(L"özel-dosya-şifreleme.txt");
        const auto encrypted = workspace.path / std::filesystem::path(L"özel-dosya-şifreleme.txt.kasa");
        const auto decrypted = workspace.path / std::filesystem::path(L"çözülmüş-dosya.txt");
        const std::vector<std::uint8_t> content {0x4b, 0x41, 0x53, 0x41, 0x00, 0xff};

        if (!expect(writeBytes(source, content), "Unicode paths: create source")) return false;
        if (!expect(engine.process_file(source, "unicode-password", ActionType::ENCRYPT,
                                        CipherType::AES256, false, encrypted),
                    "Unicode paths: encrypt")) return false;
        if (!expect(engine.process_file(encrypted, "unicode-password", ActionType::DECRYPT,
                                        CipherType::AES256, false, decrypted),
                    "Unicode paths: decrypt")) return false;
        return expect(readBytes(decrypted) == content, "Unicode paths: preserve every byte");
    }

    bool runCaseInsensitiveExtensionTest() {
        TestWorkspace workspace;
        encryption_engine engine;
        const auto source = workspace.path / "uppercase-extension.txt";
        const auto encrypted = workspace.path / "uppercase-extension.KASA";
        const auto decrypted = workspace.path / "uppercase-extension-restored.txt";
        const std::vector<std::uint8_t> content(64, 0x31);

        if (!writeBytes(source, content)) return false;
        if (!engine.process_file(source, "extension-password", ActionType::ENCRYPT,
                                 CipherType::AES256, false, encrypted)) return false;
        if (!expect(engine.process_file(encrypted, "extension-password", ActionType::DECRYPT,
                                        CipherType::XOR, false, decrypted),
                    "Uppercase extension: decrypt based on authenticated footer")) return false;
        return expect(readBytes(decrypted) == content,
                      "Uppercase extension: preserve every byte");
    }

    bool runTruncatedFormatTest() {
        TestWorkspace workspace;
        encryption_engine engine;
        const auto truncated = workspace.path / "truncated.kasa";
        const std::vector<std::uint8_t> fake_footer {
            'K', 'A', 'S', 'A', 1, 2
        };
        if (!writeBytes(truncated, fake_footer)) return false;
        return expect(!engine.inspect_file(truncated).has_value(),
                      "Format inspection: reject a truncated file with a valid-looking footer");
    }

    bool runTemporaryCollisionTest() {
        TestWorkspace workspace;
        encryption_engine engine;
        const auto source = workspace.path / "collision-source.txt";
        const auto encrypted = workspace.path / "collision-source.txt.kasa";
        auto temporary = encrypted;
        temporary += ".tmp";
        const std::vector<std::uint8_t> source_content(32, 0x41);
        const std::vector<std::uint8_t> sentinel(32, 0x7c);

        if (!writeBytes(source, source_content) || !writeBytes(temporary, sentinel)) return false;
        const bool encrypted_existing_temporary = engine.process_file(
            source, "collision-password", ActionType::ENCRYPT, CipherType::AES256,
            false, encrypted);
        return expect(!encrypted_existing_temporary && readBytes(temporary) == sentinel,
                      "Temporary output: never overwrite a pre-existing file");
    }

    bool runHardLinkDeletionTest() {
        TestWorkspace workspace;
        encryption_engine engine;
        const auto source = workspace.path / "hard-link-source.txt";
        const auto link = workspace.path / "hard-link-copy.txt";
        const std::vector<std::uint8_t> content(128, 0x5e);
        if (!writeBytes(source, content)) return false;

        std::error_code link_error;
        std::filesystem::create_hard_link(source, link, link_error);
        if (link_error) {
            std::cerr << "SKIP: hard-link deletion test: " << link_error.message() << '\n';
            return true;
        }

        const bool deleted = engine.delete_file(source);
        return expect(!deleted && readBytes(source) == content && readBytes(link) == content,
                      "Source deletion: refuse to overwrite multiply-linked data");
    }

    bool runSingleLinkDeletionTest() {
        TestWorkspace workspace;
        encryption_engine engine;
        const auto source = workspace.path / "single-link-source.txt";
        if (!writeBytes(source, std::vector<std::uint8_t>(8192, 0xa7))) return false;
        return expect(engine.delete_file(source) && !std::filesystem::exists(source),
                      "Source deletion: overwrite and remove a single-link file");
    }

    bool runAesNoUnauthenticatedFileTest(bool tampered) {
        TestWorkspace workspace;
        encryption_engine engine;
        const auto source = workspace.path / "source.bin";
        const auto encrypted = workspace.path / "source.kasa";
        const auto destination = workspace.path / "restored.bin";
        if (!writeBytes(source, std::vector<std::uint8_t>(128 * 1024, 0x61)) ||
            !engine.encrypt_aes256(source, "authentication-test", false, encrypted)) return false;
        if (tampered && !tamperWithCiphertext(encrypted)) return false;
        const HANDLE changes = FindFirstChangeNotificationW(workspace.path.c_str(), FALSE,
                                                             FILE_NOTIFY_CHANGE_FILE_NAME);
        if (changes == INVALID_HANDLE_VALUE) return expect(false, "Create directory watcher");
        const bool accepted = engine.dencrypt_aes256(encrypted,
            tampered ? "authentication-test" : "incorrect-password", false, destination);
        // A create-then-delete would also signal: checking existence alone misses it.
        const DWORD notification = WaitForSingleObject(changes, 100);
        FindCloseChangeNotification(changes);
        return expect(!accepted && notification == WAIT_TIMEOUT &&
                      !std::filesystem::exists(destination),
                      tampered ? "AES tamper: no temporary file is ever created"
                               : "AES wrong password: no temporary file is ever created");
    }

    bool runAesBusyInputTest() {
        TestWorkspace workspace;
        encryption_engine engine;
        const auto source = workspace.path / "source.bin";
        const auto encrypted = workspace.path / "source.kasa";
        const auto destination = workspace.path / "restored.bin";
        if (!writeBytes(source, std::vector<std::uint8_t>(8193, 0x51)) ||
            !engine.encrypt_aes256(source, "busy-test", false, encrypted)) return false;
        const HANDLE writer = CreateFileW(encrypted.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (writer == INVALID_HANDLE_VALUE) return expect(false, "Open writer fixture");
        const bool accepted = engine.dencrypt_aes256(encrypted, "busy-test", false, destination);
        CloseHandle(writer);
        if (!expect(!accepted && !std::filesystem::exists(destination),
                    "AES: refuse input with a pre-existing writer")) return false;
        return expect(engine.dencrypt_aes256(encrypted, "busy-test", false, destination) &&
                      readBytes(destination) == readBytes(source),
                      "AES: input works after writer closes");
    }

    bool runSourceSnapshotTest(CipherType cipher, int scenario) {
        TestWorkspace workspace;
        encryption_engine engine;
        const auto source = workspace.path / "document.bin";
        const auto encrypted = workspace.path / "document.kasa";
        const auto restored = workspace.path / "restored.bin";
        const std::vector<std::uint8_t> original(8193, 0x62);
        const std::vector<std::uint8_t> changed(8193, 0x73);
        std::optional<SourceSnapshot> snapshot;
        if (!writeBytes(source, original) || !engine.process_file(source, "snapshot-test",
                ActionType::ENCRYPT, cipher, false, encrypted, &snapshot) || !snapshot) return false;
        const auto timestamp = std::filesystem::last_write_time(source);
        HANDLE writer = INVALID_HANDLE_VALUE;
        if (scenario == 1) {
            // Same size and restored timestamp: only the content digest detects this.
            if (!writeBytes(source, changed)) return false;
            std::filesystem::last_write_time(source, timestamp);
        } else if (scenario == 2) {
            // Same bytes/timestamp at the old path, but a different file object.
            std::filesystem::rename(source, workspace.path / "original-moved.bin");
            if (!writeBytes(source, original)) return false;
            std::filesystem::last_write_time(source, timestamp);
        } else if (scenario == 3) {
            std::filesystem::create_hard_link(source, workspace.path / "extra-link.bin");
        } else if (scenario == 4) {
            writer = CreateFileW(source.c_str(), GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (writer == INVALID_HANDLE_VALUE) return false;
        }
        const bool deleted = engine.delete_file(source, *snapshot);
        if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
        if (scenario == 0) {
            if (!expect(deleted && !std::filesystem::exists(source), "Verified unchanged source is deleted")) return false;
        } else {
            if (!expect(!deleted && readBytes(source) == (scenario == 1 ? changed : original),
                        "Changed/replaced/linked/busy source remains intact: " + std::to_string(scenario))) return false;
        }
        return expect(engine.process_file(encrypted, "snapshot-test", ActionType::DECRYPT,
                       cipher, false, restored) && readBytes(restored) == original,
                      "Saved ciphertext still restores the original bytes");
    }

    bool runAutomaticDeletionTest(CipherType cipher) {
        TestWorkspace workspace;
        encryption_engine engine;
        const auto source = workspace.path / "source.bin";
        const auto encrypted = workspace.path / "source.kasa";
        const auto restored = workspace.path / "restored.bin";
        const std::vector<std::uint8_t> content(2049, 0x34);
        if (!writeBytes(source, content)) return false;
        if (!expect(engine.process_file(source, "automatic-test", ActionType::ENCRYPT,
                    cipher, true, encrypted) && !std::filesystem::exists(source),
                    "Automatic encryption deletion uses verified source")) return false;
        return expect(engine.process_file(encrypted, "automatic-test", ActionType::DECRYPT,
                      cipher, true, restored) && !std::filesystem::exists(encrypted) &&
                      readBytes(restored) == content, "Automatic decryption deletion uses verified source");
    }
}

namespace {
    bool runInvalidSelectionTest(CipherType valid_cipher) {
        TestWorkspace workspace;
        encryption_engine engine;
        const auto plain = workspace.path / "source.bin";
        const auto encrypted = workspace.path / "source.kasa";
        const auto output = workspace.path / "unexpected.bin";
        const std::vector<std::uint8_t> content(4097, 0x53);
        if (!writeBytes(plain, content) || !engine.process_file(plain, "selection-test",
                ActionType::ENCRYPT, valid_cipher, false, encrypted)) return false;
        const auto ciphertext = readBytes(encrypted);
        struct Selection { ActionType action; CipherType cipher; };
        const Selection invalid[] {
            {ActionType::ENCRYPT, static_cast<CipherType>(-1)},
            {ActionType::ENCRYPT, static_cast<CipherType>(99)},
            {ActionType::DECRYPT, static_cast<CipherType>(-1)},
            {ActionType::DECRYPT, static_cast<CipherType>(99)},
            {static_cast<ActionType>(-1), valid_cipher},
            {static_cast<ActionType>(99), valid_cipher}
        };
        for (const auto& source : {plain, encrypted}) {
            for (const auto selection : invalid) {
                std::optional<SourceSnapshot> snapshot = SourceSnapshot{};
                const bool accepted = engine.process_file(source, "selection-test",
                    selection.action, selection.cipher, true, output, &snapshot);
                if (!expect(!accepted, "Invalid selection rejected") ||
                    !expect(!snapshot, "Failure clears stale source snapshot") ||
                    !expect(readBytes(plain) == content && readBytes(encrypted) == ciphertext,
                            "Invalid selection never changes or deletes either input") ||
                    !expect(!std::filesystem::exists(output) &&
                            !std::filesystem::exists(output.string() + ".tmp"),
                            "Invalid selection produces no output")) return false;
            }
        }
        // Decryption still detects the actual algorithm from the authenticated format.
        const auto other = valid_cipher == CipherType::AES256 ? CipherType::XOR : CipherType::AES256;
        return expect(engine.process_file(encrypted, "selection-test", ActionType::DECRYPT,
                      other, false, output) && readBytes(output) == content,
                      "Valid decryption retains automatic algorithm detection");
    }
}

namespace {
    bool runDeletionFailureSafety(CipherType cipher) {
        TestWorkspace workspace;
        encryption_engine engine;
        const auto plain = workspace.path / "plain.bin";
        const auto encrypted = workspace.path / "plain.kasa";
        const auto output = workspace.path / "output.bin";
        const std::vector<std::uint8_t> content(4096, 0x6a);
        if (!writeBytes(plain, content) || !engine.process_file(plain, "delete-safety",
            ActionType::ENCRYPT, cipher, false, encrypted)) return false;
        const auto original = readBytes(encrypted);
        if (!expect(!engine.process_file(encrypted, "wrong", ActionType::DECRYPT,
            cipher, true, output) && readBytes(encrypted) == original &&
            !std::filesystem::exists(output), "Delete enabled: wrong password preserves source")) return false;
        std::filesystem::create_directory(output);
        if (!expect(!engine.process_file(encrypted, "delete-safety", ActionType::DECRYPT,
            cipher, true, output) && readBytes(encrypted) == original &&
            std::filesystem::is_directory(output), "Delete enabled: output failure preserves source")) return false;
        auto damaged = original;
        damaged[0] ^= 0x01;
        if (!writeBytes(encrypted, damaged)) return false;
        const auto rejected = workspace.path / "rejected.bin";
        return expect(!engine.process_file(encrypted, "delete-safety", ActionType::DECRYPT,
            cipher, true, rejected) && readBytes(encrypted) == damaged &&
            !std::filesystem::exists(rejected), "Delete enabled: tampered source is retained");
    }
}

int main() {
    const std::vector<std::uint8_t> binary_data {
        0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff, 0x0a, 0x0d, 0x00
    };

    bool passed = true;
    passed &= runInvalidSelectionTest(CipherType::AES256);
    passed &= runInvalidSelectionTest(CipherType::XOR);
    passed &= runRoundTrip(CipherType::AES256, "AES binary round-trip", binary_data);
    passed &= runRoundTrip(CipherType::AES256, "AES empty-file round-trip", {});
    passed &= runWrongPasswordTest(CipherType::AES256, "AES wrong password");
    passed &= runTamperTest(CipherType::AES256, "AES tamper detection");
    passed &= runRoundTrip(CipherType::XOR, "XOR binary round-trip", binary_data);
    passed &= runWrongPasswordTest(CipherType::XOR, "XOR wrong password");
    passed &= runTamperTest(CipherType::XOR, "XOR tamper detection");
    passed &= runInvalidFooterTest();
    passed &= runUnicodePathTest();
    passed &= runCaseInsensitiveExtensionTest();
    passed &= runTruncatedFormatTest();
    passed &= runTemporaryCollisionTest();
    passed &= runHardLinkDeletionTest();
    passed &= runSingleLinkDeletionTest();
    passed &= runAesNoUnauthenticatedFileTest(false);
    passed &= runAesNoUnauthenticatedFileTest(true);
    passed &= runAesBusyInputTest();
    passed &= runRoundTrip(CipherType::AES256, "AES multi-buffer round-trip",
                           std::vector<std::uint8_t>(1024 * 1024 + 17, 0xb3));
    for (const auto cipher : {CipherType::AES256, CipherType::XOR}) {
        for (int scenario = 0; scenario < 5; ++scenario) passed &= runSourceSnapshotTest(cipher, scenario);
        passed &= runAutomaticDeletionTest(cipher);
        passed &= runDeletionFailureSafety(cipher);
    }

    if (!passed) return 1;
    std::cout << "All KASA encryption engine tests passed.\n";
    return 0;
}
