#ifndef ENCRYPTION_ENCRYPTION_ENGINE_H
#define ENCRYPTION_ENCRYPTION_ENGINE_H

#include <string>
#include <filesystem>
#include <cstdint>
#include <optional>
#include <vector>
#include <array>
#include <memory>
#include <span>

// Contents are published only after authentication. Ownership cannot be copied
// or moved; callers transfer the unique_ptr instead of duplicating plaintext.
class AuthenticatedPreview {
    friend class encryption_engine;
    std::vector<unsigned char> bytes_;
    explicit AuthenticatedPreview(std::size_t size) : bytes_(size) {}
public:
    AuthenticatedPreview(const AuthenticatedPreview&) = delete;
    AuthenticatedPreview& operator=(const AuthenticatedPreview&) = delete;
    AuthenticatedPreview(AuthenticatedPreview&&) = delete;
    AuthenticatedPreview& operator=(AuthenticatedPreview&&) = delete;
    ~AuthenticatedPreview();
    [[nodiscard]] std::span<const unsigned char> bytes() const noexcept { return bytes_; }
};

enum class PreviewDecryptStatus { Success, InvalidRequest, Unavailable, TooLarge,
                                  InvalidFormat, UnsupportedCipher, AuthenticationFailed, InternalError };
struct PreviewDecryptResult {
    PreviewDecryptStatus status;
    std::unique_ptr<AuthenticatedPreview> content;
};

enum class ActionType {
    ENCRYPT,
    DECRYPT
};

enum class CipherType {
    XOR,
    AES256
};

struct KasaFileInfo {
    std::uint8_t format_version = 0;
    CipherType cipher = CipherType::AES256;
};

// Identifies the bytes actually read by the operation, not just a pathname.
struct SourceSnapshot {
    std::uint64_t file_id = 0;
    std::uint32_t volume = 0;
    std::uint64_t size = 0;
    std::uint64_t last_write = 0;
    std::array<unsigned char, 32> sha256 {};
    bool operator==(const SourceSnapshot&) const = default;
};

class encryption_engine {
    public:
    // AES format-v1 only for the first preview increment. No disk output or
    // fallback to file decryption. Limit is clamped to the 64 MiB preview cap.
    [[nodiscard]] PreviewDecryptResult decrypt_preview_aes(
        const std::filesystem::path& file_path, const std::string& password,
        std::uint64_t plaintext_limit = 64ULL * 1024 * 1024) const noexcept;
    bool encrypt_xor(std::filesystem::path file_path, const std::string& key, bool delete_original = false,
                     std::filesystem::path destination_path = {}, std::optional<SourceSnapshot>* snapshot = nullptr);
    bool dencrypt_xor(std::filesystem::path file_path, const std::string& key, bool delete_original = false,
                      std::filesystem::path destination_path = {}, std::optional<SourceSnapshot>* snapshot = nullptr);
    bool encrypt_aes256(std::filesystem::path file_path, const std::string& key, bool delete_original = false,
                        std::filesystem::path destination_path = {}, std::optional<SourceSnapshot>* snapshot = nullptr);
    bool dencrypt_aes256(std::filesystem::path file_path, const std::string& key, bool delete_original = false,
                         std::filesystem::path destination_path = {}, std::optional<SourceSnapshot>* snapshot = nullptr);
    bool delete_file(std::filesystem::path file_path);
    bool delete_file(std::filesystem::path file_path, const SourceSnapshot& expected);
    bool process_file(std::filesystem::path file_path, const std::string& key, ActionType action, CipherType cipher,
                      bool delete_original = false, std::filesystem::path destination_path = {},
                      std::optional<SourceSnapshot>* snapshot = nullptr);
    [[nodiscard]] std::optional<KasaFileInfo> inspect_file(
        const std::filesystem::path& file_path) const;
    void scan_and_process(std::filesystem::path root_path, std::string key, ActionType action, CipherType cipher, bool delete_original);


};


#endif //ENCRYPTION_ENCRYPTION_ENGINE_H
