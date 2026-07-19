#ifndef ENCRYPTION_ENCRYPTION_ENGINE_H
#define ENCRYPTION_ENCRYPTION_ENGINE_H

#include <string>
#include <filesystem>
#include <cstdint>
#include <optional>
#include <vector>

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

class encryption_engine {
    public:
    bool encrypt_xor(std::filesystem::path file_path, std::string key, bool delete_original = false,
                     std::filesystem::path destination_path = {});
    bool dencrypt_xor(std::filesystem::path file_path, std::string key, bool delete_original = false,
                      std::filesystem::path destination_path = {});
    bool encrypt_aes256(std::filesystem::path file_path, std::string key, bool delete_original = false,
                        std::filesystem::path destination_path = {});
    bool dencrypt_aes256(std::filesystem::path file_path, std::string key, bool delete_original = false,
                         std::filesystem::path destination_path = {});
    bool delete_file(std::filesystem::path file_path);
    bool process_file(std::filesystem::path file_path, std::string key, ActionType action, CipherType cipher,
                      bool delete_original = false, std::filesystem::path destination_path = {});
    [[nodiscard]] std::optional<KasaFileInfo> inspect_file(
        const std::filesystem::path& file_path) const;
    void scan_and_process(std::filesystem::path root_path, std::string key, ActionType action, CipherType cipher, bool delete_original);


};


#endif //ENCRYPTION_ENCRYPTION_ENGINE_H
