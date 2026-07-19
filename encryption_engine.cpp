#include "encryption_engine.h"
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <stdio.h>
#include <io.h>
#include <list>
#include <array>
#include <cstdint>
#include <algorithm>
#include <climits>

using namespace std;

struct FileGuard {
    std::filesystem::path target_path;
    bool success = false;

    // Nesne yaratılırken silinecek hedef yolu hafızaya alırız
    FileGuard(std::filesystem::path p) : target_path(p) {}

    // Kutsal An: Fonksiyon nerede biterse bitsin burası OTOMATİK çalışır!
    ~FileGuard() noexcept {
        if (!success) {
            std::error_code error;
            std::filesystem::remove(target_path, error);
        }
    }
};

namespace {
    constexpr std::array<char, 4> FOOTER_MAGIC {'K', 'A', 'S', 'A'};
    constexpr std::uint8_t FORMAT_VERSION = 1;
    constexpr std::size_t FOOTER_SIZE = FOOTER_MAGIC.size() + sizeof(std::uint8_t) * 2;
    constexpr std::uint8_t XOR_CIPHER_ID = 1;
    constexpr std::uint8_t AES256_CIPHER_ID = 2;
    constexpr std::size_t XOR_SALT_SIZE = 16;
    constexpr std::size_t XOR_TAG_SIZE = 32;
    constexpr std::size_t XOR_KEY_SIZE = 32;
    constexpr int XOR_KDF_ITERATIONS = 100000;
    constexpr std::size_t AES_SALT_SIZE = 16;
    constexpr std::size_t AES_NONCE_SIZE = 12;
    constexpr std::size_t AES_TAG_SIZE = 16;
    constexpr std::size_t AES_KEY_SIZE = 32;
    constexpr int AES_KDF_ITERATIONS = 100000;

    static_assert(FOOTER_SIZE == 6, "KASA footer boyutu beklenenden farkli");

    struct Footer {
        std::array<char, 4> magic {};
        std::uint8_t version = 0;
        std::uint8_t cipher_id = 0;
    };

    struct XorKeys {
        std::array<unsigned char, XOR_KEY_SIZE> encryption {};
        std::array<unsigned char, XOR_KEY_SIZE> authentication {};

        ~XorKeys() {
            OPENSSL_cleanse(encryption.data(), encryption.size());
            OPENSSL_cleanse(authentication.data(), authentication.size());
        }
    };

    struct AesKey {
        std::array<unsigned char, AES_KEY_SIZE> value {};

        ~AesKey() {
            OPENSSL_cleanse(value.data(), value.size());
        }
    };

    class HmacSha256 {
        EVP_MAC* mac = nullptr;
        EVP_MAC_CTX* context = nullptr;

    public:
        HmacSha256() {
            mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
            if (mac) {
                context = EVP_MAC_CTX_new(mac);
            }
        }

        ~HmacSha256() {
            EVP_MAC_CTX_free(context);
            EVP_MAC_free(mac);
        }

        HmacSha256(const HmacSha256&) = delete;
        HmacSha256& operator=(const HmacSha256&) = delete;

        bool initialize(const std::array<unsigned char, XOR_KEY_SIZE>& key) {
            if (!context) {
                return false;
            }
            char digest_name[] = "SHA256";
            OSSL_PARAM parameters[] = {
                OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0),
                OSSL_PARAM_construct_end()
            };
            return EVP_MAC_init(context, key.data(), key.size(), parameters) == 1;
        }

        bool update(const unsigned char* data, std::size_t size) {
            return context && EVP_MAC_update(context, data, size) == 1;
        }

        bool finish(std::array<unsigned char, XOR_TAG_SIZE>& tag) {
            std::size_t tag_size = 0;
            return context && EVP_MAC_final(context, tag.data(), &tag_size, tag.size()) == 1
                   && tag_size == tag.size();
        }
    };

    std::array<unsigned char, FOOTER_SIZE> make_footer_bytes(std::uint8_t cipher_id) {
        std::array<unsigned char, FOOTER_SIZE> bytes {};
        for (std::size_t i = 0; i < FOOTER_MAGIC.size(); ++i) {
            bytes[i] = static_cast<unsigned char>(FOOTER_MAGIC[i]);
        }
        bytes[FOOTER_MAGIC.size()] = FORMAT_VERSION;
        bytes[FOOTER_MAGIC.size() + 1] = cipher_id;
        return bytes;
    }

    bool write_footer(FILE* file, std::uint8_t cipher_id) {
        const auto bytes = make_footer_bytes(cipher_id);
        return fwrite(bytes.data(), 1, bytes.size(), file) == bytes.size();
    }

    bool read_footer(FILE* file, Footer& footer) {
        std::array<unsigned char, FOOTER_SIZE> bytes {};
        const auto footer_offset = -static_cast<std::int64_t>(FOOTER_SIZE);
        if (_fseeki64(file, footer_offset, SEEK_END) != 0) {
            return false;
        }
        if (fread(bytes.data(), 1, bytes.size(), file) != bytes.size()) {
            return false;
        }
        for (std::size_t i = 0; i < footer.magic.size(); ++i) {
            footer.magic[i] = static_cast<char>(bytes[i]);
        }
        footer.version = bytes[FOOTER_MAGIC.size()];
        footer.cipher_id = bytes[FOOTER_MAGIC.size() + 1];
        return true;
    }

    bool derive_xor_keys(const std::string& password,
                         const std::array<unsigned char, XOR_SALT_SIZE>& salt,
                         XorKeys& keys) {
        if (password.empty() || password.size() > static_cast<std::size_t>(INT_MAX)) {
            return false;
        }

        std::array<unsigned char, XOR_KEY_SIZE * 2> derived {};
        const int result = PKCS5_PBKDF2_HMAC(
            password.c_str(), static_cast<int>(password.size()),
            salt.data(), static_cast<int>(salt.size()),
            XOR_KDF_ITERATIONS, EVP_sha256(),
            static_cast<int>(derived.size()), derived.data());

        if (result != 1) {
            OPENSSL_cleanse(derived.data(), derived.size());
            return false;
        }

        std::copy_n(derived.begin(), XOR_KEY_SIZE, keys.encryption.begin());
        std::copy_n(derived.begin() + XOR_KEY_SIZE, XOR_KEY_SIZE, keys.authentication.begin());
        OPENSSL_cleanse(derived.data(), derived.size());
        return true;
    }

    bool derive_aes_key(const std::string& password,
                        const std::array<unsigned char, AES_SALT_SIZE>& salt,
                        AesKey& key) {
        if (password.empty() || password.size() > static_cast<std::size_t>(INT_MAX)) {
            return false;
        }
        return PKCS5_PBKDF2_HMAC(
            password.c_str(), static_cast<int>(password.size()),
            salt.data(), static_cast<int>(salt.size()),
            AES_KDF_ITERATIONS, EVP_sha256(),
            static_cast<int>(key.value.size()), key.value.data()) == 1;
    }

    bool finish_file(FILE* file) {
        return fflush(file) == 0 && _commit(_fileno(file)) == 0;
    }
}

void encryption_engine::scan_and_process(std::filesystem::path root_path, std::string key, ActionType action, CipherType cipher, bool delete_original) {
    try {
        std::list<std::filesystem::path> files;
        if (std::filesystem::exists(root_path)) {
            for (const auto &entry : std::filesystem::recursive_directory_iterator(root_path)) {
                if (std::filesystem::is_regular_file(entry) ) {
                    switch (action) {
                        case ActionType::ENCRYPT:
                            if (entry.path().extension() != ".kasa") {
                                files.push_back(entry.path());
                            }
                            break;
                        case ActionType::DECRYPT:
                            if (entry.path().extension() == ".kasa") {
                                files.push_back(entry.path());
                            }
                            break;
                    }
                }
            }

        }else {return;}
        for (const auto &file : files) {
            process_file(file, key, action, cipher, delete_original);
        }
    }catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Hata: " << e.what() << '\n';
    }
}


bool encryption_engine::process_file(std::filesystem::path file_path, std::string key, ActionType action,
                                     CipherType cipher, bool delete_original,
                                     std::filesystem::path destination_path) {
    switch (action) {
        case ActionType::ENCRYPT:
            switch (cipher) {
                case CipherType::AES256:
                    return encrypt_aes256(file_path, key, delete_original, destination_path);
            case CipherType::XOR:
                    return encrypt_xor(file_path, key, delete_original, destination_path);
            }
        case ActionType::DECRYPT: {
            std::unique_ptr<FILE, decltype(&fclose)> file(fopen(file_path.string().c_str(), "rb"), &fclose);
            if (!file) {
                return false;
            }
            std::uintmax_t file_size = std::filesystem::file_size(file_path);
            if (file_size < FOOTER_SIZE) {
                return false;
            }
            Footer footer;
            if (!read_footer(file.get(), footer)) {
                std::cout << "Mühür okunamadi, dosya manipüle edilmiş olabilir!" << std::endl;
                return false;
            }
            if (footer.magic == FOOTER_MAGIC && footer.version == FORMAT_VERSION) {
                file.reset();
                switch (footer.cipher_id) {
                    case XOR_CIPHER_ID:
                        return dencrypt_xor(file_path, key, delete_original, destination_path);
                    case AES256_CIPHER_ID:
                        return dencrypt_aes256(file_path, key, delete_original, destination_path);
                }
            }
            return false;
        }
        default:
            std::cout << "process_file hatası" << std::endl;
            return false;
    }
    std::cout << "hata oldu seçim" << std::endl;
    return false;
}


bool encryption_engine::delete_file(std::filesystem::path file_path) {
    std::unique_ptr<FILE, decltype(&fclose)> file(fopen(file_path.string().c_str(),"r+b"),&fclose);
    if (file == nullptr) {
        return false;
    }
    if (_fseeki64(file.get(), 0, SEEK_END) != 0) {
        std::cout << "fseek failed delete" << std::endl;
        return false;
    }
    const std::int64_t file_size = _ftelli64(file.get());
    if (file_size < 0 || _fseeki64(file.get(), 0, SEEK_SET) != 0) {
        std::cout << "file size failed delete" << std::endl;
        return false;
    }
    unsigned char buffer[4096] = {0};

    std::int64_t write_size = 0;
    while (write_size < file_size) {
        const std::size_t written = static_cast<std::size_t>(
            std::min<std::int64_t>(sizeof(buffer), file_size - write_size));
        size_t btyes_written = fwrite(buffer, 1, written, file.get());
        if (btyes_written != written) {
            std::cout << "fwrite failed delete" << std::endl;
            return false;
        }
        write_size += btyes_written;
    }
    if (!finish_file(file.get())) {
        return false;
    }
    file.reset();
    std::error_code remove_error;
    const bool removed = std::filesystem::remove(file_path, remove_error);
    return removed && !remove_error;
}

bool encryption_engine::encrypt_aes256(std::filesystem::path file_path, std::string key, bool delete_original,
                                       std::filesystem::path destination_path) {
    if (key.empty()) {
        std::cout << "Sifre bos olamaz" << std::endl;
        return false;
    }

    std::filesystem::path output_path = std::move(destination_path);
    if (output_path.empty()) {
        output_path = file_path;
        output_path += ".kasa";
    }
    std::filesystem::path temporary_path = output_path;
    temporary_path += ".tmp";
    if (std::filesystem::exists(output_path) || std::filesystem::exists(temporary_path)) {
        std::cout << "Hedef dosya zaten mevcut" << std::endl;
        return false;
    }

    std::unique_ptr<FILE, decltype(&fclose)> input(fopen(file_path.string().c_str(), "rb"), &fclose);
    if (!input) {
        std::cout << "Kaynak dosya acilamadi" << std::endl;
        return false;
    }

    std::array<unsigned char, AES_SALT_SIZE> salt {};
    std::array<unsigned char, AES_NONCE_SIZE> nonce {};
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1 ||
        RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
        std::cout << "AES salt veya nonce uretilemedi" << std::endl;
        return false;
    }

    AesKey aes_key;
    if (!derive_aes_key(key, salt, aes_key)) {
        std::cout << "AES anahtari turetilemedi" << std::endl;
        return false;
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(
        EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!context || EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(context.get(), nullptr, nullptr, aes_key.value.data(), nonce.data()) != 1) {
        std::cout << "AES-GCM sifreleme baslatilamadi" << std::endl;
        return false;
    }

    const auto footer_bytes = make_footer_bytes(AES256_CIPHER_ID);
    int aad_length = 0;
    if (EVP_EncryptUpdate(context.get(), nullptr, &aad_length,
                          salt.data(), static_cast<int>(salt.size())) != 1 ||
        EVP_EncryptUpdate(context.get(), nullptr, &aad_length,
                          nonce.data(), static_cast<int>(nonce.size())) != 1 ||
        EVP_EncryptUpdate(context.get(), nullptr, &aad_length,
                          footer_bytes.data(), static_cast<int>(footer_bytes.size())) != 1) {
        std::cout << "AES-GCM AAD eklenemedi" << std::endl;
        return false;
    }

    FileGuard temporary_guard(temporary_path);
    std::unique_ptr<FILE, decltype(&fclose)> output(fopen(temporary_path.string().c_str(), "wb"), &fclose);
    if (!output || fwrite(salt.data(), 1, salt.size(), output.get()) != salt.size() ||
        fwrite(nonce.data(), 1, nonce.size(), output.get()) != nonce.size()) {
        std::cout << "Gecici AES dosyasi olusturulamadi" << std::endl;
        return false;
    }

    std::array<unsigned char, 4096> input_buffer {};
    std::array<unsigned char, 4096 + EVP_MAX_BLOCK_LENGTH> output_buffer {};
    while (true) {
        const std::size_t bytes_read = fread(input_buffer.data(), 1, input_buffer.size(), input.get());
        if (bytes_read == 0) {
            break;
        }
        int bytes_written = 0;
        if (EVP_EncryptUpdate(context.get(), output_buffer.data(), &bytes_written,
                              input_buffer.data(), static_cast<int>(bytes_read)) != 1 ||
            (bytes_written > 0 && fwrite(output_buffer.data(), 1,
                                         static_cast<std::size_t>(bytes_written), output.get())
                                  != static_cast<std::size_t>(bytes_written))) {
            std::cout << "AES verisi sifrelenemedi" << std::endl;
            return false;
        }
    }
    if (ferror(input.get())) {
        std::cout << "Kaynak dosya okunamadi" << std::endl;
        return false;
    }

    int final_length = 0;
    if (EVP_EncryptFinal_ex(context.get(), output_buffer.data(), &final_length) != 1 ||
        (final_length > 0 && fwrite(output_buffer.data(), 1,
                                    static_cast<std::size_t>(final_length), output.get())
                             != static_cast<std::size_t>(final_length))) {
        std::cout << "AES sifreleme tamamlanamadi" << std::endl;
        return false;
    }

    std::array<unsigned char, AES_TAG_SIZE> tag {};
    if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(tag.size()), tag.data()) != 1 ||
        fwrite(tag.data(), 1, tag.size(), output.get()) != tag.size() ||
        !write_footer(output.get(), AES256_CIPHER_ID) || !finish_file(output.get())) {
        std::cout << "AES tag veya footer yazilamadi" << std::endl;
        return false;
    }

    output.reset();
    input.reset();
    context.reset();

    std::error_code rename_error;
    std::filesystem::rename(temporary_path, output_path, rename_error);
    if (rename_error) {
        std::cout << "Gecici AES dosyasi yeniden adlandirilamadi" << std::endl;
        return false;
    }
    temporary_guard.success = true;

    if (delete_original && !delete_file(file_path)) {
        std::cout << "Sifreleme tamamlandi ancak orijinal dosya silinemedi" << std::endl;
        return false;
    }
    return true;
}

bool encryption_engine::dencrypt_aes256(std::filesystem::path file_path, std::string key, bool delete_original,
                                        std::filesystem::path destination_path) {
    if (key.empty() || file_path.extension() != ".kasa") {
        std::cout << "Gecersiz AES cozme istegi" << std::endl;
        return false;
    }

    std::unique_ptr<FILE, decltype(&fclose)> input(fopen(file_path.string().c_str(), "rb"), &fclose);
    if (!input) {
        std::cout << "Sifreli AES dosyasi acilamadi" << std::endl;
        return false;
    }

    const std::uintmax_t file_size = std::filesystem::file_size(file_path);
    const std::uintmax_t metadata_size = AES_SALT_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE + FOOTER_SIZE;
    if (file_size < metadata_size) {
        std::cout << "Gecersiz AES dosya boyutu" << std::endl;
        return false;
    }
    const std::uintmax_t ciphertext_size = file_size - metadata_size;

    Footer footer;
    if (!read_footer(input.get(), footer) || footer.magic != FOOTER_MAGIC ||
        footer.version != FORMAT_VERSION || footer.cipher_id != AES256_CIPHER_ID) {
        std::cout << "Gecersiz AES footer" << std::endl;
        return false;
    }

    if (_fseeki64(input.get(), 0, SEEK_SET) != 0) {
        return false;
    }
    std::array<unsigned char, AES_SALT_SIZE> salt {};
    std::array<unsigned char, AES_NONCE_SIZE> nonce {};
    if (fread(salt.data(), 1, salt.size(), input.get()) != salt.size() ||
        fread(nonce.data(), 1, nonce.size(), input.get()) != nonce.size()) {
        std::cout << "AES salt veya nonce okunamadi" << std::endl;
        return false;
    }

    const std::uintmax_t tag_offset = AES_SALT_SIZE + AES_NONCE_SIZE + ciphertext_size;
    if (_fseeki64(input.get(), static_cast<std::int64_t>(tag_offset), SEEK_SET) != 0) {
        return false;
    }
    std::array<unsigned char, AES_TAG_SIZE> tag {};
    if (fread(tag.data(), 1, tag.size(), input.get()) != tag.size()) {
        std::cout << "AES tag okunamadi" << std::endl;
        return false;
    }

    AesKey aes_key;
    if (!derive_aes_key(key, salt, aes_key)) {
        std::cout << "AES anahtari turetilemedi" << std::endl;
        return false;
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(
        EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!context || EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, aes_key.value.data(), nonce.data()) != 1) {
        std::cout << "AES-GCM cozme baslatilamadi" << std::endl;
        return false;
    }

    const auto footer_bytes = make_footer_bytes(AES256_CIPHER_ID);
    int aad_length = 0;
    if (EVP_DecryptUpdate(context.get(), nullptr, &aad_length,
                          salt.data(), static_cast<int>(salt.size())) != 1 ||
        EVP_DecryptUpdate(context.get(), nullptr, &aad_length,
                          nonce.data(), static_cast<int>(nonce.size())) != 1 ||
        EVP_DecryptUpdate(context.get(), nullptr, &aad_length,
                          footer_bytes.data(), static_cast<int>(footer_bytes.size())) != 1) {
        std::cout << "AES-GCM AAD dogrulanamadi" << std::endl;
        return false;
    }

    std::filesystem::path output_path = std::move(destination_path);
    if (output_path.empty()) {
        output_path = file_path;
        output_path.replace_extension("");
    }
    std::filesystem::path temporary_path = output_path;
    temporary_path += ".tmp";
    if (std::filesystem::exists(output_path) || std::filesystem::exists(temporary_path)) {
        std::cout << "Cozulmus hedef dosya zaten mevcut" << std::endl;
        return false;
    }
    if (_fseeki64(input.get(), static_cast<std::int64_t>(AES_SALT_SIZE + AES_NONCE_SIZE), SEEK_SET) != 0) {
        return false;
    }

    FileGuard temporary_guard(temporary_path);
    std::unique_ptr<FILE, decltype(&fclose)> output(fopen(temporary_path.string().c_str(), "wb"), &fclose);
    if (!output) {
        std::cout << "Gecici cozulmus AES dosyasi olusturulamadi" << std::endl;
        return false;
    }

    std::array<unsigned char, 4096> input_buffer {};
    std::array<unsigned char, 4096 + EVP_MAX_BLOCK_LENGTH> output_buffer {};
    std::uintmax_t processed_bytes = 0;
    while (processed_bytes < ciphertext_size) {
        const std::size_t to_read = static_cast<std::size_t>(
            std::min<std::uintmax_t>(input_buffer.size(), ciphertext_size - processed_bytes));
        const std::size_t bytes_read = fread(input_buffer.data(), 1, to_read, input.get());
        int bytes_written = 0;
        if (bytes_read != to_read ||
            EVP_DecryptUpdate(context.get(), output_buffer.data(), &bytes_written,
                              input_buffer.data(), static_cast<int>(bytes_read)) != 1 ||
            (bytes_written > 0 && fwrite(output_buffer.data(), 1,
                                         static_cast<std::size_t>(bytes_written), output.get())
                                  != static_cast<std::size_t>(bytes_written))) {
            std::cout << "AES verisi cozulemedi" << std::endl;
            return false;
        }
        processed_bytes += bytes_read;
    }

    if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(tag.size()), tag.data()) != 1) {
        return false;
    }
    int final_length = 0;
    if (EVP_DecryptFinal_ex(context.get(), output_buffer.data(), &final_length) != 1) {
        std::cout << "Sifre yanlis veya dosya bozulmus" << std::endl;
        return false;
    }
    if ((final_length > 0 && fwrite(output_buffer.data(), 1,
                                    static_cast<std::size_t>(final_length), output.get())
                             != static_cast<std::size_t>(final_length)) ||
        !finish_file(output.get())) {
        std::cout << "Cozulmus AES dosyasi tamamlanamadi" << std::endl;
        return false;
    }

    output.reset();
    input.reset();
    context.reset();

    std::error_code rename_error;
    std::filesystem::rename(temporary_path, output_path, rename_error);
    if (rename_error) {
        std::cout << "Gecici cozulmus AES dosyasi yeniden adlandirilamadi" << std::endl;
        return false;
    }
    temporary_guard.success = true;

    if (delete_original && !delete_file(file_path)) {
        std::cout << "Dosya cozuldu ancak sifreli dosya silinemedi" << std::endl;
        return false;
    }
    return true;
}

bool encryption_engine::encrypt_xor(std::filesystem::path file_path, std::string key, bool delete_original,
                                    std::filesystem::path destination_path) {
    if (key.empty()) {
        std::cout << "Sifre bos olamaz" << std::endl;
        return false;
    }

    std::filesystem::path output_path = std::move(destination_path);
    if (output_path.empty()) {
        output_path = file_path;
        output_path += ".kasa";
    }
    std::filesystem::path temporary_path = output_path;
    temporary_path += ".tmp";

    if (std::filesystem::exists(output_path) || std::filesystem::exists(temporary_path)) {
        std::cout << "Hedef dosya zaten mevcut" << std::endl;
        return false;
    }

    std::unique_ptr<FILE, decltype(&fclose)> input(fopen(file_path.string().c_str(), "rb"), &fclose);
    if (!input) {
        std::cout << "Kaynak dosya acilamadi" << std::endl;
        return false;
    }

    std::array<unsigned char, XOR_SALT_SIZE> salt {};
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
        std::cout << "Salt uretilemedi" << std::endl;
        return false;
    }

    XorKeys keys;
    if (!derive_xor_keys(key, salt, keys)) {
        std::cout << "XOR anahtarlari turetilemedi" << std::endl;
        return false;
    }

    FileGuard temporary_guard(temporary_path);
    std::unique_ptr<FILE, decltype(&fclose)> output(fopen(temporary_path.string().c_str(), "wb"), &fclose);
    if (!output) {
        std::cout << "Gecici dosya olusturulamadi" << std::endl;
        return false;
    }

    HmacSha256 hmac;
    if (!hmac.initialize(keys.authentication)) {
        std::cout << "HMAC baslatilamadi" << std::endl;
        return false;
    }

    std::array<unsigned char, 4096> buffer {};
    std::size_t key_index = 0;
    while (true) {
        const std::size_t bytes_read = fread(buffer.data(), 1, buffer.size(), input.get());
        if (bytes_read == 0) {
            break;
        }

        for (std::size_t i = 0; i < bytes_read; ++i) {
            buffer[i] ^= keys.encryption[key_index % keys.encryption.size()];
            ++key_index;
        }

        if (!hmac.update(buffer.data(), bytes_read) ||
            fwrite(buffer.data(), 1, bytes_read, output.get()) != bytes_read) {
            std::cout << "XOR verisi yazilamadi" << std::endl;
            return false;
        }
    }

    if (ferror(input.get())) {
        std::cout << "Kaynak dosya okunamadi" << std::endl;
        return false;
    }

    const auto footer_bytes = make_footer_bytes(XOR_CIPHER_ID);
    if (fwrite(salt.data(), 1, salt.size(), output.get()) != salt.size() ||
        !hmac.update(salt.data(), salt.size()) ||
        !hmac.update(footer_bytes.data(), footer_bytes.size())) {
        std::cout << "XOR metadata yazilamadi" << std::endl;
        return false;
    }

    std::array<unsigned char, XOR_TAG_SIZE> tag {};
    if (!hmac.finish(tag) ||
        fwrite(tag.data(), 1, tag.size(), output.get()) != tag.size() ||
        !write_footer(output.get(), XOR_CIPHER_ID) || !finish_file(output.get())) {
        std::cout << "XOR dosyasi tamamlanamadi" << std::endl;
        return false;
    }

    output.reset();
    input.reset();

    std::error_code rename_error;
    std::filesystem::rename(temporary_path, output_path, rename_error);
    if (rename_error) {
        std::cout << "Gecici dosya yeniden adlandirilamadi" << std::endl;
        return false;
    }
    temporary_guard.success = true;

    if (delete_original && !delete_file(file_path)) {
        std::cout << "Sifreleme tamamlandi ancak orijinal dosya silinemedi" << std::endl;
        return false;
    }
    return true;
}

bool encryption_engine::dencrypt_xor(std::filesystem::path file_path, std::string key, bool delete_original,
                                     std::filesystem::path destination_path) {
    if (key.empty()) {
        std::cout << "Sifre bos olamaz" << std::endl;
        return false;
    }

    std::unique_ptr<FILE, decltype(&fclose)> input(fopen(file_path.string().c_str(), "rb"), &fclose);
    if (!input) {
        std::cout << "Sifreli dosya acilamadi" << std::endl;
        return false;
    }

    const std::uintmax_t file_size = std::filesystem::file_size(file_path);
    const std::uintmax_t metadata_size = XOR_SALT_SIZE + XOR_TAG_SIZE + FOOTER_SIZE;
    if (file_size < metadata_size) {
        std::cout << "Gecersiz XOR dosya boyutu" << std::endl;
        return false;
    }
    const std::uintmax_t ciphertext_size = file_size - metadata_size;

    Footer footer;
    if (!read_footer(input.get(), footer) || footer.magic != FOOTER_MAGIC ||
        footer.version != FORMAT_VERSION || footer.cipher_id != XOR_CIPHER_ID) {
        std::cout << "Gecersiz XOR footer" << std::endl;
        return false;
    }

    if (_fseeki64(input.get(), static_cast<std::int64_t>(ciphertext_size), SEEK_SET) != 0) {
        std::cout << "XOR metadata konumuna gidilemedi" << std::endl;
        return false;
    }

    std::array<unsigned char, XOR_SALT_SIZE> salt {};
    std::array<unsigned char, XOR_TAG_SIZE> stored_tag {};
    if (fread(salt.data(), 1, salt.size(), input.get()) != salt.size() ||
        fread(stored_tag.data(), 1, stored_tag.size(), input.get()) != stored_tag.size()) {
        std::cout << "XOR metadata okunamadi" << std::endl;
        return false;
    }

    XorKeys keys;
    if (!derive_xor_keys(key, salt, keys)) {
        std::cout << "XOR anahtarlari turetilemedi" << std::endl;
        return false;
    }

    HmacSha256 hmac;
    if (!hmac.initialize(keys.authentication) || _fseeki64(input.get(), 0, SEEK_SET) != 0) {
        std::cout << "HMAC dogrulamasi baslatilamadi" << std::endl;
        return false;
    }

    std::array<unsigned char, 4096> buffer {};
    std::uintmax_t authenticated_bytes = 0;
    while (authenticated_bytes < ciphertext_size) {
        const std::size_t to_read = static_cast<std::size_t>(
            std::min<std::uintmax_t>(buffer.size(), ciphertext_size - authenticated_bytes));
        const std::size_t bytes_read = fread(buffer.data(), 1, to_read, input.get());
        if (bytes_read != to_read || !hmac.update(buffer.data(), bytes_read)) {
            std::cout << "XOR verisi dogrulanamadi" << std::endl;
            return false;
        }
        authenticated_bytes += bytes_read;
    }

    const auto footer_bytes = make_footer_bytes(XOR_CIPHER_ID);
    std::array<unsigned char, XOR_TAG_SIZE> calculated_tag {};
    if (!hmac.update(salt.data(), salt.size()) ||
        !hmac.update(footer_bytes.data(), footer_bytes.size()) ||
        !hmac.finish(calculated_tag) ||
        CRYPTO_memcmp(stored_tag.data(), calculated_tag.data(), stored_tag.size()) != 0) {
        std::cout << "Sifre yanlis veya dosya bozulmus" << std::endl;
        return false;
    }

    std::filesystem::path output_path = std::move(destination_path);
    if (output_path.empty()) {
        output_path = file_path;
        output_path.replace_extension("");
    }
    std::filesystem::path temporary_path = output_path;
    temporary_path += ".tmp";
    if (std::filesystem::exists(output_path) || std::filesystem::exists(temporary_path)) {
        std::cout << "Cozulmus hedef dosya zaten mevcut" << std::endl;
        return false;
    }

    if (_fseeki64(input.get(), 0, SEEK_SET) != 0) {
        return false;
    }
    FileGuard temporary_guard(temporary_path);
    std::unique_ptr<FILE, decltype(&fclose)> output(fopen(temporary_path.string().c_str(), "wb"), &fclose);
    if (!output) {
        std::cout << "Gecici cozulmus dosya olusturulamadi" << std::endl;
        return false;
    }

    std::uintmax_t decrypted_bytes = 0;
    std::size_t key_index = 0;
    while (decrypted_bytes < ciphertext_size) {
        const std::size_t to_read = static_cast<std::size_t>(
            std::min<std::uintmax_t>(buffer.size(), ciphertext_size - decrypted_bytes));
        const std::size_t bytes_read = fread(buffer.data(), 1, to_read, input.get());
        if (bytes_read != to_read) {
            std::cout << "XOR verisi okunamadi" << std::endl;
            return false;
        }
        for (std::size_t i = 0; i < bytes_read; ++i) {
            buffer[i] ^= keys.encryption[key_index % keys.encryption.size()];
            ++key_index;
        }
        if (fwrite(buffer.data(), 1, bytes_read, output.get()) != bytes_read) {
            std::cout << "Cozulmus XOR verisi yazilamadi" << std::endl;
            return false;
        }
        decrypted_bytes += bytes_read;
    }

    if (!finish_file(output.get())) {
        std::cout << "Cozulmus XOR dosyasi tamamlanamadi" << std::endl;
        return false;
    }
    output.reset();
    input.reset();

    std::error_code rename_error;
    std::filesystem::rename(temporary_path, output_path, rename_error);
    if (rename_error) {
        std::cout << "Gecici cozulmus dosya yeniden adlandirilamadi" << std::endl;
        return false;
    }
    temporary_guard.success = true;

    if (delete_original && !delete_file(file_path)) {
        std::cout << "Dosya cozuldu ancak sifreli dosya silinemedi" << std::endl;
        return false;
    }
    return true;
}
