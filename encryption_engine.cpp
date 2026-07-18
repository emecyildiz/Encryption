#include "encryption_engine.h"
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <stdio.h>
#include <io.h>

using namespace std;

struct FileGuard {
    std::filesystem::path target_path;
    bool success = false;

    // Nesne yaratılırken silinecek hedef yolu hafızaya alırız
    FileGuard(std::filesystem::path p) : target_path(p) {}

    // Kutsal An: Fonksiyon nerede biterse bitsin burası OTOMATİK çalışır!
    ~FileGuard() {
        if (!success) {
            std::filesystem::remove(target_path);
        }
    }
};

struct Header {
    char magic[4] = {'K', 'A', 'S', 'A'}; // Bu mühür her zaman sabit
    unsigned char cipher_id = 0;          // Bu alan şifreleme anında doldurulacak!
};

void encryption_engine::scan_and_process(std::filesystem::path root_path, std::string key, ActionType action, CipherType cipher, bool delete_original) {
    try {
        if (std::filesystem::exists(root_path)) {
            for (const auto &entry : std::filesystem::recursive_directory_iterator(root_path)) {
                if (std::filesystem::is_regular_file(entry) ) {
                    if (entry.path().extension() != ".kasa") {
                        process_file(entry, key, action, cipher, delete_original);
                    }
                }
            }

        }else {return;}
    }catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Hata: " << e.what() << '\n';
    }
}


bool encryption_engine::process_file(std::filesystem::path file_path, std::string key, ActionType action, CipherType cipher, bool delete_original) {
    switch (action) {
        case ActionType::ENCRYPT:
            switch (cipher) {
                case CipherType::AES256:
                    return encrypt_aes256(file_path, key, delete_original);
            case CipherType::XOR:
                    return encrypt_xor(file_path, key, delete_original);
            }
        case ActionType::DECRYPT:
            std::unique_ptr<FILE, decltype(&fclose)> file(fopen(file_path.string().c_str(), "rb"), &fclose);
            if (!file) {
                return false;
            }
            Header header;
            if (fread(&header, 1, sizeof(Header), file.get()) != sizeof(Header)) {
                std::cout << "Mühür okunamadi, dosya manipüle edilmiş olabilir!" << std::endl;
                return false;
            }
            if (strncmp(header.magic, "KASA", 4) == 0) {
                switch (header.cipher_id) {
                    case 1:
                        return dencrypt_xor(file_path,key, delete_original);
                    case 2:
                        return dencrypt_aes256(file_path, key, delete_original);
                }
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
    if (fseek(file.get(), 0, SEEK_END) != 0) {
        std::cout << "fseek failed delete" << std::endl;
        return false;
    }
    long long file_size = ftell(file.get());
    if (fseek(file.get(), 0, SEEK_SET) != 0) {
        std::cout << "ftell failed delete" << std::endl;
        return false;
    }
    unsigned char buffer[4096] = {0};

    size_t write_size = 0;
    while (write_size < file_size) {
        size_t written = (file_size-write_size > 4096) ? 4096 : (file_size-write_size);
        size_t btyes_written = fwrite(buffer, 1, written, file.get());
        if (btyes_written != written) {
            std::cout << "fwrite failed delete" << std::endl;
            return false;
        }
        write_size += btyes_written;
    }
    fflush(file.get());
    _commit(_fileno(file.get()));
    file.reset();
    std::filesystem::remove(file_path);
    return true;
}

bool encryption_engine::encrypt_aes256(std::filesystem::path file_path, std::string key, bool delete_original) {
    bool success = false;
    unsigned char output_hash[32];
    unsigned char nonce[12];
    unsigned char salt[16];
    if (RAND_bytes(salt, sizeof(salt)) != 1 ) return false;
    if (RAND_bytes(nonce,sizeof(nonce)) != 1) {
        std::cout << "RAND_bytes failed" << std::endl;
        return false;
    }
    std::unique_ptr<FILE, decltype(&fclose)> file(fopen(file_path.string().c_str(), "rb"), &fclose);

    if (file == NULL) {
        std::cout << "File does not exist şifrelenecek" << std::endl;
        return false;
    }

    if (PKCS5_PBKDF2_HMAC(
        key.c_str(), key.length(),    // Kullanıcının şifresi
        salt, sizeof(salt),           // Ürettiğimiz rastgele tuz
        100000,                       // 100 bin kez döndür (Hacker yavaşlatıcı)
        EVP_sha256(),                 // İçeride SHA256 kullan
        32, output_hash               // Çıkan 32 byte'ı buraya yaz
    ) != 1) {
        return false;
    }

    unsigned char input_file[4096];
    std::string out_path = file_path.string() + ".kasa";
    FileGuard file_guard(out_path);
    std::unique_ptr<FILE, decltype(&fclose)> out_file(fopen(out_path.c_str(), "wb"), &fclose);
    if (out_file == NULL) {
        std::cout << "File could not be opened .kasa yaratılamadı" << std::endl;
        return false;
    }
    if (fwrite(salt,16,1,out_file.get()) != 1) {
        std::cout << "salt could not be written" << std::endl;
        return false;
    }
    if (fwrite(nonce,1,12,out_file.get()) != 12) {
        std::cout << "File could not be written file dolu olabilir" << std::endl;
        return false;
    }
    size_t bytes_read;
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (ctx == NULL) {
        std::cout << "EVP_CIPHER_CTX_new failed ctx sorunu encryption" << std::endl;
        return false;
    };

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        std::cout << "EVP_EncryptInit_ex failed ctx sorunu encryption" << std::endl;
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        std::cout << "EVP_CIPHER_CTX_ctrl failed set ıvlen tarafı" << std::endl;
        return false;
    }
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, output_hash, nonce) != 1) {
        std::cout << "encrypt init failed" << std::endl;
        return false;
    }
    unsigned char output_file[4096];
    int bytes_written;
    while ((bytes_read = fread(input_file, 1, 4096, file.get())) > 0) {

        if (EVP_EncryptUpdate(ctx.get(), output_file, &bytes_written, input_file, bytes_read) != 1) {
            std::cout << "EVP_EncryptUpdate failed encryption" << std::endl;
            return false;
        }
        if (fwrite(output_file,1,bytes_written,out_file.get()) != bytes_written) {
            std::cout << "fwrite failed encryption bytes written" << std::endl;
            return false;
        }
    }
    if (ferror(file.get())) {
        std::cout << "HATA: Disk okunurken fiziksel bir hata oluştu!" << std::endl;
        return false;
    }
    unsigned char final_buf[16];
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), final_buf, &final_len) != 1) {
        std::cout << "EVP_EncryptFinal_ex failed encryption" << std::endl;
        return false;
    }
    if (final_len > 0) {
        if (fwrite(final_buf,1,final_len,out_file.get()) != final_len) {
            std::cout << "fwrite failed encryption" << std::endl;
            return false;
        }
    }
    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        std::cout << "EVP_CIPHER_CTX_ctrl failed encryption tag sorunu" << std::endl;
        return false;
    }
    if (fwrite(tag,1,16,out_file.get()) != 16) {
        std::cout << "fwrite failed encryption tag" << std::endl;
        return false;
    }
    std::cout << "şifreleme başarılı oldu" << std::endl;
    success = true;

    out_file.reset();
    file.reset();
    ctx.reset();

    file_guard.success = true;
    return success;

}

bool encryption_engine::dencrypt_aes256(std::filesystem::path file_path, std::string key, bool delete_original) {
    bool success = false;
    unsigned char output_hash[32];
    if (file_path.extension() != ".kasa") {
        std::cout << "dosyanın uzantısı .kasa değil" << std::endl;
        return false;
    }
    std::unique_ptr<FILE, decltype(&fclose)> file(fopen(file_path.string().c_str(), "rb"), &fclose);
    if (file == NULL) {
        std::cout << "açıla şifrelenmiş dosya boş " << std::endl;
        return false;
    }
    unsigned char salt[16];
    if (fread(salt, 1, 16, file.get()) != 16) {
        std::cout << "HATA: Salt değeri dosyadan okunamadı!" << std::endl;
        return false;
    }
    unsigned char nonce[12];
    if (fread(nonce,1,12,file.get()) != 12) {
        std::cout << "nonce fread sorunu"<< std::endl;
        return false;
    }
    unsigned char tag[16];

    if (fseek(file.get(), 0, SEEK_END) != 0) {
        std::cout << "fseek failed encryption" << std::endl;
        return false;
    }


    long long file_size = ftell(file.get());
    if (file_size < 0) {
        std::cout << "HATA: Dosya boyutu ölçülemedi, ftell başarısız oldu!" << std::endl;
        return false;
    }
    if (file_size < 44) {
        std::cout << "HATA: Dosya boyutu çok küçük, bu geçerli bir .kasa dosyası olamaz!" << std::endl;
        return false;
    }
    if (PKCS5_PBKDF2_HMAC(key.c_str(), key.length(), salt, sizeof(salt), 100000, EVP_sha256(), 32, output_hash) != 1) {
        return false;
    }
    if (fseek(file.get(), -16, SEEK_END) != 0) {
        std::cout << "fseek failed encryption after file size" << std::endl;
        return false;
    }

    if (fread(tag,1,16,file.get()) != 16) {
        std::cout << "tag fread sorunu" << std::endl;
        return false;
    }
    fseek(file.get(), 28, SEEK_SET);
    std::string out_path = (file_path.parent_path() / file_path.stem()).string();
    FileGuard file_guard(out_path);
    std::unique_ptr<FILE, decltype(&fclose)> out_file(fopen(out_path.c_str(), "wb"), &fclose);
    if (out_file == NULL) {
        std::cout << "açılan out_file boş" << std::endl;
        return false;
    }
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (ctx == NULL) {
        std::cout << "ctx boş " << std::endl;
        return false;
    };

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        std::cout << "EVP_DecryptInit_ex failed encryption" << std::endl;
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        std::cout << "EVP_CIPHER_CTX_ctrl sorunu" << std::endl;
        return false;
    }

    if ( EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, tag) != 1) {
        std::cout << "EVP_CIPHER_CTX_ctrl tag sorunu" << std::endl;
        return false;
    }

    if (EVP_DecryptInit_ex(ctx.get(), NULL, NULL, output_hash, nonce) != 1) {
        std::cout << "EVP_DecryptInit_ex failed encryption nonce değeri girilmis" << std::endl;
        return false;
    }
    unsigned char input_file[4096];
    unsigned char output_file[4096];
    size_t total_bytes_read = 0;
    size_t ciphertext_len = file_size - 12 - 16 -16;
    int bytes_written;
    size_t bytes_read;
    while (total_bytes_read < ciphertext_len) {
        size_t to_read = (ciphertext_len - total_bytes_read > 4096) ? 4096 : (ciphertext_len - total_bytes_read);
        bytes_read = fread(input_file, 1, to_read, file.get());
        if (bytes_read == 0) {
            std::cout << "bytes_read sorunu" << std::endl;
            return false;
        }
        if (EVP_DecryptUpdate(ctx.get(), output_file, &bytes_written, input_file, bytes_read) != 1) {
            std::cout << "EVP_DecryptUpdate sorunu" << std::endl;
            return false;
        }
        if (fwrite(output_file,1,bytes_written,out_file.get()) != bytes_written) {
            std::cout << "fwrite sorunu bytes written" << std::endl;
            return false;
        }
        total_bytes_read += bytes_read;
    }
    unsigned char final_buf[16];
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), final_buf, &final_len) != 1) {
        std::cout << "EVP_DecryptFinal sorunu" << std::endl;
        return false;
    }
    if (final_len > 0) {
        if (fwrite(final_buf,1,final_len,out_file.get()) != final_len) {
            std::cout << "fwrite sorunu" << std::endl;
            return false;
        }
    }
    std::cout << "başarılı deşifre" << std::endl;
    success = true;
    out_file.reset();
    file.reset();
    ctx.reset();

    file_guard.success = true;
    if (delete_original) {
        std::filesystem::remove(file_path);
    }
    return success;

}

bool encryption_engine::encrypt_xor(std::filesystem::path file_path, std::string key) {
    int A = key.size();
    std::unique_ptr<FILE, decltype(&fclose)> file(fopen(file_path.string().c_str(), "r+b"), fclose);
    if (file == NULL) {
        std::cout << "fopen sorunu" << std::endl;
        return false;
    }
    std::uintmax_t file_size = std::filesystem::file_size(file_path);
    if (fseek(file.get(), -5, SEEK_END) != 0) {
        std::cout << "fseek failed encryption after file size" << std::endl;
        return false;
    }
    unsigned char buffer[4096];
    size_t total_bytes_read = 0;
    size_t bytes_read = 0;
    size_t key_index = 0;
    while (total_bytes_read < file_size) {
        size_t written = (file_size-total_bytes_read > 4096) ? 4096 : (file_size-total_bytes_read);
        bytes_read = fread(buffer, 1, written, file.get());
        for (int i = 0; i < bytes_read; i++) {
            buffer[i] = buffer[i] ^ key[key_index%A];
            key_index++;
        }
        fseek(file.get(), -bytes_read, SEEK_CUR);
        fwrite(buffer, 1, bytes_read, file.get());
        fseek(file.get(), 0, SEEK_CUR);
        total_bytes_read += bytes_read;

    }
    Header header {.cipher_id = 1 };
    fwrite(&header, 1, sizeof(header), file.get());

    std::filesystem::path new_file_path = file_path;
    new_file_path += ".kasa";
    file.reset();
    std::filesystem::rename(file_path, new_file_path);
    return true;

}

bool encryption_engine::dencrypt_xor(std::filesystem::path file_path, std::string key) {
    int A = key.size();
    std::unique_ptr<FILE, decltype(&fclose)> file(fopen(file_path.string().c_str(), "r+b"), fclose);
    if (file == NULL) {
        std::cout << "fopen sorunu" << std::endl;
        return false;
    }
    std::uintmax_t file_size = std::filesystem::file_size(file_path);
    if (_fseeki64(file.get(), -5, SEEK_END) != 0) {
        std::cout << "fseek failed encryption after file size" << std::endl;
        return false;
    }
    size_t max_data_size = file_size - sizeof(Header);
    unsigned char buffer[4096];
    size_t total_bytes_read = 0;
    size_t bytes_read = 0;
    size_t key_index = 0;
    _fseeki64(file.get(), 0, SEEK_SET);
    while (total_bytes_read < max_data_size) {
        size_t written = (max_data_size - total_bytes_read > 4096) ? 4096 : (max_data_size - total_bytes_read);
        bytes_read = fread(buffer, 1, written, file.get());
        for (int i = 0; i < bytes_read; i++) {
            buffer[i] = buffer[i] ^ key[key_index%A];
            key_index++;
        }
        fseek(file.get(), -bytes_read, SEEK_CUR);
        fwrite(buffer, 1, bytes_read, file.get());
        fseek(file.get(), 0, SEEK_CUR);
        total_bytes_read += bytes_read;

    }
    std::filesystem::path new_file_path = file_path;
    new_file_path.replace_extension("");
    file.reset();
    std::filesystem::resize_file(file_path, file_size - sizeof(Header));
    std::filesystem::rename(file_path, new_file_path);
    return true;
}