// Build against the old engine to create synthetic fixtures, and the candidate
// engine to verify them. This does not automate the graphical installer.
#include "encryption_engine.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <iterator>

namespace fs = std::filesystem;
using Bytes = std::vector<unsigned char>;
const std::string password = "synthetic-compatibility-test-only";
void require(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}
Bytes content(std::size_t n) {
    Bytes result(n);
    for (std::size_t i=0; i<n; ++i) result[i]=static_cast<unsigned char>((i*31+7)%256);
    return result;
}
Bytes read(const fs::path& p) {
    std::ifstream stream(p, std::ios::binary);
    require(stream.good(), "read failed");
    return {std::istreambuf_iterator<char>(stream), {}};
}
void write_new(const fs::path& p, const Bytes& bytes) {
    require(!fs::exists(p), "refusing to overwrite existing fixture");
    std::ofstream stream(p, std::ios::binary);
    stream.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    require(stream.good(), "write failed");
}
int wmain(int argc, wchar_t** argv) {
    try {
        require(argc==3, "usage: probe create|verify NEW_FIXTURE_DIRECTORY");
        const bool create = std::wstring(argv[1])==L"create";
        require(create || std::wstring(argv[1])==L"verify", "unknown mode");
        const fs::path root(argv[2]);
        if (create) {
            require(!fs::exists(root), "fixture directory already exists");
            require(fs::create_directories(root), "cannot create fixture directory");
        } else require(fs::is_directory(root), "fixture directory missing");
        encryption_engine engine;
        unsigned checks=0;
        for (const auto cipher : {CipherType::AES256, CipherType::XOR}) {
            for (std::size_t size : {std::size_t(0), std::size_t(17), std::size_t(1048589)}) {
                const auto name = (cipher==CipherType::AES256 ? "aes-" : "xor-") + std::to_string(size);
                const auto source=root/(name+".bin");
                const auto encrypted=root/(name+".bin.kasa");
                const auto expected=content(size);
                if (create) {
                    write_new(source, expected);
                    require(engine.process_file(source,password,ActionType::ENCRYPT,cipher,false,encrypted), "old engine encryption failed");
                    require(read(source)==expected, "source changed");
                    ++checks;
                    continue;
                }
                const auto original=read(encrypted);
                const auto info=engine.inspect_file(encrypted);
                require(info && info->format_version==1 && info->cipher==cipher, "format recognition failed"); ++checks;
                const auto output=root/(name+"-restored.bin");
                require(!fs::exists(output), "verification output already exists");
                require(engine.process_file(encrypted,password,ActionType::DECRYPT,cipher,false,output), "candidate decryption failed");
                require(read(output)==expected, "candidate plaintext mismatch"); ++checks;
                require(read(encrypted)==original, "encrypted source changed"); ++checks;
                const auto rejected=root/(name+"-rejected.bin");
                require(!fs::exists(rejected), "rejection output already exists");
                require(!engine.process_file(encrypted,"incorrect",ActionType::DECRYPT,cipher,false,rejected), "wrong password accepted");
                require(!fs::exists(rejected), "wrong password left output"); ++checks;
                if (cipher==CipherType::AES256) {
                    auto preview=engine.decrypt_preview_aes(encrypted,password);
                    require(preview.status==PreviewDecryptStatus::Success && preview.content, "authenticated preview failed");
                    const auto bytes=preview.content->bytes();
                    require(Bytes(bytes.begin(),bytes.end())==expected, "preview mismatch"); ++checks;
                }
                if (size>32) {
                    auto damaged=original;
                    damaged[32]^=0x40;
                    const auto tampered=root/(name+"-tampered.kasa");
                    write_new(tampered,damaged);
                    require(!engine.process_file(tampered,password,ActionType::DECRYPT,cipher,false,rejected), "tampered file accepted");
                    require(!fs::exists(rejected) && read(encrypted)==original, "tamper failure damaged original or created output"); ++checks;
                }
            }
        }
        std::cout << checks << (create ? " legacy fixtures created\n" : " cross-release checks passed\n");
        return 0;
    } catch(const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n'; return 1;
    }
}
