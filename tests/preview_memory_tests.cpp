#include "encryption_engine.h"
#include "preview_policy.h"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <type_traits>
#include <windows.h>

static_assert(!std::is_copy_constructible_v<AuthenticatedPreview>);
static_assert(!std::is_move_constructible_v<AuthenticatedPreview>);
int main() {
    namespace fs = std::filesystem;
    using S = PreviewDecryptStatus;
    const auto root = fs::temp_directory_path() / ("kasa-preview-test-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directory(root);
    struct Cleanup { fs::path p; ~Cleanup(){std::error_code ec; fs::remove_all(p, ec);} } cleanup{root};
    auto write = [](const fs::path& p, const std::vector<unsigned char>& b) {
        std::ofstream f(p, std::ios::binary); f.write(reinterpret_cast<const char*>(b.data()), b.size());
    };
    auto read = [](const fs::path& p) {
        std::ifstream f(p, std::ios::binary);
        return std::vector<unsigned char>(std::istreambuf_iterator<char>(f), {});
    };
    int failures=0, checks=0;
    auto check = [&](bool ok, const char* name) {++checks; if(!ok){++failures; std::cerr<<"FAIL: "<<name<<'\n';}};
    encryption_engine engine;
    const std::string password="Synthetic-preview-test!";
    for (const std::size_t size : {0u, 1u, 4097u, 65537u}) {
        std::vector<unsigned char> data(size);
        for(std::size_t i=0;i<size;++i)data[i]=static_cast<unsigned char>(i%251);
        const auto src=root/(std::to_string(size)+".txt"), enc=root/(std::to_string(size)+".txt.kasa");
        write(src,data);
        if(!engine.encrypt_aes256(src,password,false,enc)) return 2;
        const auto original=read(enc);
        fs::remove(src); // synthetic fixture only: any accidental output becomes detectable
        auto result=engine.decrypt_preview_aes(enc,password,size);
        check(result.status==S::Success && result.content && result.content->bytes().size()==size
            && std::equal(data.begin(),data.end(),result.content->bytes().begin()), "authenticated roundtrip");
        result.content.reset();
        auto wrong=engine.decrypt_preview_aes(enc,"wrong");
        check(wrong.status==S::AuthenticationFailed && !wrong.content,"wrong password exposes no content");
        if(size){auto limit=engine.decrypt_preview_aes(enc,password,size-1);
            check(limit.status==S::TooLarge && !limit.content,"plaintext limit before allocation");}
        check(read(enc)==original && !fs::exists(src) && !fs::exists(src.string()+".tmp"),"source unchanged no plaintext output");
        for (auto pos : {std::size_t(0), std::size_t(16), original.size()-7, original.size()-1}) {
            auto damaged=original; damaged[pos]^=0x40; write(enc,damaged);
            auto bad=engine.decrypt_preview_aes(enc,password);
            check(bad.status!=S::Success && !bad.content,"tampered metadata/tag/footer rejected");
        }
        if(size){auto damaged=original;damaged[28]^=1;write(enc,damaged);
            auto bad=engine.decrypt_preview_aes(enc,password);check(!bad.content && bad.status==S::AuthenticationFailed,"ciphertext tamper");}
        write(enc,std::vector<unsigned char>(original.begin(),original.begin()+10));
        auto short_file=engine.decrypt_preview_aes(enc,password);
        check(short_file.status==S::InvalidFormat && !short_file.content,"truncated file");
        write(enc,original);
        HANDLE locked=CreateFileW(enc.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);
        check(locked!=INVALID_HANDLE_VALUE,"lock fixture");
        auto busy=engine.decrypt_preview_aes(enc,password);
        check(busy.status==S::Unavailable && !busy.content,"writer locked source");
        if(locked!=INVALID_HANDLE_VALUE) CloseHandle(locked);
    }
    auto missing=engine.decrypt_preview_aes(root/"missing.kasa",password);
    check(missing.status==S::Unavailable && !missing.content,"missing file");
    auto empty=engine.decrypt_preview_aes(root/"0.txt.kasa","");
    check(empty.status==S::InvalidRequest && !empty.content,"empty password");
    const auto big=root/"big.kasa";
    write(big,{});fs::resize_file(big,kasa::preview::max_encrypted_bytes+1);
    auto large=engine.decrypt_preview_aes(big,password);
    check(large.status==S::TooLarge && !large.content,"input hard cap");
    auto xsrc=root/"xor.txt", xenc=root/"xor.txt.kasa";write(xsrc,{1,2,3});
    if(!engine.encrypt_xor(xsrc,password,false,xenc))return 2;
    auto legacy=engine.decrypt_preview_aes(xenc,password);
    check(legacy.status==S::UnsupportedCipher && !legacy.content,"XOR explicit no disk fallback");
    std::cout<<checks<<" memory preview checks; "<<failures<<" failures.\n";
    return failures?1:0;
}
