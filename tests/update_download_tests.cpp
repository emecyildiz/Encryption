#include "update_download.h"
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <memory>
#include <iostream>
#include <vector>

int main(int argc,char**) {
    using namespace kasa::updates;
    std::atomic<bool> cancel{false};
    if(argc>1) {
        auto result=fetch_asset_https(release_asset_url("1.1.0-test.1","KASA-Setup-1.1.0-test.1.exe"),
            16*1024*1024,cancel,[](auto){ return true; });
        std::cout<<"HTTP "<<result.http_status<<", bytes "<<result.received<<", error "
            <<static_cast<int>(result.error)<<", system "<<result.system_error<<'\n';
        return result ? 0:1; // Live read-only smoke: bytes discarded, never saved/executed.
    }
    int checks=0,failures=0;
    const auto check=[&](bool ok,const char* label){ ++checks; if(!ok){++failures;std::cerr<<label<<'\n';} };
    check(!release_asset_url("1.1.0-test.3","KASA-update.json").empty(),"metadata URL");
    check(!release_asset_url("1.1.0-test.3","KASA-update.sig").empty(),"signature URL");
    check(!release_asset_url("1.1.0-test.3","KASA-Setup-1.1.0-test.3.exe").empty(),"installer URL");
    check(release_asset_url("v1.1.0-test.3","KASA-update.sig").empty(),"noncanonical version");
    check(release_asset_url("../1.0.0","KASA-update.sig").empty(),"version traversal");
    check(release_asset_url("1.0.0","../a.exe").empty(),"asset traversal");
    check(release_asset_url("1.0.0","KASA-Setup-2.0.0.exe").empty(),"different version asset");
    check(release_asset_url("1.0.0","a.exe?x=1").empty(),"arbitrary asset");
    check(allowed_asset_redirect(L"https://release-assets.githubusercontent.com/github-production-release-asset/123/abc?sig=x"),"GitHub CDN");
    for(const auto* url:{L"http://release-assets.githubusercontent.com/github-production-release-asset/a",
        L"https://release-assets.githubusercontent.com.evil.invalid/github-production-release-asset/a",
        L"https://evil.invalid/github-production-release-asset/a", L"https://127.0.0.1/github-production-release-asset/a",
        L"https://release-assets.githubusercontent.com:444/github-production-release-asset/a",
        L"https://user:pass@release-assets.githubusercontent.com/github-production-release-asset/a",
        L"https://release-assets.githubusercontent.com/other/a", L"https://release-assets.githubusercontent.com/github-production-release-asset/a#x",
        L"https://release-assets.githubusercontent.com\\@evil.invalid/github-production-release-asset/a"})
        check(!allowed_asset_redirect(url),"denied redirect");
    check(fetch_asset_https(L"https://evil.invalid/a",10,cancel,[](auto){return true;}).error==DownloadError::InvalidRequest,"deny initial host without network");
    auto url=release_asset_url("1.0.0","KASA-update.json");
    check(fetch_asset_https(url,0,cancel,[](auto){return true;}).error==DownloadError::InvalidRequest,"zero limit");
    cancel=true;
    check(fetch_asset_https(url,8192,cancel,[](auto){return true;}).error==DownloadError::Cancelled,"cancel before network");
    cancel=false;
    std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(EVP_PKEY_Q_keygen(nullptr,nullptr,"ED25519"),EVP_PKEY_free);
    std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(),EVP_MD_CTX_free);
    if(!key || !context) return 2;
    std::array<unsigned char,32> public_key{};std::size_t key_size=32;
    if(EVP_PKEY_get_raw_public_key(key.get(),public_key.data(),&key_size)!=1) return 2;
    nlohmann::json j={{"schema",1U},{"product","KASA"},{"platform","windows-x64"},{"version","1.1.0-test.3"},
        {"prerelease",true},{"asset","KASA-Setup-1.1.0-test.3.exe"},{"size",3U},
        {"sha256","ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},{"issued_at",1000U},{"expires_at",2000U}};
    const auto bytes=j.dump();std::array<unsigned char,64> signature{};std::size_t sig_size=64;
    if(EVP_DigestSignInit(context.get(),nullptr,nullptr,nullptr,key.get())!=1 ||
        EVP_DigestSign(context.get(),signature.data(),&sig_size,reinterpret_cast<const unsigned char*>(bytes.data()),bytes.size())!=1) return 2;
    const auto manifest=verify_manifest(bytes,signature,public_key,"1.1.0-test.2","v1.1.0-test.3",Channel::Test,1500);
    if(!manifest) return 2;
    const auto transport=[](std::string payload,DownloadError ending=DownloadError::None) -> DownloadTransport {
        return [payload,ending](auto,std::uint64_t,const auto&,const DownloadSink& sink) {
            for(unsigned char c:payload) if(!sink(std::span(&c,1))) return DownloadResult{DownloadError::SinkFailed};
            return DownloadResult{ending,200,0,payload.size()};
        };
    };
    std::string stored;
    const DownloadSink sink=[&](auto block){stored.append(reinterpret_cast<const char*>(block.data()),block.size());return true;};
    auto result=download_verified_payload(*manifest,cancel,sink,transport("abc"));
    check(result && result.received==3 && stored=="abc","chunked verified payload");
    stored.clear(); result=download_verified_payload(*manifest,cancel,sink,transport("abcd"));
    check(result.error==DownloadError::TooLarge && stored=="abc","reject excess before sink");
    check(download_verified_payload(*manifest,cancel,sink,transport("ab")).error==DownloadError::SizeMismatch,"short download");
    check(download_verified_payload(*manifest,cancel,sink,transport("abd")).error==DownloadError::HashMismatch,"tampered download");
    check(download_verified_payload(*manifest,cancel,sink,transport("",DownloadError::Network)).error==DownloadError::Network,"network error");
    check(download_verified_payload(*manifest,cancel,[](auto){return false;},transport("abc")).error==DownloadError::SinkFailed,"disk failure");
    check(download_verified_payload(*manifest,cancel,[](auto)->bool{throw std::runtime_error("disk");},transport("abc")).error==DownloadError::SinkFailed,"sink exception");
    const DownloadSink cancelling=[&](auto){cancel=true;return true;};
    check(download_verified_payload(*manifest,cancel,cancelling,transport("abc")).error==DownloadError::Cancelled,"cancel during chunks");
    check(download_verified_payload(*manifest,cancel,sink,transport("abc")).error==DownloadError::Cancelled,"cancelled start");
    cancel=false;
    check(download_verified_payload(*manifest,cancel,{},transport("abc")).error==DownloadError::InvalidRequest,"missing sink");
    check(download_verified_payload(*manifest,cancel,sink,{}).error==DownloadError::InvalidRequest,"missing transport");
    std::cout<<checks<<" checks, "<<failures<<" failures\n";
    return failures!=0;
}
