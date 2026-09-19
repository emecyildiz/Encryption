#include "update_manifest.h"
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <memory>
#include <sstream>
#include <iostream>
#include <vector>

int main() {
    using namespace kasa::updates;
    using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    // Ephemeral test-only keys: never written to disk or used as a release trust root.
    Key key(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"), EVP_PKEY_free);
    Key other(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"), EVP_PKEY_free);
    if (!key || !other) return 2;
    std::array<unsigned char,32> public_key{}, other_public{};
    std::size_t length = 32;
    if (EVP_PKEY_get_raw_public_key(key.get(), public_key.data(), &length) != 1) return 2;
    length = 32;
    if (EVP_PKEY_get_raw_public_key(other.get(), other_public.data(), &length) != 1) return 2;
    const auto sign = [&](std::string_view bytes) {
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> c(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        std::vector<unsigned char> signature(64);
        std::size_t size = signature.size();
        if (!c || EVP_DigestSignInit(c.get(), nullptr, nullptr, nullptr, key.get()) != 1 ||
            EVP_DigestSign(c.get(), signature.data(), &size,
                reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()) != 1 || size != 64)
            throw std::runtime_error("test signing failed");
        return signature;
    };
    int checks=0, failures=0;
    const auto check=[&](bool pass, const char* label) { ++checks; if(!pass) { ++failures; std::cerr << label << '\n'; } };
    nlohmann::json base = {{"schema",1U},{"product","KASA"},{"platform","windows-x64"},
        {"version","1.1.0-test.3"},{"prerelease",true},{"asset","KASA-Setup-1.1.0-test.3.exe"},
        {"size",3U},{"sha256","ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"issued_at",1000U},{"expires_at",2000U}};
    const auto validate = [&](const nlohmann::json& j) {
        const auto bytes=j.dump(); return verify_manifest(bytes, sign(bytes), public_key,
            "1.1.0-test.2", "v1.1.0-test.3", Channel::Test, 1500);
    };
    auto trusted=validate(base); check(trusted.has_value(), "valid signed manifest");
    if(!trusted) return 1;
    std::istringstream good("abc"), bad("abd"), short_input("ab"), long_input("abcd"), empty("");
    check(verify_payload(good,*trusted),"correct payload");
    check(!verify_payload(bad,*trusted),"modified payload");
    check(!verify_payload(short_input,*trusted),"truncated payload");
    check(!verify_payload(long_input,*trusted),"appended payload");
    check(!verify_payload(empty,*trusted),"empty payload");
    const auto bytes=base.dump(); const auto signature=sign(bytes);
    check(!verify_manifest(bytes,signature,other_public,"1.1.0-test.2","v1.1.0-test.3",Channel::Test,1500),"wrong publisher key");
    auto broken=signature; broken[0]^=1;
    check(!verify_manifest(bytes,broken,public_key,"1.1.0-test.2","v1.1.0-test.3",Channel::Test,1500),"bad signature");
    check(!verify_manifest(bytes+" ",signature,public_key,"1.1.0-test.2","v1.1.0-test.3",Channel::Test,1500),"exact bytes covered");
    check(!verify_manifest(bytes,std::span(signature).first(63),public_key,"1.1.0-test.2","v1.1.0-test.3",Channel::Test,1500),"short signature");
    check(!verify_manifest(bytes,signature,std::span(public_key).first(31),"1.1.0-test.2","v1.1.0-test.3",Channel::Test,1500),"short key");
    check(!verify_manifest(bytes,signature,public_key,"1.1.0-test.2","v1.1.0-test.4",Channel::Test,1500),"release substitution");
    check(!verify_manifest(bytes,signature,public_key,"1.1.0-test.2","v1.1.0-test.3",Channel::Stable,1500),"test on stable channel");
    check(!verify_manifest(bytes,signature,public_key,"1.1.0-test.3","v1.1.0-test.3",Channel::Test,1500),"same version");
    check(!verify_manifest(bytes,signature,public_key,"2.0.0","v1.1.0-test.3",Channel::Test,1500),"downgrade");
    check(!verify_manifest(bytes,signature,public_key,"1.1.0-test.2","v1.1.0-test.3",Channel::Test,2000),"expired boundary");
    check(!verify_manifest(bytes,signature,public_key,"1.1.0-test.2","v1.1.0-test.3",Channel::Test,699),"future timestamp");
    check(verify_manifest(bytes,signature,public_key,"1.1.0-test.2","v1.1.0-test.3",Channel::Test,700).has_value(),"clock tolerance boundary");
    const auto change=[&](const char* field, nlohmann::json value) { auto j=base; j[field]=value; check(!validate(j),field); };
    change("schema",2U); change("product","CTI"); change("platform","linux-x64");
    change("asset","../KASA.exe"); change("asset","https://evil.invalid/a.exe");
    change("size",0U); change("size",268435457ULL); change("size",-1); change("size",3.0);
    change("sha256",std::string(64,'z')); change("sha256",std::string(63,'a'));
    change("prerelease",false); change("prerelease","true"); change("version","v1.1.0-test.3");
    change("expires_at",1000U); change("expires_at",2593001U); change("issued_at",-1);
    change("unknown",true); change("size",nlohmann::json::array());
    auto missing=base; missing.erase("sha256"); check(!validate(missing),"missing hash");
    const auto duplicate=bytes.substr(0,bytes.size()-1)+",\"size\":3}";
    check(!verify_manifest(duplicate,sign(duplicate),public_key,"1.1.0-test.2","v1.1.0-test.3",Channel::Test,1500),"duplicate JSON key");
    const std::string oversized(8193,' ');
    check(!verify_manifest(oversized,sign(oversized),public_key,"1.1.0-test.2","v1.1.0-test.3",Channel::Test,1500),"oversized metadata");
    check(!verify_manifest("invalid",sign("invalid"),public_key,"1.1.0-test.2","v1.1.0-test.3",Channel::Test,1500),"signed malformed JSON");
    std::cout << checks << " checks, " << failures << " failures\n";
    return failures != 0;
}
