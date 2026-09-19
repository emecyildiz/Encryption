#include "update_publisher.h"
#include "update_policy.h"
#include <nlohmann/json.hpp>
#include <memory>
#include <limits>
#include <stdexcept>

namespace kasa::updates {
SignedRelease sign_release(EVP_PKEY* key,std::istream& input,const std::string& version,
    std::uint64_t issued,std::uint64_t lifetime) {
    const auto parsed=parse_version(version);
    if(!parsed || version.starts_with('v') || !key || EVP_PKEY_is_a(key,"ED25519")!=1 ||
        lifetime==0 || lifetime>30ULL*86400 || issued>std::numeric_limits<std::uint64_t>::max()-lifetime)
        throw std::runtime_error("Invalid publisher key, canonical version, or lifetime.");
    using Context=std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)>;
    Context hash(EVP_MD_CTX_new(),EVP_MD_CTX_free);
    if(!hash || EVP_DigestInit_ex(hash.get(),EVP_sha256(),nullptr)!=1)throw std::runtime_error("Hash initialization failed.");
    std::array<char,65536> buffer{};std::uint64_t total=0;
    while(input) {
        input.read(buffer.data(),buffer.size());const auto count=input.gcount();
        if(count<0 || static_cast<std::uint64_t>(count)>268435456ULL-total)throw std::runtime_error("Installer exceeds size limit.");
        if(count && EVP_DigestUpdate(hash.get(),buffer.data(),static_cast<std::size_t>(count))!=1)throw std::runtime_error("Hash failed.");
        total+=static_cast<std::uint64_t>(count);
    }
    if(!input.eof() || input.bad() || !total)throw std::runtime_error("Empty or unreadable installer.");
    std::array<unsigned char,32> digest{};unsigned int count=0;
    if(EVP_DigestFinal_ex(hash.get(),digest.data(),&count)!=1 || count!=32)throw std::runtime_error("Hash failed.");
    constexpr char hex[]="0123456789abcdef";std::string encoded;
    for(auto b:digest){encoded+=hex[b>>4];encoded+=hex[b&15];}
    SignedRelease result;
    result.descriptor=nlohmann::json{{"schema",1U},{"product","KASA"},{"platform","windows-x64"},
        {"version",version},{"prerelease",parsed->test.has_value()},{"asset","KASA-Setup-"+version+".exe"},
        {"size",total},{"sha256",encoded},{"issued_at",issued},{"expires_at",issued+lifetime}}.dump();
    std::size_t size=result.public_key.size();
    if(EVP_PKEY_get_raw_public_key(key,result.public_key.data(),&size)!=1 || size!=32)throw std::runtime_error("Public key unavailable.");
    Context signer(EVP_MD_CTX_new(),EVP_MD_CTX_free);size=result.signature.size();
    if(!signer || EVP_DigestSignInit(signer.get(),nullptr,nullptr,nullptr,key)!=1 ||
        EVP_DigestSign(signer.get(),result.signature.data(),&size,
            reinterpret_cast<const unsigned char*>(result.descriptor.data()),result.descriptor.size())!=1 || size!=64)
        throw std::runtime_error("Signing failed.");
    return result;
}
}
