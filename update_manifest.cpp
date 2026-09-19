#include "update_manifest.h"
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <memory>
#include <set>
#include <stdexcept>
#include <algorithm>

namespace kasa::updates {
namespace {
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
constexpr std::uint64_t max_package_size = 256ULL * 1024 * 1024;
constexpr std::uint64_t max_lifetime = 30ULL * 24 * 60 * 60;
}
std::optional<VerifiedManifest> verify_manifest(std::string_view bytes,
    std::span<const unsigned char> signature, std::span<const unsigned char> trusted_public_key,
    std::string_view installed, std::string_view expected_release, Channel channel,
    std::uint64_t now_unix) {
    if (bytes.empty() || bytes.size() > 8192 || signature.size() != 64 || trusted_public_key.size() != 32)
        return std::nullopt;
    Key key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
        trusted_public_key.data(), trusted_public_key.size()), EVP_PKEY_free);
    Context context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!key || !context || EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, key.get()) != 1 ||
        EVP_DigestVerify(context.get(), signature.data(), signature.size(),
            reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()) != 1) return std::nullopt;
    try {
        std::set<std::string> keys;
        auto j = nlohmann::json::parse(bytes, [&keys](int depth, auto event, auto& value) {
            if (depth > 2) throw std::runtime_error("depth");
            if (event == nlohmann::json::parse_event_t::key &&
                !keys.insert(value.template get<std::string>()).second) throw std::runtime_error("duplicate key");
            return true;
        });
        if (!j.is_object() || j.size() != 10) return std::nullopt;
        for (const auto* field : {"product", "platform", "version", "asset", "sha256"})
            if (!j.contains(field) || !j[field].is_string()) return std::nullopt;
        for (const auto* field : {"schema", "size", "issued_at", "expires_at"})
            if (!j.contains(field) || !j[field].is_number_unsigned()) return std::nullopt;
        if (!j.contains("prerelease") || !j["prerelease"].is_boolean() || j["schema"] != 1 ||
            j["product"] != "KASA" || j["platform"] != "windows-x64") return std::nullopt;
        VerifiedManifest result;
        result.version_ = j["version"].get<std::string>();
        if (result.version_.empty() || result.version_.front() == 'v') return std::nullopt;
        std::string_view expected = expected_release;
        if (expected.starts_with('v')) expected.remove_prefix(1);
        if (result.version_ != expected || evaluate(installed, result.version_, channel, false,
            j["prerelease"].get<bool>()) != Decision::Offer) return std::nullopt;
        result.asset_ = j["asset"].get<std::string>();
        if (result.asset_ != "KASA-Setup-" + result.version_ + ".exe") return std::nullopt;
        result.size_ = j["size"].get<std::uint64_t>();
        if (!result.size_ || result.size_ > max_package_size) return std::nullopt;
        const auto issued = j["issued_at"].get<std::uint64_t>();
        const auto expires = j["expires_at"].get<std::uint64_t>();
        if (expires <= issued || expires - issued > max_lifetime || now_unix >= expires ||
            (issued > now_unix && issued - now_unix > 300)) return std::nullopt;
        result.issued_ = issued;
        result.expires_ = expires;
        const auto hash = j["sha256"].get<std::string>();
        if (hash.size() != 64) return std::nullopt;
        const auto digit = [](char c) -> int { return c >= '0' && c <= '9' ? c - '0' :
            (c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1); };
        for (std::size_t i = 0; i < 32; ++i) {
            const int high = digit(hash[i*2]), low = digit(hash[i*2+1]);
            if (high < 0 || low < 0) return std::nullopt;
            result.sha256_[i] = static_cast<unsigned char>(high * 16 + low);
        }
        return result;
    } catch (...) { return std::nullopt; }
}

bool verify_payload(std::istream& input, const VerifiedManifest& manifest) {
    Context context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) return false;
    std::array<char, 65536> buffer{};
    std::uint64_t total = 0;
    try {
        while (total < manifest.size()) {
            const auto count = static_cast<std::streamsize>(std::min<std::uint64_t>(buffer.size(), manifest.size() - total));
            input.read(buffer.data(), count);
            if (input.gcount() != count || !input ||
                EVP_DigestUpdate(context.get(), buffer.data(), static_cast<std::size_t>(count)) != 1) return false;
            total += static_cast<std::uint64_t>(count);
        }
        if (input.peek() != std::char_traits<char>::eof() || input.bad()) return false;
        std::array<unsigned char, 32> hash{};
        unsigned int length = 0;
        return EVP_DigestFinal_ex(context.get(), hash.data(), &length) == 1 && length == hash.size() &&
            CRYPTO_memcmp(hash.data(), manifest.sha256().data(), hash.size()) == 0;
    } catch (...) { return false; }
}
}
