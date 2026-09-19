#pragma once
#include <openssl/evp.h>
#include <array>
#include <istream>
#include <string>
#include <cstdint>

namespace kasa::updates {
struct SignedRelease {
    std::string descriptor;
    std::array<unsigned char,64> signature{};
    std::array<unsigned char,32> public_key{};
};
// Publisher-only function; no key generation, persistence, or network side effects.
SignedRelease sign_release(EVP_PKEY* key, std::istream& payload,
    const std::string& version, std::uint64_t issued, std::uint64_t lifetime);
}
