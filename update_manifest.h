#pragma once
#include "update_policy.h"
#include <array>
#include <cstdint>
#include <istream>
#include <optional>
#include <span>
#include <string>

namespace kasa::updates {
// Only verify_manifest may create a trusted descriptor. No network-provided key is accepted.
class VerifiedManifest {
public:
    const std::string& version() const { return version_; }
    const std::string& asset() const { return asset_; }
    std::uint64_t size() const { return size_; }
    std::uint64_t expires_at() const { return expires_; }
    bool current_at(std::uint64_t now) const {
        return now < expires_ && (issued_ <= now || issued_ - now <= 300);
    }
    const std::array<unsigned char, 32>& sha256() const { return sha256_; }
private:
    VerifiedManifest() = default;
    std::string version_, asset_;
    std::uint64_t size_ = 0;
    std::uint64_t issued_ = 0, expires_ = 0;
    std::array<unsigned char, 32> sha256_{};
    friend std::optional<VerifiedManifest> verify_manifest(std::string_view,
        std::span<const unsigned char>, std::span<const unsigned char>,
        std::string_view, std::string_view, Channel, std::uint64_t);
};

// Detached Ed25519 signature over the exact UTF-8 bytes, not reserialized JSON.
// trusted_public_key must come from the application's pinned trust store.
std::optional<VerifiedManifest> verify_manifest(std::string_view bytes,
    std::span<const unsigned char> signature, std::span<const unsigned char> trusted_public_key,
    std::string_view installed, std::string_view expected_release, Channel channel,
    std::uint64_t now_unix);

// Streaming check only: it never opens or executes files. A later installer handoff
// must keep the verified file protected from replacement until process creation.
bool verify_payload(std::istream& input, const VerifiedManifest& manifest);
}
