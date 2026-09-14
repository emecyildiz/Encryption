#pragma once

#include <cstdint>
#include <string_view>

namespace kasa::preview {
enum class Kind { Unsupported, Text, Png, Jpeg };
inline constexpr std::uint64_t max_encrypted_bytes = 64ULL * 1024 * 1024;
inline constexpr std::uint64_t max_text_bytes = 2ULL * 1024 * 1024;
inline constexpr std::uint64_t max_pixels = 20ULL * 1000 * 1000;
inline constexpr std::uint32_t max_dimension = 16384;

// Extension is a routing hint, never proof of content type. Callers must verify
// authentication before signature checks, text decoding, or image decoding.
inline Kind kind_from_extension(std::wstring_view ext) {
    auto equal = [ext](std::wstring_view expected) {
        if (ext.size() != expected.size()) return false;
        for (std::size_t i = 0; i < ext.size(); ++i) {
            wchar_t c = ext[i];
            if (c >= L'A' && c <= L'Z') c += L'a' - L'A';
            if (c != expected[i]) return false;
        }
        return true;
    };
    if (equal(L".txt")) return Kind::Text;
    if (equal(L".png")) return Kind::Png;
    if (equal(L".jpg") || equal(L".jpeg")) return Kind::Jpeg;
    return Kind::Unsupported;
}

inline bool image_dimensions_allowed(std::uint32_t width, std::uint32_t height) {
    return width > 0 && height > 0 && width <= max_dimension && height <= max_dimension
        && static_cast<std::uint64_t>(width) * height <= max_pixels;
}

enum class Gate { Ready, Unsupported, TooLarge, AuthenticationFailed };
inline Gate evaluate(Kind kind, std::uint64_t encrypted_bytes,
                     std::uint64_t plaintext_bytes, bool authenticated) {
    if (!authenticated) return Gate::AuthenticationFailed;
    if (kind == Kind::Unsupported) return Gate::Unsupported;
    if (encrypted_bytes > max_encrypted_bytes || plaintext_bytes > max_encrypted_bytes
        || (kind == Kind::Text && plaintext_bytes > max_text_bytes)) return Gate::TooLarge;
    return Gate::Ready;
}

inline constexpr const char* password_notice =
    "Read-only preview does not modify the encrypted file.";
inline constexpr const char* privacy_notice =
    "KASA does not save a decrypted preview file. Windows or other software may still retain traces.";
inline constexpr const char* export_notice =
    "Decrypt and save creates an unencrypted file on disk.";
inline constexpr const char* authentication_error =
    "The password may be incorrect or the file may be damaged. Nothing was opened.";
inline constexpr const char* unsupported_notice =
    "Preview supports PNG, JPEG and UTF-8 plain text only. Decrypt and save is available separately.";
inline constexpr const char* size_notice =
    "This file exceeds the preview limits. No unencrypted file was saved.";
}
