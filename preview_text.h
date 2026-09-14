#pragma once
#include "encryption_engine.h"
#include "preview_policy.h"

namespace kasa::preview {
enum class TextStatus { Ready, TooLarge, InvalidUtf8, UnsupportedControl, LayoutLimit };
inline constexpr std::size_t max_line_bytes = 16 * 1024;
inline constexpr std::size_t max_text_lines = 50000;
struct TextValidation {
    TextStatus status;
    std::size_t offset = 0; // Optional UTF-8 BOM skipped, never a copied string.
};
[[nodiscard]] TextValidation validate_text(std::span<const unsigned char> bytes) noexcept;

class TextPreview {
    std::unique_ptr<AuthenticatedPreview> owner_;
    TextValidation validation_;
    explicit TextPreview(std::unique_ptr<AuthenticatedPreview> owner, TextValidation validation)
        : owner_(std::move(owner)), validation_(validation) {}
public:
    TextPreview(const TextPreview&) = delete;
    TextPreview& operator=(const TextPreview&) = delete;
    // Accepts only an authenticated owner. On failure the plaintext is wiped.
    [[nodiscard]] static std::unique_ptr<TextPreview> create(
        std::unique_ptr<AuthenticatedPreview> owner, TextStatus& status);
    [[nodiscard]] std::span<const unsigned char> bytes() const noexcept {
        return owner_->bytes().subspan(validation_.offset);
    }
};
inline constexpr const char* invalid_text_notice =
    "This file is not supported UTF-8 plain text or contains unsupported control characters. "
    "Nothing was saved. You can choose Decrypt and save separately.";
inline constexpr const char* text_layout_notice =
    "This text exceeds the preview layout limits (16 KiB per line or 50,000 lines). "
    "The text was not truncated and nothing was saved. Use Decrypt and save in KASA to read the full file.";
}
