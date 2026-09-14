#pragma once
#include "encryption_engine.h"
#include "preview_policy.h"

namespace kasa::preview {
enum class ImageStatus { Ready, InvalidInput, Unsupported, TooLarge, InvalidImage, DecoderUnavailable };
class ImagePreview {
    std::vector<unsigned char> pixels_;
    std::uint32_t width_ = 0, height_ = 0;
    ImagePreview() = default;
public:
    ImagePreview(const ImagePreview&) = delete;
    ImagePreview& operator=(const ImagePreview&) = delete;
    ~ImagePreview();
    // No arbitrary byte API: only authenticated plaintext can reach the decoder.
    static std::unique_ptr<ImagePreview> create(std::unique_ptr<AuthenticatedPreview> owner,
                                               Kind expected, ImageStatus& status) noexcept;
    std::span<const unsigned char> pixels() const noexcept { return pixels_; }
    std::uint32_t width() const noexcept { return width_; }
    std::uint32_t height() const noexcept { return height_; }
};
}
