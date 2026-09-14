#include "preview_text.h"

namespace kasa::preview {
TextValidation validate_text(std::span<const unsigned char> bytes) noexcept {
    if (bytes.size() > max_text_bytes) return {TextStatus::TooLarge};
    std::size_t start = 0;
    if (bytes.size() >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf) start=3;
    std::size_t line_start=start, line_count=1;
    for (std::size_t i=start; i<bytes.size();) {
        const auto codepoint_start=i;
        const auto first=bytes[i++];
        std::uint32_t cp=0, minimum=0;
        std::size_t tail=0;
        if (first<0x80) cp=first;
        else if (first>=0xc2 && first<=0xdf) {cp=first&0x1f;tail=1;minimum=0x80;}
        else if (first>=0xe0 && first<=0xef) {cp=first&0x0f;tail=2;minimum=0x800;}
        else if (first>=0xf0 && first<=0xf4) {cp=first&0x07;tail=3;minimum=0x10000;}
        else return {TextStatus::InvalidUtf8};
        if (tail>bytes.size()-i) return {TextStatus::InvalidUtf8};
        for(std::size_t j=0;j<tail;++j) {
            const auto next=bytes[i++];
            if ((next&0xc0)!=0x80) return {TextStatus::InvalidUtf8};
            cp=(cp<<6)|(next&0x3f);
        }
        if (cp<minimum || cp>0x10ffff || (cp>=0xd800 && cp<=0xdfff))
            return {TextStatus::InvalidUtf8};
        // Plain text, not terminal/markup execution. Reject binary controls and
        // explicit bidi formatting controls rather than silently changing text.
        if ((cp<0x20 && cp!=9 && cp!=10 && cp!=13) || (cp>=0x7f && cp<=0x9f)
            || cp==0x061c || cp==0x200e || cp==0x200f
            || (cp>=0x202a && cp<=0x202e) || (cp>=0x2066 && cp<=0x2069)
            || cp==0xfeff || (cp>=0xfdd0 && cp<=0xfdef) || (cp&0xffff)>=0xfffe)
            return {TextStatus::UnsupportedControl};
        if(cp==10) {
            // CR belongs to CRLF, not to the displayed line content.
            auto end=codepoint_start;
            if(end>line_start && bytes[end-1]==13)--end;
            if(end-line_start>max_line_bytes || ++line_count>max_text_lines)
                return {TextStatus::LayoutLimit};
            line_start=i;
        } else if (i-line_start>max_line_bytes && !(cp==13 && i-line_start==max_line_bytes+1)) {
            return {TextStatus::LayoutLimit};
        }
    }
    auto end=bytes.size();
    if(end>line_start && bytes[end-1]==13)--end;
    if(end-line_start>max_line_bytes)return {TextStatus::LayoutLimit};
    return {TextStatus::Ready,start};
}

std::unique_ptr<TextPreview> TextPreview::create(
    std::unique_ptr<AuthenticatedPreview> owner, TextStatus& status) {
    if (!owner) {status=TextStatus::InvalidUtf8;return nullptr;}
    const auto validation=validate_text(owner->bytes());
    status=validation.status;
    if (status!=TextStatus::Ready) return nullptr;
    return std::unique_ptr<TextPreview>(new TextPreview(std::move(owner),validation));
}
}
