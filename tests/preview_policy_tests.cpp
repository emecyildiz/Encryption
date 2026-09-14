#include "preview_policy.h"
#include <iostream>
#include <limits>

int main() {
    using namespace kasa::preview;
    int failures = 0, checks = 0;
    auto check = [&](bool ok, const char* label) {
        ++checks;
        if (!ok) { ++failures; std::cerr << "FAIL: " << label << '\n'; }
    };
    check(kind_from_extension(L".TXT") == Kind::Text, "case insensitive text");
    check(kind_from_extension(L".JpEg") == Kind::Jpeg, "jpeg hint");
    check(kind_from_extension(L".png") == Kind::Png, "png hint");
    check(kind_from_extension(L".svg") == Kind::Unsupported, "no active markup renderer");
    check(kind_from_extension(L".exe") == Kind::Unsupported, "no executable launch");
    check(kind_from_extension(L"") == Kind::Unsupported, "unknown extension");
    check(evaluate(Kind::Text, 100, 0, true) == Gate::Ready, "empty authenticated text");
    check(evaluate(Kind::Png, 100, 50, false) == Gate::AuthenticationFailed, "authentication first");
    check(evaluate(Kind::Text, max_text_bytes+100, max_text_bytes, true) == Gate::Ready, "text boundary");
    check(evaluate(Kind::Text, max_text_bytes+101, max_text_bytes+1, true) == Gate::TooLarge, "text overflow");
    check(evaluate(Kind::Png, max_encrypted_bytes+1, 1, true) == Gate::TooLarge, "input cap");
    check(evaluate(Kind::Png, 100, max_encrypted_bytes+1, true) == Gate::TooLarge, "plaintext cap");
    check(image_dimensions_allowed(5000, 4000), "pixel boundary");
    check(!image_dimensions_allowed(5001, 4000), "pixel overflow");
    check(!image_dimensions_allowed(0, 100), "zero dimension");
    check(!image_dimensions_allowed(16385, 1), "dimension cap");
    check(!image_dimensions_allowed(std::numeric_limits<std::uint32_t>::max(),
                                    std::numeric_limits<std::uint32_t>::max()), "integer overflow defense");
    check(evaluate(Kind::Unsupported, 100, 1, true) == Gate::Unsupported, "unsupported gate");
    std::cout << checks << " preview policy checks; " << failures << " failures.\n";
    return failures ? 1 : 0;
}
