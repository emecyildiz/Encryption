#include "update_policy.h"
#include <iostream>
#include <string>
using namespace kasa::updates;

int main() {
    int count = 0, failures = 0;
    const auto check = [&](bool ok, const char* label) {
        ++count;
        if (!ok) { ++failures; std::cerr << "FAIL: " << label << '\n'; }
    };
    for (auto valid : {"0.0.0", "v1.1.0", "1.1.0-test.1", "v1.1.0-test.10",
                       "4294967295.0.0", "1.0.0-test.0"})
        check(parse_version(valid).has_value(), valid);
    for (auto invalid : {"", "v", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.03",
                         "1.2.3-test.01", "1.2.3-test.", "1.2.3-test.-1", "1.2.3-rc.1",
                         "1.2.3+metadata", " 1.2.3", "1.2.3\n", "1.2.3-test.1.exe",
                         "4294967296.0.0", "1.0.0-test.4294967296", "V1.2.3", "1.2.-3"})
        check(!parse_version(invalid), invalid);
    check(!parse_version(std::string(81, '1')), "Oversized tag");
    check(!parse_version(std::string_view("1.2.3\0evil", 10)), "Embedded NUL");
    check(evaluate("1.1.0-test.1", "v1.1.0-test.2", Channel::Test, false, true) == Decision::Offer, "Test A to B");
    check(evaluate("1.1.0-test.2", "1.1.0-test.10", Channel::Test, false, true) == Decision::Offer, "Numeric test ordering");
    check(evaluate("1.9.0", "1.10.0", Channel::Stable, false, false) == Decision::Offer, "Numeric minor ordering");
    check(evaluate("1.1.0-test.2", "1.1.0", Channel::Test, false, false) == Decision::Offer, "Final supersedes test");
    check(evaluate("1.1.0", "1.1.0-test.99", Channel::Test, false, true) == Decision::NotNewer, "No final-to-test downgrade");
    check(evaluate("1.1.0-test.1", "1.0.0", Channel::Stable, false, false) == Decision::NotNewer, "Older stable rejected");
    check(evaluate("1.1.0", "1.1.0", Channel::Stable, false, false) == Decision::NotNewer, "Equal rejected");
    check(evaluate("1.1.0", "1.2.0-test.1", Channel::Stable, false, true) == Decision::ChannelExcluded, "Stable excludes tests");
    check(evaluate("1.1.0", "1.2.0", Channel::Stable, true, false) == Decision::Draft, "Draft rejected");
    check(evaluate("1.1.0", "1.2.0-test.1", Channel::Test, false, false) == Decision::Invalid, "Mislabelled test rejected");
    check(evaluate("1.1.0", "1.2.0", Channel::Test, false, true) == Decision::Invalid, "Mislabelled stable rejected");
    check(evaluate("unknown", "1.2.0", Channel::Test, false, false) == Decision::Invalid, "Unknown installed version");
    for (int mask = 0; mask < 16; ++mask) {
        const bool approved = mask & 1, verified = mask & 2, busy = mask & 4, pending = mask & 8;
        check(may_begin_install(approved, verified, busy, pending) == (mask == 3), "Install gates");
    }
    std::cout << count << " checks, " << failures << " failures\n";
    return failures ? 1 : 0;
}
