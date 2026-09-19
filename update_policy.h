#pragma once
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>

namespace kasa::updates {
enum class Channel { Stable, Test };
struct Version {
    std::array<std::uint32_t, 3> core{};
    std::optional<std::uint32_t> test;
};

// Deliberately narrow release contract: [v]MAJOR.MINOR.PATCH[-test.NUMBER].
// Unsupported tags fail closed; this is not a general SemVer parser.
inline std::optional<Version> parse_version(std::string_view text) {
    if (text.empty() || text.size() > 80) return std::nullopt;
    if (text.front() == 'v') text.remove_prefix(1);
    const auto number = [&text](std::uint32_t& out) {
        std::size_t count = 0;
        std::uint32_t value = 0;
        while (count < text.size() && text[count] >= '0' && text[count] <= '9') {
            const auto digit = static_cast<std::uint32_t>(text[count] - '0');
            if (value > (std::numeric_limits<std::uint32_t>::max() - digit) / 10) return false;
            value = value * 10 + digit;
            ++count;
        }
        if (!count || (count > 1 && text.front() == '0')) return false;
        text.remove_prefix(count);
        out = value;
        return true;
    };
    Version result;
    for (std::size_t i = 0; i < result.core.size(); ++i) {
        if (!number(result.core[i])) return std::nullopt;
        if (i < 2) {
            if (text.empty() || text.front() != '.') return std::nullopt;
            text.remove_prefix(1);
        }
    }
    if (text.empty()) return result;
    if (!text.starts_with("-test.")) return std::nullopt;
    text.remove_prefix(6);
    std::uint32_t test = 0;
    if (!number(test) || !text.empty()) return std::nullopt;
    result.test = test;
    return result;
}

inline int compare(const Version& a, const Version& b) {
    if (a.core < b.core) return -1;
    if (a.core > b.core) return 1;
    if (!a.test && b.test) return 1;
    if (a.test && !b.test) return -1;
    if (a.test && b.test) return *a.test < *b.test ? -1 : (*a.test > *b.test ? 1 : 0);
    return 0;
}

enum class Decision { Invalid, Draft, ChannelExcluded, NotNewer, Offer };
inline Decision evaluate(std::string_view installed, std::string_view candidate,
                         Channel channel, bool draft, bool prerelease) {
    const auto current = parse_version(installed);
    const auto next = parse_version(candidate);
    if (!current || !next || next->test.has_value() != prerelease) return Decision::Invalid;
    if (draft) return Decision::Draft;
    if (channel != Channel::Stable && channel != Channel::Test) return Decision::Invalid;
    if (channel == Channel::Stable && prerelease) return Decision::ChannelExcluded;
    return compare(*next, *current) > 0 ? Decision::Offer : Decision::NotNewer;
}

// Offer is only version eligibility, never permission to execute a download.
// Callers must separately verify origin, package signature and integrity.
inline bool may_begin_install(bool user_approved, bool package_verified,
                              bool processing, bool pending_outputs) {
    return user_approved && package_verified && !processing && !pending_outputs;
}
}
