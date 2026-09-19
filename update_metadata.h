#pragma once
#include "update_policy.h"
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>

namespace kasa::updates {
struct CheckResult { bool ok = false; std::string version; std::string message; };
inline CheckResult parse_releases(std::string_view body, std::string_view installed, Channel channel) {
    if (body.size() > 1024 * 1024 || !parse_version(installed) ||
        (channel != Channel::Stable && channel != Channel::Test))
        return {false, {}, "Invalid release response or installed version."};
    try {
        auto data = nlohmann::json::parse(body, [](int depth, auto, auto&) {
            if (depth > 24) throw std::runtime_error("depth");
            return true;
        });
        if (!data.is_array() || data.size() > 100) throw std::runtime_error("shape");
        std::string best;
        for (const auto& release : data) {
            if (!release.is_object() || !release.contains("tag_name") ||
                !release["tag_name"].is_string() || !release.contains("draft") ||
                !release["draft"].is_boolean() || !release.contains("prerelease") ||
                !release["prerelease"].is_boolean()) throw std::runtime_error("fields");
            const auto tag = release["tag_name"].get<std::string>();
            if (evaluate(installed, tag, channel, release["draft"].get<bool>(),
                         release["prerelease"].get<bool>()) != Decision::Offer) continue;
            if (best.empty() || compare(*parse_version(tag), *parse_version(best)) > 0) best = tag;
        }
        return {true, best, best.empty() ? "No newer compatible release found." : "A newer release is available."};
    } catch (...) { return {false, {}, "Release metadata could not be validated. Try again later."}; }
}
}
