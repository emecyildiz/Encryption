#include "update_check.h"
#include "update_metadata.h"
#include <windows.h>
#include <winhttp.h>
#include <chrono>
#include <array>

namespace kasa::updates {
namespace {
struct Handle { HINTERNET value; ~Handle() { if (value) WinHttpCloseHandle(value); } };
CheckResult fetch(Channel channel, const std::atomic<bool>& cancel) {
    const auto failure = [](const char* message) { return CheckResult{false, {}, message}; };
    Handle session{WinHttpOpen(L"KASA-UpdateCheck/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)};
    if (!session.value || !WinHttpSetTimeouts(session.value, 4000, 4000, 4000, 4000))
        return failure("Update check could not start.");
    Handle connection{WinHttpConnect(session.value, L"api.github.com", INTERNET_DEFAULT_HTTPS_PORT, 0)};
    if (!connection.value) return failure("Could not connect to GitHub.");
    Handle request{WinHttpOpenRequest(connection.value, L"GET",
        L"/repos/emecyildiz/Encryption/releases?per_page=100", nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE)};
    if (!request.value) return failure("Could not create update request.");
    DWORD disabled = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
    if (!WinHttpSetOption(request.value, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled)))
        return failure("Secure update request configuration failed.");
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    if (cancel || !WinHttpSendRequest(request.value,
        L"Accept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n", -1L,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0) || !WinHttpReceiveResponse(request.value, nullptr))
        return failure("GitHub is unreachable or TLS validation failed. Local file operations are unaffected.");
    DWORD status = 0, size = sizeof(status);
    if (!WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX) || status != 200)
        return failure(status == 403 || status == 429 ? "GitHub rate limit or access restriction. Try later." : "GitHub returned an unexpected HTTP status.");
    std::string body;
    std::array<char, 8192> buffer{};
    for (;;) {
        if (cancel || std::chrono::steady_clock::now() > deadline) return failure("Update check cancelled or timed out.");
        DWORD read = 0;
        if (!WinHttpReadData(request.value, buffer.data(), static_cast<DWORD>(buffer.size()), &read))
            return failure("Update response could not be read.");
        if (!read) break;
        if (body.size() + read > 1024 * 1024) return failure("Update response exceeds the safety limit.");
        body.append(buffer.data(), read);
    }
    return parse_releases(body, KASA_RELEASE_VERSION, channel);
}
}
UpdateCheck::~UpdateCheck() { cancel_ = true; if (worker_.joinable()) worker_.join(); }
CheckState UpdateCheck::state() const { std::lock_guard lock(mutex_); return state_; }
void UpdateCheck::reset() { std::lock_guard lock(mutex_); if (!state_.busy) state_ = {}; }
bool UpdateCheck::start(Channel channel) {
    if (channel != Channel::Stable && channel != Channel::Test) return false;
    { std::lock_guard lock(mutex_); if (state_.busy) return false; }
    if (worker_.joinable()) worker_.join();
    cancel_ = false;
    { std::lock_guard lock(mutex_); state_ = {true, false, {}, "Checking GitHub releases..."}; }
    try {
        worker_ = std::thread([this, channel] {
            CheckResult result;
            try { result = fetch(channel, cancel_); }
            catch (...) { result = {false, {}, "Update check failed safely. Try later."}; }
            std::lock_guard lock(mutex_);
            state_ = {false, result.ok && !result.version.empty(), result.version, result.message};
        });
    } catch (...) { std::lock_guard lock(mutex_); state_ = {false, false, {}, "Could not start background update check."}; return false; }
    return true;
}
}
