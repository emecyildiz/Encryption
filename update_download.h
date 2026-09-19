#pragma once
#include "update_manifest.h"
#include <atomic>
#include <functional>
#include <span>
#include <string>

namespace kasa::updates {
enum class DownloadError { None, InvalidRequest, Cancelled, Timeout, Network, HttpStatus,
    RedirectDenied, TooLarge, SinkFailed, SizeMismatch, HashMismatch };
struct DownloadResult {
    DownloadError error = DownloadError::None;
    unsigned long http_status = 0;
    unsigned long system_error = 0;
    std::uint64_t received = 0;
    explicit operator bool() const { return error == DownloadError::None; }
};
using DownloadSink = std::function<bool(std::span<const unsigned char>)>;
using DownloadTransport = std::function<DownloadResult(std::wstring_view, std::uint64_t,
    const std::atomic<bool>&, const DownloadSink&)>;

std::wstring release_asset_url(std::string_view version, std::string_view asset);
bool allowed_asset_redirect(std::wstring_view url);
DownloadResult fetch_asset_https(std::wstring_view url, std::uint64_t max_bytes,
    const std::atomic<bool>& cancel, const DownloadSink& sink);

// Streams into a staging sink. Bytes remain untrusted until success. The caller
// must delete/abandon partial staging on ANY failure; this function never executes.
DownloadResult download_verified_payload(const VerifiedManifest& manifest,
    const std::atomic<bool>& cancel, const DownloadSink& staging_sink,
    const DownloadTransport& transport = fetch_asset_https);
}
