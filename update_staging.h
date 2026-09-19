#pragma once
#include "update_download.h"
#include <filesystem>
#include <memory>

namespace kasa::updates {
struct StageResult;
class StagedUpdate {
public:
    ~StagedUpdate();
    StagedUpdate(const StagedUpdate&) = delete;
    StagedUpdate& operator=(const StagedUpdate&) = delete;
    const std::filesystem::path& path() const;
    bool discard(); // Reports best-effort cleanup; never recursively removes unknown files.
    // Rechecks expiry and local bytes under the retained read lock. Does not execute.
    bool may_handoff(bool approved, bool processing, bool pending_outputs, std::uint64_t now);
    // Starts the bundled helper with an explicit inherited-handle allowlist.
    // Caller must exit only after success; helper waits for this process to exit.
    bool launch_helper(const std::filesystem::path& helper, std::uint64_t now, unsigned long& error);
private:
    struct State;
    std::unique_ptr<State> state_;
    explicit StagedUpdate(std::unique_ptr<State>);
    friend struct StageResult;
    friend StageResult stage_update(const VerifiedManifest&,const std::atomic<bool>&,
        const std::filesystem::path&,const DownloadTransport&);
};
struct StageResult {
    std::unique_ptr<StagedUpdate> package;
    DownloadResult download;
    std::string error;
    explicit operator bool() const { return package != nullptr; }
};
// Caller supplies an existing local staging root. Existing files are never overwritten.
StageResult stage_update(const VerifiedManifest&,const std::atomic<bool>&,
    const std::filesystem::path& root, const DownloadTransport& transport=fetch_asset_https);
// Full preparation: bounded metadata + signature -> trusted manifest -> locked package.
StageResult prepare_update(std::string_view installed,std::string_view release,Channel channel,
    std::span<const unsigned char> pinned_key,std::uint64_t now,const std::atomic<bool>& cancel,
    const std::filesystem::path& root,const DownloadTransport& transport=fetch_asset_https);
}
