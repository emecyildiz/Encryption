#pragma once
#include "update_staging.h"
#include <mutex>
#include <thread>

namespace kasa::updates {
enum class PreparePhase { Idle, Preparing, Ready, Failed, Cancelled, Transferred };
struct PreparationRequest {
    std::string installed, release;
    Channel channel = Channel::Stable;
    std::array<unsigned char,32> pinned_key{}; // Public key only, never a private signing key.
    std::uint64_t now = 0;
    std::filesystem::path root;
};
struct PreparationStatus {
    PreparePhase phase = PreparePhase::Idle;
    std::uint64_t received = 0, total = 0;
    std::string message = "No update is being prepared.";
    unsigned long http_status = 0, system_error = 0;
};
// start/reset/take_ready belong to one owner thread. snapshot/cancel are safe
// from other threads. Destruction requests cancellation and joins before cleanup.
class UpdatePreparation {
public:
    ~UpdatePreparation();
    bool start(PreparationRequest request, DownloadTransport transport=fetch_asset_https);
    void cancel();
    PreparationStatus snapshot() const;
    bool reset(); // Non-blocking refusal while preparing; never throws away active work.
    // Does a final locked-file hash: run this handoff validation off the GUI thread.
    std::unique_ptr<StagedUpdate> take_ready(bool approved,bool processing,bool pending,std::uint64_t now);
private:
    mutable std::mutex mutex_;
    PreparationStatus status_;
    StageResult result_;
    std::atomic<bool> cancel_{false};
    std::thread worker_;
};
}
