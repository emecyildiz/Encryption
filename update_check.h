#pragma once
#include "update_policy.h"
#include <atomic>
#include <mutex>
#include <string>
#include <thread>

namespace kasa::updates {
struct CheckState { bool busy = false; bool available = false; std::string version; std::string message = "Not checked yet."; };
class UpdateCheck {
public:
    ~UpdateCheck();
    bool start(Channel channel);
    CheckState state() const;
    void reset();
private:
    mutable std::mutex mutex_;
    CheckState state_;
    std::thread worker_;
    std::atomic<bool> cancel_{false};
};
}
