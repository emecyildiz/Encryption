#pragma once

namespace kasa {
// Session-local choices stay independent when automatic file detection changes mode.
struct SourceDeletionPolicy {
    bool encrypt = false;
    bool decrypt = true;

    bool& for_mode(bool unlocking) { return unlocking ? decrypt : encrypt; }
    bool for_mode(bool unlocking) const { return unlocking ? decrypt : encrypt; }
};
}
