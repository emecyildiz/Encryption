#pragma once

namespace kasa {
constexpr bool needs_source_retention_confirmation(bool delete_source, bool confirmed) {
    return !delete_source && !confirmed;
}
// Session-local choices stay independent when automatic file detection changes mode.
struct SourceDeletionPolicy {
    bool encrypt = false;
    bool decrypt = true;

    bool& for_mode(bool unlocking) { return unlocking ? decrypt : encrypt; }
    bool for_mode(bool unlocking) const { return unlocking ? decrypt : encrypt; }
};
}
