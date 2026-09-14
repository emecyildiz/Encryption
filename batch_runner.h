#pragma once
#include <cstddef>

namespace kasa {
struct BatchRunSummary {
    std::size_t attempted = 0;
    bool stopped_before_next = false;
};

// Cancellation is a boundary between files, not an interruption of a crypto
// operation. Process must record per-file failures itself. Unexpected exceptions
// propagate to the worker's fatal-error guard, never silently count as success.
template<class Items, class Cancelled, class Process>
BatchRunSummary run_file_batch(const Items& items, Cancelled cancelled, Process process) {
    BatchRunSummary summary;
    for (const auto& item : items) {
        if (cancelled()) {
            summary.stopped_before_next = true;
            break;
        }
        process(item);
        ++summary.attempted;
    }
    return summary;
}
}
