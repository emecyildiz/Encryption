#pragma once

#include <algorithm>

namespace kasa {
enum class BatchItemStatus { READY, PROCESSING, PENDING_SAVE, SAVED, FAILED };

template<class Outputs>
bool has_pending_outputs(const Outputs& outputs) {
    return std::any_of(outputs.begin(), outputs.end(), [](const auto& output) {
        return output.status == BatchItemStatus::PENDING_SAVE;
    });
}

// A cancelled batch can contain saved, failed, and unattempted sources.
// Only saved inputs are removed; pending output must be saved before retrying.
template<class Sources, class Outputs>
void remove_saved_sources(Sources& sources, const Outputs& outputs) {
    sources.erase(std::remove_if(sources.begin(), sources.end(), [&](const auto& source) {
        return std::any_of(outputs.begin(), outputs.end(), [&](const auto& output) {
            return output.status == BatchItemStatus::SAVED && output.source_path == source.path;
        });
    }), sources.end());
}
}
