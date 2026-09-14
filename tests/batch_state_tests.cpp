#include "batch_state.h"
#include <filesystem>
#include <iostream>
#include <vector>

using Status = kasa::BatchItemStatus;
struct Source { std::filesystem::path path; };
struct Output { std::filesystem::path source_path; Status status; };
int main() {
    int failures = 0;
    auto check = [&](bool ok, const char* name) {
        if (!ok) { std::cerr << "FAIL: " << name << '\n'; ++failures; }
    };
    std::vector<Output> outputs;
    check(!kasa::has_pending_outputs(outputs), "empty batch permits start");
    outputs = {{"done", Status::SAVED}, {"bad", Status::FAILED}};
    check(!kasa::has_pending_outputs(outputs), "completed/error batch permits retry");
    outputs.push_back({"prepared", Status::PENDING_SAVE});
    check(kasa::has_pending_outputs(outputs), "mixed batch blocks destructive restart");
    std::vector<Source> sources = {{"done"}, {"bad"}, {"prepared"}, {"unattempted"}};
    kasa::remove_saved_sources(sources, outputs);
    check(sources.size() == 3 && sources[0].path == "bad" && sources[1].path == "prepared"
          && sources[2].path == "unattempted", "cancel retains failed/pending/unattempted inputs");
    outputs[2].status = Status::SAVED;
    kasa::remove_saved_sources(sources, outputs);
    check(!kasa::has_pending_outputs(outputs) && sources.size() == 2
          && sources[0].path == "bad" && sources[1].path == "unattempted",
          "save finishes pending entry without losing retry inputs");
    kasa::remove_saved_sources(sources, outputs);
    check(sources.size() == 2, "repeated finalization is idempotent");
    check(outputs.size() == 3 && outputs[1].status == Status::FAILED,
          "finalization retains visible output history");
    std::vector<Source> exact = {{"same"}, {"same-prefix"}};
    kasa::remove_saved_sources(exact, std::vector<Output>{{"same", Status::SAVED}});
    check(exact.size() == 1 && exact[0].path == "same-prefix", "exact source identity matching");
    if (!failures) std::cout << "All 8 batch-state checks passed.\n";
    return failures ? 1 : 0;
}
