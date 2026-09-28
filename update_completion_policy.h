#pragma once
#include <cstdint>
namespace kasa::updates {
enum class Completion { Relaunch, RestartRequired, Cancelled, Failed };
constexpr Completion completion_for(std::uint32_t exit_code) {
    if (exit_code == 0) return Completion::Relaunch;
    if (exit_code == 3010) return Completion::RestartRequired;
    if (exit_code == 2 || exit_code == 5) return Completion::Cancelled;
    return Completion::Failed;
}
}
