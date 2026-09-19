#include "update_check.h"
#include <chrono>
#include <iostream>
int main(int argc, char**) {
    kasa::updates::UpdateCheck checker;
    if (checker.state().busy || checker.state().available || checker.start(static_cast<kasa::updates::Channel>(99))) return 1;
    checker.reset();
    if (argc == 1) { std::cout << "Idle and invalid-channel lifecycle checks passed\n"; return 0; }
    if (!checker.start(kasa::updates::Channel::Test)) return 2;
    if (checker.start(kasa::updates::Channel::Test)) return 3;
    while(checker.state().busy) std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto state = checker.state();
    std::cout << state.message << "\nVersion: " << state.version << '\n';
    checker.reset();
    if (checker.state().available || checker.state().message != "Not checked yet.") return 4;
    return 0;
}
