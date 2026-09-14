#include "operation_password.h"
#include <memory>
#include <thread>
#include <type_traits>
#include <iostream>
#include <stdexcept>

static_assert(!std::is_copy_constructible_v<OperationPassword>);
static_assert(!std::is_move_constructible_v<OperationPassword>);
int main() {
    for (const std::string text : {std::string("short"), std::string(127, 'x'), std::string("parola-\xc3\xb6\xc4\x9f")}) {
        auto owner = std::make_unique<OperationPassword>(text.c_str());
        const auto* original_object = owner.get();
        const auto* original_bytes = owner->value().data();
        bool passed = false;
        std::thread worker([password = std::move(owner), &passed, original_object,
                            original_bytes, &text]() {
            if (password.get() != original_object || password->value().data() != original_bytes ||
                password->value() != text) return;
            password->clear();
            passed = password->value().empty();
        });
        worker.join();
        if (owner || !passed) return 1;
    }
    // The owning object is destroyed by unwinding if worker startup fails.
    try {
        auto password = std::make_unique<OperationPassword>("synthetic");
        throw std::runtime_error("synthetic startup failure");
    } catch (const std::runtime_error&) {}
    std::cout << "Operation password ownership tests passed (3 transfer cases).\n";
}
