#include "source_deletion_policy.h"
#include <iostream>

int main() {
    kasa::SourceDeletionPolicy policy;
    int failures = 0;
    const auto check = [&](bool ok, const char* name) {
        if (!ok) { ++failures; std::cerr << name << '\n'; }
    };
    check(!policy.for_mode(false), "Encryption preserves sources by default");
    check(policy.for_mode(true), "Decryption deletes sources by default");
    policy.for_mode(true) = false;
    check(!policy.for_mode(true), "Decryption opt-out is retained");
    check(!policy.for_mode(false), "Decryption opt-out does not change encryption");
    policy.for_mode(false) = true;
    check(policy.for_mode(false), "Encryption opt-in is retained");
    check(!policy.for_mode(true), "Encryption opt-in does not reset decryption opt-out");
    const auto snapshot = policy;
    policy.for_mode(true) = true;
    check(!snapshot.for_mode(true), "Operation snapshot is independent");
    check(kasa::SourceDeletionPolicy{}.for_mode(true), "New session restores decryption default");
    return failures ? 1 : 0;
}
